import boto3
import json
import sys

master_role_credentials = {}
########## Assume Role Start #####################
def assume_role(role_arn, session_name, credentials):
    assumedRoleObject=None
    sts_client = boto3.client('sts',
        aws_access_key_id     = credentials['AccessKeyId'],
        aws_secret_access_key = credentials['SecretAccessKey'],
        aws_session_token     = credentials['SessionToken']
    )
    #print (sts_client.get_caller_identity())
    try:
      assumedRoleObject = sts_client.assume_role(
          RoleArn         = role_arn,
          RoleSessionName = session_name,
          DurationSeconds = 3600
      )
    except Exception as e:
      print e.message
    return assumedRoleObject
########## Assume Role End   #####################


########## Get Account Credentials Start #####################
def get_account_credentials(account_id, master_role_credentials):
    account_credentials = None
    account_role_arn = "arn:aws:iam::" + account_id + ":role/OrganizationAccountAccessRole"
    account_role = assume_role(account_role_arn, account_id, master_role_credentials)
    if account_role is not None:
      account_credentials = account_role['Credentials']
    return account_credentials
########## Get Account Credentials End   #####################

print "Procssing Starts."
accountId = ''
try:
 accountId =  str(sys.argv[1])
except Exception as e:
  print "Enter Account Id"
  exit

print accountId
bucketName = accountId+'-ssm-bucket'
with open('credentials.json') as json_data:
    master_role_credentials = dict(json.load(json_data))['Credentials']

credentials = get_account_credentials(accountId, master_role_credentials)

regions = boto3.Session(region_name="us-east-1").client('ec2', aws_access_key_id = credentials['AccessKeyId'],aws_secret_access_key = credentials['SecretAccessKey'],aws_session_token = credentials['SessionToken']).describe_regions().get("Regions",[])
for region in regions:
  print region["RegionName"]
  next_token =''
  ssm_client = boto3.client('ssm', region_name=region["RegionName"], aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
  ec2Client = boto3.client('ec2', region_name=region["RegionName"], aws_access_key_id = credentials['AccessKeyId'],aws_secret_access_key = credentials['SecretAccessKey'],aws_session_token = credentials['SessionToken'])
  while next_token is not None:
    
    response = {}
    try:
      response = ssm_client.describe_instance_information(NextToken=next_token)
      next_token=response.get('NextToken')
      print "next token", next_token
    except Exception as e:
      print e.message
    instanceDetailsList = []
    for instancelist in response["InstanceInformationList"]:
      command = []
      instanceDetails = {}
      instanceId = instancelist["InstanceId"]
      platformType =  instancelist["PlatformType"]
      print "Platform type for instance: ", instanceId, "is", platformType
      if platformType == "Linux" or platformType == "linux":
        docName = 'AWS-RunShellScript'
        command.append('#!/bin/bash')
        command.append('if [[ -L "/etc/redhat-release" ||  -e "/etc/redhat-release" ]]; then')
        command.append('if [[ -e "/etc/centos-release" ]]; then')
        command.append('if grep -q \'7\.\' /etc/centos-release; then')
        command.append('echo "centos_7"')
        command.append('elif grep -q \'6\.\' /etc/centos-release; then')
        command.append('echo "centos_6"')
        command.append('else')
        command.append('echo "Unsupported version of CentOS detected. Exiting..."')
        command.append('exit 1')
        command.append('fi')
        command.append('else')
        command.append('if grep -q \'8\.\' /etc/redhat-release; then')
        command.append('echo "rhel_8"')
        command.append('elif grep -q \'7\.\' /etc/redhat-release; then')
        command.append('echo "rhel_7"')
        command.append('elif grep -q \'6\.\' /etc/redhat-release; then')
        command.append('echo "rhel_6"')
        command.append('else')
        command.append('echo "Unsupported version of RHEL detected. Exiting..."')
        command.append('exit 1')
        command.append('fi')
        command.append('fi')
        command.append('fi')
      if platformType == "Windows" or platformType == "windows":
        docName = 'AWS-RunPowerShellScript'
        command.append('$windows=(Get-WMIObject win32_operatingsystem).name')
        command.append('if(select-string -pattern "2012" -InputObject $windows){')
        command.append('$windows_ver="windowsserver_2012"')
        command.append('}')
        command.append('elseif(select-string -pattern "2016" -InputObject $windows){')
        command.append('$windows_ver="windowsserver_2016"')
        command.append('}')
        command.append('elseif(select-string -pattern "2019" -InputObject $windows){')
        command.append('$windows_ver="windowsserver_2019"')
        command.append('}')
        command.append('else{')
        command.append('$windows_ver="Unsupported. None of 2012,2016,2019"')
        command.append('}')
        command.append('Write-host $windows_ver')
      ssmCommands ={"commands": command}
      try:
        response = ssm_client.send_command( InstanceIds=[instanceId], DocumentName=docName, OutputS3BucketName=bucketName, Parameters=ssmCommands)
        commandId = response["Command"]["CommandId"]
        print "comand Id for instance "+ instanceId+" is : "+ commandId
        key = ''
        if platformType == "Linux" or platformType == "linux":
          key = commandId+"/"+instanceId+"/awsrunShellScript/0.awsrunShellScript/stdout"
        if platformType == "Windows" or platformType == "windows":
          key =  commandId+"/"+instanceId+"/awsrunPowerShellScript/0.awsrunPowerShellScript/stdout"
        print "Key is: ", key
 #       time.sleep(10)
        s3 = boto3.client('s3', aws_access_key_id = credentials['AccessKeyId'],aws_secret_access_key = credentials['SecretAccessKey'],aws_session_token = credentials['SessionToken'])
        finalresult = ''
        try:
          waiter = s3.get_waiter('object_exists')
          waiter.wait(Bucket=bucketName, Key=key, WaiterConfig={'Delay': 5,'MaxAttempts': 30})
          #res = boto3.resource('s3').ObjectAcl(bucketName,key).put(ACL='public-read')
          result = s3.get_object(Bucket=bucketName, Key=key)
          fresult = result["Body"].read().decode()
          finalresult = fresult.replace("\n", "")
          print "os Type: ",finalresult
        except Exception as e:
          print "Can not fetch : ", key
          print e.message
        if (finalresult != ''):
          if ("Unsupported" not in finalresult):
            try:
              ec2Client.create_tags(Resources=[instanceId], Tags=[{'Key': 'wk_os_version', 'Value': finalresult}])
            except Exception as e:
              print "can not add os version tag on : ", instanceId
              print e.message
          else:
            print finalresult, instanceId
        else:
          print "Can not get os and version information on ", instanceId
      except Exception as e:
        print 'On Instance ' +instanceId+ 'ssm command has failed '
        print instancelist
        print e.message
#      commandId = response["Command"]["CommandId"]
#      print "commandId = ", commandId
#    sleep (10)
  #  next_token=response.get('NextToken')

print "Processing Complete!!"

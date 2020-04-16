import sys
import boto3
import botocore
import json
import csv
import datetime
import time
import logging
import os
import threading

outputS3BucketName="wk-test-output"
inputS3BucketName="rainier-enterprise-cloud"
inputKey="manifest/AWS/new/"
outputKey="autoremediation-reports/"
metadataFileName="account-manifest.json"
s3acc_id = '334087799703'
metadataPath='/tmp/metadata.json'
activeCsvPath='active.csv'
jumpAccount='835377776149'
dynamoDb="WK-Account-Metadata"
#accountId='185614922766
InstanceId='i-02fe8a9264e900479'

errors = []

logger = logging.getLogger()
logger.setLevel(logging.INFO)

print_lock = threading.Lock()

readOnly=str(sys.argv[1])
accountId=str(sys.argv[2])
bu=str(sys.argv[3])
cu=str(sys.argv[4])
OpsRampClientId=str(sys.argv[5])
#OpsRampClientId=str(sys.argv[5])

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

########## Read Metadata Start #####################
def readMetadata(filepath):
  try:
   with open(filepath) as json_file:
     metadata = json.load(json_file)
     return metadata
  except Exception as e:
     print "Error While Reading Matadata file"
     print e.message
     exit
########## Read Metadata End   #####################

########## readManifestFromDynamoDB Start #####################
def readManifestFromDynamoDB(region, credentials, tableName, accountId):
  metadata = {}
  response = {}
  dynamodb = boto3.resource('dynamodb', region_name = region, aws_access_key_id = credentials['AccessKeyId'],aws_secret_access_key = credentials['SecretAccessKey'],aws_session_token = credentials['SessionToken'])
  table = dynamodb.Table(tableName)
#response = dynamodb.batch_get_item(RequestItems={"WK-Account-Metadata": {"Keys": [{"AccountID": {"S":"185614922766"}}]}})
  try:
    response = table.get_item(Key={"AccountID":accountId})
  except Exception as e:
    print "No metadata exists in the dynamo db for account: ", accountId
    #print e.message
  if "Item" in response.keys():
    metadata = response["Item"].get("data")
  else:
   # print "No metadata found for ", accountId
    metadata = {}
  return metadata
########## readManifestFromDynamoDB End   #####################


########## Read Accounts from Active.csv Start #####################
def readActiveCsv(activeFile):
  accountList=[]
  try:
    file = open(activeFile,"r")
    reader = csv.reader(file,delimiter=',')
    next(reader, None)
    for line in reader:
      if len(line) > 0:
        account=line[0]
        accountList.append(account)
  except Exception as e:
    print e.message
  return accountList
########## Read Accounts from Active.csv End   #####################

########## Download Document Start #####################
def downloadDocument(bucketName, fileName, localPath, master_role_credentials):
  print "file to be downloaded: ", fileName
  account_cred= get_account_credentials(s3acc_id,master_role_credentials)
  s3 = boto3.resource('s3', aws_access_key_id = account_cred['AccessKeyId'],aws_secret_access_key = account_cred['SecretAccessKey'],aws_session_token = account_cred['SessionToken'])
  try:
      s3.Bucket(bucketName).download_file(fileName, localPath)
      print fileName ," is successfully downloaded at " ,localPath
  except botocore.exceptions.ClientError as e:
      print e.message
      if e.response['Error']['Code'] == "404":
          print("The object does not exist.")
      else:
          raise
########## Download Document End #####################

########## Get List of Active Accounts Start #####################
def getActiveAccountList(metadata, accountList):
  activeAccountList = []
  for account in metadata['AccountMetadata']:
    accountId = account['AccountId']
    if (accountId in accountList):
      activeAccountList.append(account)
  return activeAccountList
########## Get List of Active Accounts End   #####################

########## Get List of Active Regions Start #####################
def getActiveRegions(account):
  activeRegions=[]
  try:
    activeRegions = account['ActiveRegion']
  except Exception as e:
    print("No Active Region")
  return activeRegions
########## Get List of Active Regions End   #####################

########## Create Output Bucket Start #####################
def createOutputBucket(accountId, credentials):
  bucketName=accountId+"-ssm-bucket"
  print "Output bucket to be created: ", bucketName
  s3 = boto3.resource('s3', aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
  try:
    if (s3.Bucket(bucketName) in s3.buckets.all()) == False:
      response=s3.create_bucket(ACL='public-read-write', Bucket=bucketName)
      print "Bucket Created: ",response
    else:
      print "The bucket: ",bucketName," already exists..."
  except botocore.exceptions.ClientError as e:
    print e.message
  return bucketName
########## Create Output Bucket End   #####################

########## Get List Of All Instances In A Region Start #####################
def getAllInstance(region, credentials):
  ec2Client = boto3.client('ec2', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
  try:
    response = ec2Client.describe_instances()
  except Exception as e:
    print e.message
  return response
########## Get List Of All Instances In A Region End   #####################

########## Get SSM Enabled Instances Start #####################
def getSsmInstances(region, credentials):
  ssm_client = boto3.client('ssm', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
  ssmList = []
  next_token = ''
  try:
    while next_token is not None:
      response =  ssm_client.describe_instance_information(NextToken=next_token)
      for instancelist in response["InstanceInformationList"]:
        if "PingStatus" in instancelist.keys():
          if instancelist["PingStatus"] =='Online':
  #          platform = instancelist["PlatformType"]
            ssmList.append(instancelist)
          else:
            print "Instance: ", instancelist['InstanceId']," is not connected."
      next_token=response.get('NextToken')

  except Exception as e:
    print e.message
  return ssmList
########## Get SSM Enabled Instances End   #####################

def getInstaneDetails(allInstanceList, ssmInstances):
  vmReport=[]
  for reservation in allInstanceList.get("Reservations"):
    for instance in reservation.get("Instances",[]):
      instancedata={}
      instanceDetails={}
      instancedata["instance-identifier"] = instance.get("InstanceId")
      instanceDetails["name"] = instance.get("InstanceId")
      instanceDetails["state"] = instance["State"].get("Name")
      instanceDetails["ami-id"] = instance.get("ImageId")
      instanceDetails["VPC-ID"] = instance.get("VpcId")
      instanceDetails["subnet-id"] = instance.get("SubnetId")
      instanceDetails["IP"] = instance.get("PrivateIpAddress")
      instancedata["instance-details"]=instanceDetails
      instancedata["instance-tags"]=instance.get("Tags")
      if instance["State"].get("Name") != "running":
        state = "No Action Taken. VM state is ",instance["State"].get("Name")
        instancedata["vm-validation-metadata"] = state
      else:
        ssmStatus = "SSM Not Installed."
        for vm in ssmInstances:
          if instance.get("InstanceId") == vm['InstanceId']:
            ssmStatus = "SSM Installed"
        instancedata["vm-validation-metadata"] = ssmStatus
      vmReport.append(instancedata)
  return vmReport
    #  instanceDetails.append()
########## Get Instance Details End   #####################

########## Get Vpc Id Start #####################
def getVPC(instanceId, region, credentials):
  vpcId=''
  try:
    ec2_client=boto3.client('ec2', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
    response=response=ec2_client.describe_instances(InstanceIds=[instanceId])
    vpcId=response['Reservations'][0]['Instances'][0].get('VpcId')
  except Exception as e:
    print e.message
  return vpcId
########## Get Vpc Id End   #####################

########## Check VPC in Metadata Start #####################
def checkVpcInMetadata(vpcId,account):
  vpcExistsInMetadata = {}
  for vdc in account['VDC']:
    if (vpcId == vdc.get('VdcId')):
      vpcExistsInMetadata = vdc
  return vpcExistsInMetadata
########## Check VPC in Metadata End   #####################


########## Get VPC exempt Status Start #####################
def getVdcRemediationExemption(vpcDetails):
  try:
    return vpcDetails.get('VdcAutoRemediateExempt')
  except Exception as e:
    print 'Exemption Status Not Present in Metadata for VPC' , vpcDetails.get('VdcId')
    return 'false'
########## Get VPC Exempt Status End   #####################

########## VM level maintenance Window Start #####################
def getVmLevelMaintenanceWindow(instanceId, region, credentials):
  maintenanceWindow = []
  autoremediateflag =[]
  ec2 = boto3.client('ec2', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
  try:
    response_b = ec2.describe_instances( Filters=[{ 'Name': 'instance-id', 'Values': [instanceId] } ])
    for reserved in response_b["Reservations"]:
      for instance in reserved["Instances"]:
        if "Tags" in instance.keys():
           for tag in instance["Tags"]:
             key = tag["Key"]
             if "maintenance_window" in tag ["Key"]:
                tag_value = tag["Value"]
                maintenanceWindow.append(tag_value)
                if "maintenance_window" not in tag["Key"]:
                  print "Please define maintenance_window tag at VM level"

        else:
                  print "No Tags on this VM."
  except Exception as f:
    print f.message

  return maintenanceWindow
########## VM level maintenance Window End   #####################

########## VPC level maintenance Window Start #####################
def getVpcLevelMaintenanceWindow(vpcId, region, credentials):
  maintenanceWindow = []
  response_a = boto3.client('ec2', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
  try:
    response_b = response_a.describe_vpcs( Filters=[{ 'Name': 'vpc-id', 'Values': [vpcId] } ])
    for vpc in response_b["Vpcs"]:
        if "Tags" in vpc.keys():
           for tag in vpc["Tags"]:
             key = tag["Key"]
             if "maintenance_window" in tag ["Key"]:
                tag_value = tag["Value"]
                maintenanceWindow.append(tag_value)
        else:
                  print "No Tag on this VPC."
  except Exception as f:
    print f.message

  return maintenanceWindow

########## VPC level maintenance Window End   #####################

########## Account level maintenance Window Start #####################
def getAccountLevelMaintenanceWindow(accountId, account):
  maintenanceWindow = []
  try:
    if 'MaintenanceWindow' in account.keys():
      maintenanceWindow = account['MaintenanceWindow']
    else:
      print "No Maintenance Window defined for the account ", accountId
  except:
    print e.message
  return maintenanceWindow
########## Account level maintenance Window End   #####################

########## Compare Time Start #####################
def compareCurrentTime(maintenanceWindow):
    print "maintenanceWindow set to: ", maintenanceWindow
    result = False
    dayofweek = datetime.datetime.today().strftime("%A")
    timestamp = time.time()
    utc_time = datetime.datetime.utcfromtimestamp(timestamp).strftime('%H%M')
    day_time = dayofweek + ' ' + utc_time
    current_time =int(utc_time)
    try:
     if maintenanceWindow != []:
      for listitems in maintenanceWindow :
        day = listitems.split(' ')
        tag_day_window = day [0]
        tag_time_window= day [1]
        print "dayofweek: ", dayofweek
        print "tag_day_window: ", tag_day_window
        if dayofweek==tag_day_window :
            TW =tag_time_window.split('-')
            LB=int(TW[0])
            UB=int(TW[1])
            print "current_time: ", current_time
            print "LB: ", LB
            print "UB: ", UB
            if ( current_time > LB and current_time < UB ):
              return True
            else:
              print "Time window is notcorrect"
    except Exception as f:
       print f.message
    return result
########## Compare Time End   #####################

########## Get Maintenancewindow Start #####################
def getMaintenaceWindow(instanceId, vpcId, region, account, credentials):
  result = False
  maintenanceWindow = []
  maintenanceWindow = getVmLevelMaintenanceWindow(instanceId, region, credentials)
  if maintenanceWindow == []:
    print "Maintenance_window tag not defined at vm level"
    maintenanceWindow = getVpcLevelMaintenanceWindow(vpcId, region, credentials)
    if maintenanceWindow == []:
      print "Maintenance_window tag not defined at vpc level"
      maintenanceWindow = getAccountLevelMaintenanceWindow(account['AccountId'], account)
      if maintenanceWindow == []:
        print "Maintenance Window not defined at any level"
        return False
  for time in maintenanceWindow:
    result = compareCurrentTime(maintenanceWindow)
    if result:
      return result
  return result
########## Get Maintenancewindow End   #####################

########## Get Remediation Tags Start #####################
def getRemediationTags(instanceId, region, credentials):
  autoremediatetag =''
  osType = ''
  response_a = boto3.client('ec2', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
  try:
    response_b = response_a.describe_instances( Filters=[{ 'Name': 'instance-id', 'Values': [instanceId] } ])
    for reserved in response_b["Reservations"]:
      for instance in reserved["Instances"]:
        if "Tags" in instance.keys():
           for tag in instance["Tags"]:
             key = tag["Key"]
             if "Wk_autoremediate" in tag ["Key"]:
                autoremediatetag = tag["Value"]
             if "wk_os_version" in tag ["Key"]:
               osType = tag["Value"]
        else:
                  print "No Tags on this VM."
  except Exception as f:
    print f.message
  return autoremediatetag, osType
########## Get Remediation Tags End   #####################

########## Get Agents TO Validate Start #####################
def getAgentsToValidate(osTag,account):
  agentsToValidate = []
  for agents in account.get('Autoremediate').get('agents'):
    if (osTag == agents['osname']):
      tasks = agents['tasks']
      for task in tasks:
        if (task['enabled'] == True):
          agentsToValidate.append(task['name'])
  print "agentsToValidate: ",agentsToValidate
  print "for os: ",osTag
  return agentsToValidate
########## Get Agents TO Validate End   #####################

########## Get Validation Parameter Start #####################
def getValidationParameters(sw, agents, osTag, platformType):
    validationParameters=[]
    installationParameters=[]

    for agent in agents:
      if(sw == agent['name']):
        for metadata in agent['metadata']:
          if (osTag == metadata['os']):
            validationScript =  metadata['script_checkonly']
            installationScript = metadata['script']
            print "validationScript", validationScript
            print "installationScript", installationScript
            validationcommand = []
            installationcommand = []
            if(platformType == 'Linux'):
              validationcommand.append('cd /tmp')
              validationcommand.append('yum install wget -y &> /dev/null')
              validationcommand.append(' yum install dos2unix -y &> /dev/null')
              validationcommand.append('wget '+validationScript+' &> /dev/null')
              validationcommand.append('dos2unix '+sw+'.check.sh &> /dev/null')
              validationcommand.append('sh '+sw+'.check.sh')
              validationcommand.append('yum remove dos2unix -y &> /dev/null')
              validationcommand.append('rm -f '+sw+'.check.sh &> /dev/null')
              validationcommand.append('yum remove wget -y &> /dev/null')

              installationcommand.append('cd /tmp')
              installationcommand.append('yum install wget -y &> /dev/null')
              installationcommand.append(' yum install dos2unix -y &> /dev/null')
              installationcommand.append('wget '+installationScript+' &> /dev/null')
              installationcommand.append('dos2unix '+sw+'.sh &> /dev/null')
              if (sw == 'opsramp'):
                installationcommand.append('sh '+sw+'.sh '+OpsRampClientId)
              else:
                installationcommand.append('sh '+sw+'.sh')
              installationcommand.append('yum remove dos2unix -y &> /dev/null')
              installationcommand.append('rm -f '+sw+'.sh &> /dev/null')
              installationcommand.append('yum remove wget -y &> /dev/null')

            if(platformType == 'Windows'):
              validationcommand.append('$folder = "C:\\scripts\"')
              validationcommand.append('if(!(Test-Path $folder)) { mkdir $folder > $null }')
              #validationcommand.append('Remove-Item -Recurse C:\\scripts\\WKwindowsAgents.ps1 2> Out-Null')
              #validationcommand.append('mkdir scripts')
              validationcommand.append('Invoke-WebRequest '+validationScript+' -OutFile C:\\scripts\\WKwindowsAgents.ps1')
              validationcommand.append('powershell.exe -executionpolicy bypass -file C:\\scripts\\WKwindowsAgents.ps1')
              validationcommand.append('Remove-Item -Recurse C:\\scripts\\WKwindowsAgents.ps1')

              installationcommand.append('Remove-Item -Recurse C:\\scripts\\installation.ps1 2> Out-Null')
              installationcommand.append('Invoke-WebRequest '+installationScript+'   -OutFile C:\\scripts\\installation.ps1')
              if (sw == 'opsramp'):
                installationcommand.append('powershell.exe -executionpolicy bypass -file C:\\scripts\\installation.ps1 -OpsRampClientId '+ OpsRampClientId+' 2> Out-Null')
              else:
                if (sw == 'mcafee'):
                   installationcommand.append('powershell.exe -executionpolicy bypass -file C:\\scripts\\installation.ps1 -BU '+ bu+' -CU '+cu+' 2> Out-Null')
                else:
                  installationcommand.append('powershell.exe -executionpolicy bypass -file C:\\scripts\\installation.ps1 2> Out-Null')
              
    print "validationcommand",validationcommand
    print "installationcommand",installationcommand
    return validationcommand, installationcommand

#            validationcommand = '{"commands": ["cd /tmp, yum install wget -y &> /dev/null, yum install dos2unix -y &> /dev/null, wget '+validationScript+' &> /dev/null, dos2unix script.install.sh &> /dev/null, sh script.install.sh, yum remove dos2unix -y &> /dev/null, rm -f script.install.sh &> /dev/null, yum remove wget -y &> /dev/null"]}'
#  for agent in agentsToValidate:

########## Get Validation Parameter End   #####################
def getValidationStatus(commandId, bucketName, instanceId, platform, readOnly, credentials):
  agensStatusPreInstallation = []
  result = {}
  key = ''
  if platform == 'Linux':
        key = commandId+"/"+instanceId+"/awsrunShellScript/0.awsrunShellScript/stdout"
  if platform == 'Windows':
        key =  commandId+"/"+instanceId+"/awsrunPowerShellScript/0.awsrunPowerShellScript/stdout"
  print key
  s3 = boto3.client('s3', aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
  try:
        waiter = s3.get_waiter('object_exists')
        waiter.wait(Bucket=bucketName, Key=key, WaiterConfig={'Delay': 15,'MaxAttempts': 30})
      #  res = boto3.resource('s3').ObjectAcl(bucketName,key).put(ACL='public-read')
        response = s3.get_object(Bucket=bucketName, Key=key)
        result = response["Body"].read().decode()
        print result
  except Exception as e:
        print "can not fetch: " + key
        print e.message
  #print result
  return result

def installAgents(installationcommand, region, instanceId, docName, bucketName, accountId, credentials):
  response = {}
  commandId = ''
  ssmClient = boto3.client('ssm', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
  commands ={"commands": installationcommand}
  try:
    response = ssmClient.send_command( InstanceIds=[instanceId], DocumentName=docName, OutputS3BucketName=bucketName, Parameters=commands)
  except Exception as e:
      print 'On Instance ' +instanceId+ 'ssm command has failed'
      #print commands
      print e
      if ("ExpiredTokenException" in e.message ):
        installAgents(installationcommand, region, instanceId, docName, bucketName, accountId, credentials)
  if (response != {}):
    commandId = response["Command"]["CommandId"]
  print commandId
  return commandId

def validateVM(validationcommand, installationcommand, region, instanceId, bucketName, platform, readOnly, maintenanceWindow, sw, accountId, credentials):
  preInstallationReport = {}
  postInstallationResult = {}
  docName = ''
  ssmClient = boto3.client('ssm', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
  commands ={"commands": validationcommand}

  if (platform == "Linux"):
    docName = 'AWS-RunShellScript'
  if (platform == "Windows"):
    docName = 'AWS-RunPowerShellScript'
  try:
    response = ssmClient.send_command( InstanceIds=[instanceId], DocumentName=docName, OutputS3BucketName=bucketName, Parameters=commands)
  except Exception as e:
      print 'On Inscance ' ,instanceId, ' ssm command has failed.'
      print e
      print e
      if ("ExpiredTokenException" in e.message ):
        credentials = get_account_credentials(accountId, master_role_credentials)
        installAgents(installationcommand, region, instanceId, docName, bucketName, accountId, credentials)

  commandId = response["Command"]["CommandId"]
  print commandId
  preInstallation = getValidationStatus(commandId, bucketName, instanceId, platform, readOnly, credentials)
  if preInstallation != {}:
    preInstallationReport = json.loads(preInstallation)
  if ("Not configured" not in preInstallation):
    print "Already Installed!!"
    postInstallationResult = {sw: "Already Installed"}
  else:
    print "readOnly: ", readOnly
    print "maintenanceWindow: ", maintenanceWindow
    if readOnly == "N" and maintenanceWindow == True :
      print "Not Installed, installing."
      commandId = installAgents(installationcommand, region, instanceId, docName, bucketName, accountId, credentials)
      print "commandId:", commandId
      postInstallation = getValidationStatus(commandId, bucketName, instanceId, platform, readOnly, credentials)
      if postInstallation != {}:
        postInstallationResult = json.loads(postInstallation)
    else:
      print "Not Installed, Not making any changes because ReadOnly flag is set to true OR the current time is outside of maintenance window."
      postInstallationResult={sw: "No Changes Done.Either you ran in readOnly Mode OR the current time is outside of maintenance window."}

  return preInstallationReport, postInstallationResult


def writeJson(data, filename):
  try:
    with open(filename, 'w') as outfile:
      json.dump(data, outfile, indent=4)
  except Exception as e:
    print e.message

def uploadDocument(bucketName, outputName, key, master_role_credentials):
  print "path where output file is uploaded: ", key
  account_cred= get_account_credentials(s3acc_id,master_role_credentials)
  s3 = boto3.resource('s3', aws_access_key_id = account_cred['AccessKeyId'],aws_secret_access_key = account_cred['SecretAccessKey'],aws_session_token = account_cred['SessionToken'])
  try:
      s3.meta.client.upload_file(outputName, bucketName, key, ExtraArgs={'ACL':'public-read'})
  except botocore.exceptions.ClientError as e:
      print e.response

########## Apply Tags Start #####################
def applyTags(instanceId, region, vmTags, credentials):

  newTagList=[]
  if(vmTags != {}):
    for vmtag in vmTags['tags']:
      newTag={}
      newTag['Key']=vmtag['tag_key']
      newTag['Value']=vmtag['default_value']
      newTagList.append(newTag)

    ec2=boto3.client('ec2', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
    try:
      ec2.create_tags(Resources=[instanceId], Tags=newTagList)
      #print "Added tags..."
    except Exception as e:
      print e.message

########## Apply Tags  End   #####################



########## VM Autoremediation Start #####################
def vm_autoremediation(accountId, vmTags):
#    instanceReport = []
    reportOutput = []
    credentials = {}
    metadata = {}
    print "Reading manifest file for account ", accountId
    jumpAccountCreds= get_account_credentials(jumpAccount,master_role_credentials)
    metadata = readManifestFromDynamoDB('us-east-1', jumpAccountCreds, dynamoDb, accountId)
    if (metadata != {}):
      print accountId, " is an active Account"
      print "Fetching credentials for account ", accountId
      credentials = get_account_credentials(accountId, master_role_credentials)
      if (credentials != {}):
        account=metadata['AccountMetadata']
      #for account in activeAccountList:
        print "Getting Active Regions in account: ", account["AccountId"]
        activeRegions = getActiveRegions(account)
        if(activeRegions != []):
          for region in activeRegions:
            instanceReport=[]
            print "Getting List of VMs in ", region
            allInstanceList = getAllInstance(region, credentials)
            if (allInstanceList != []):
              print "Fetching the List of SSM enabled instances in " , region
              ssmInstances = getSsmInstances(region, credentials)
              if (ssmInstances != []):
                print "Creating instance report."
                instanceReport = getInstaneDetails(allInstanceList, ssmInstances)
                print "creating output bucket."
                bucketName = createOutputBucket(accountId,credentials)
                for instance in ssmInstances:
                  postInstallationReport=[]
                  preRemediationReport=[]
                  print "Applying Tags"
                  applyTags(instance['InstanceId'], region, vmTags, credentials)
                  print "tags applied on : ", instance['InstanceId']
                  print "Fetching vpc id for ",instance['InstanceId']
                  vpcId = getVPC(instance['InstanceId'], region, credentials)
                  print "Checking VpcId in metadata."
                  vpcDetails = checkVpcInMetadata(vpcId,account)
                  if(vpcDetails != {}):
                    print "Getting vdcAutoRemediateExempt tag from metadata file."
                    vdcAutoRemediateExempt = getVdcRemediationExemption(vpcDetails)
                    if(vdcAutoRemediateExempt == 'False' or vdcAutoRemediateExempt == 'false'):
                      print "Getting Maintenance Window."
                      #maintenanceWindow = getMaintenaceWindow(instance['InstanceId'], vpcId, region, account, credentials) 
                      maintenanceWindow = True
                      print "Getting OS tag and vmRemediationTag."
                      vmRemediationTag, osTag = getRemediationTags(instance['InstanceId'],region, credentials)
                      if(vmRemediationTag == '' or vmRemediationTag == 'True' or vmRemediationTag == 'true'):
                        print "os Tag: ", osTag
                        if(osTag):
                          print "Getting Agents to validate from manifest file."
                          agentsToValidate = getAgentsToValidate(osTag,account)
                          #print "agentsToValidate: ", agentsToValidate
                          if(agentsToValidate != []):
                            for sw in agentsToValidate:
                              print "Creating ssm commands for ", sw
                              validationcommand, installationcommand = getValidationParameters(sw, metadata['agents'], osTag, instance['PlatformType'])
                              print "Validating the VM for ", sw
                              credentials = get_account_credentials(accountId, master_role_credentials)
                              preRemediation, postInstallation = validateVM(validationcommand, installationcommand, region, instance['InstanceId'],bucketName, instance['PlatformType'], readOnly, maintenanceWindow, sw,accountId, credentials)

                              preRemediationReport.append(preRemediation)
                              postInstallationReport.append(postInstallation)
                            for report in instanceReport:
                             # print "instance['InstanceId'] :",instance['InstanceId']
                             # print "report.get(instance-identifier) :",report.get("instance-identifier")
                              if (instance['InstanceId'] == report.get("instance-identifier")):
                                print "AccountId Matched ------------------------------------------------------------------------------------"
                                report['pre-vm-remediation-Report'] = preRemediationReport
                                report['post-vm-remediation-Report'] = postInstallationReport
                            reportOutput.append(instanceReport)
                         # writeJson(reportOutput,'reportOutput.json')
                          else:
                             msg = 'No remediation Action Defined on ' +osTag+' in account '+account['AccountId']
                             errors.append(msg)
                             print msg
                        else:
                          msg = 'The wk_os_version tag is not defined on the instance '+ instance['InstanceId']+' hence not remediated.'
                          errors.append(msg)
                          print msg
                      else:
                        msg = 'No Scrips executed on instance '+ instance['InstanceId']+' because Wk_autoremediate tag is set to false.'
                        errors.append(msg)
                        print msg
                    else:
                      msg = 'The instance '+ instance['InstanceId']  + ' is not remediated because the vpc is marked to be exempted from remediation'
                      errors.append(msg)
                      print msg
                  else:
                     msg = 'The vpc for instance '+instance['InstanceId'] +' is not present in manifest file'
                     errors.append(msg)
                     print msg

                    #reportOutput.append(report)

              else:
                msg = 'No SSM enabled Instance available in region: '+region
                errors.append(msg)
                print msg
            else:
              msg = 'No Instance available in region: ' + region
              errors.append(msg)
              print msg
        else:
          msg = 'No Active Region defined for Account Id:' + account['AccountId']
          errors.append(msg)
          print msg
        writeJson(reportOutput, "finalReport.json")
        writeJson(errors, "errorReport.json")
        key=outputKey+accountId+'-NewRemediationReport.json'
        uploadDocument(outputS3BucketName, 'finalReport.json', key, master_role_credentials)
        key = outputKey+accountId+'-NewErrorReport.json'
        uploadDocument(outputS3BucketName, 'errorReport.json', key, master_role_credentials)
      else:
        msg = "Can not fetch role for Account Id: "+ accountId
        errors.append(msg)
        print msg
    else:
      msg = "No metadata defined for account "+ accountId
      print msg
########## VM Autoremediation End   #####################


#-----------Script Starts Here--------------------------------------#
print "Procssing Starts."
print "Reading Master Credentials."
with open('credentials.json') as json_data:
    master_role_credentials = dict(json.load(json_data))['Credentials']

print "Reading Tags file from s3 bucket"
vmTags = {}
bucketkey=inputKey+'vm-tags.json'
downloadDocument(inputS3BucketName, bucketkey, '/tmp/vmtags.json', master_role_credentials)
with open('/tmp/vmtags.json') as json_file:
  vmTags = json.load(json_file)
vm_autoremediation(accountId, vmTags)
print "Processing Complete."

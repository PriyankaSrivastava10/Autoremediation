from bson import json_util
import os, sys, time, json, logging, csv
import boto3
from datetime import datetime
from dateutil.tz import tzlocal
from botocore.vendored import requests
from botocore.exceptions import ClientError
import timeit
import threading
import metadata
import vmtag
import botocore

logger = logging.getLogger()
logger.setLevel(logging.INFO)

checkAgentStatusDoc="pri-check"
installAgentDoc="pri-install"
#outputS3BucketName="wk-gbs-artifact-output"
outputS3BucketName="wk-test-output"
#outputS3BucketName="wk-test-agents-bucket" #changed for testing purpose
inputS3BucketName="rainier-enterprise-cloud"
#inputS3BucketName="wk-test-agents-bucket" #changed for testing purpose
inputKey="manifest/AWS/"
outputKey="autoremediation-reports/"
metadataFileName="account-manifest.json"
#opsrampclientid=str(raw_input("Enter OpsRamp Client ID: 616093")
opsrampclientid= "616093"
s3acc_id = '334087799703'
#s3acc_id = '185614922766' #changed account id for testing purpose

metadataPath='/tmp/metadata.json'
activeCsvPath='active.csv'


def getActiveRegions(currentAccount, metaData):
        activeRegions = []
        try:
                for data in metaData['data']:
                        if data['AccountId']==currentAccount:
                                return  data['activeRegions']
        except Exception as e:
                print e.message


def convertToJson(metaData):
        try:
                return json.load(metaData)
        except Exception as e:
                print e.message


def getSSMInstances(region, credentials):
        ssm_client = boto3.client('ssm', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
        vmList=[]
        next_token = ''
        try:
                while next_token is not None:
                        response =  ssm_client.describe_instance_information(NextToken=next_token)
                        for instancelist in response["InstanceInformationList"]:
                                if "PingStatus" in instancelist.keys():
                                        if instancelist["PingStatus"] =='Online':
                                                vmList.append(instancelist)
                                        else:
                                                print "Instance: ", instancelist['InstanceId']," is not connected."
                        next_token=response.get('NextToken')
        except Exception as e:
                print e.message
        return vmList

def checkInstanceInMetaData(instanceId, metaData, currentAccount):
        try:
                for data in metaData['data']:
                        if data['AccountId']==currentAccount:
                                instanceDetails =  data['InstanceDetails']
                                for instance in instanceDetails:
                                        if instanceId ==  instance['Instance']['InstanceId']:
                                                #print "###############",data
                                                return instance,data['otherParameters']
                print "No action taken on instance: ",instanceId
        except Exception as e:
                print e.message

        return None, None

def generateParameters(instance, otherParameters, platform):
        parameters = {}
        try:

                if 'RemediationLevel' not in instance['autoRemediateAction'].keys() or  instance['autoRemediateAction']['RemediationLevel'] == "all":
                        for key in instance['autoRemediateAction'].keys():
                                value=[]
                                data = instance['autoRemediateAction'][key]
                                value.append(data)
                                parameters[key] = value
                        if otherParameters is not None:
                          for key in otherParameters.keys():
                                value=[]
                                data = otherParameters[key]
                                value.append(data)
                                parameters[key] = value

                else:
                        value=[]
                        value.append('Y')
                        if platform == 'Linux':
                                parameters['OpsRamp']=value
                                parameters['SAM']=value
                                parameters['Epel']=value
                        if platform == 'Windows':
                                parameters['OpsRamp']=value
                                parameters['SAM']=value
                                parameters['Mcafee']=value

                        if otherParameters is not None:
                          for key in otherParameters.keys():
                                value=[]
                                data = otherParameters[key]
                                value.append(data)
                                parameters[key] = value
        except Exception as e:
                print e.message
        return parameters

def sendCommand(instanceId, platform, parameters, region, credentials, bucketName):
        print "inside sendCommand...instanceId: ", instanceId
        key = ''
        ssm_client = boto3.client('ssm', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
        try:
                response = ssm_client.send_command( InstanceIds=[instanceId], DocumentName='pri-check', OutputS3BucketName=bucketName, Parameters=parameters)
                commandId = str(response["Command"]["CommandId"])
                time.sleep(60)
                print commandId
                if platform == 'Linux':
                        key = commandId+"/"+instanceId+"/awsrunShellScript/CheckAgentStatusOnLinux/stdout"
                else:
                        if platform == 'Windows':
                                key = commandId+"/"+instanceId+"/awsrunPowerShellScript/CheckAgentStatusOnWindows/stdout"

        except Exception as e:
                print e.message
        return key

def getInstallationStatus(key, credentials, bucketName):
        result = ''
        s3 = boto3.client('s3', aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
        try:
                waiter = s3.get_waiter('object_exists')
                waiter.wait(Bucket=bucketName, Key=key, WaiterConfig={'Delay': 15,'MaxAttempts': 30
    })
                response = s3.get_object(Bucket=bucketName, Key=key)
                result = response["Body"].read().decode()
        except Exception as e:
                print e.message
        return result

def installAgents(instanceId, platform, parameters, region, credentials, bucketName):
        outputFile = ''
        ssm_client = boto3.client('ssm', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
        try:
                response = ssm_client.send_command( InstanceIds=[instanceId], DocumentName=installAgentDoc, OutputS3BucketName=bucketName, Parameters=parameters)
                commandId = str(response["Command"]["CommandId"])
                time.sleep(60)
                if platform == 'Linux':
                        outputFile = commandId+"/"+instanceId+"/awsrunShellScript/InstallAgentsOnLinux/stdout"
                else:
                        if platform == 'Windows':
                                outputFile=commandId+"/"+instanceId+"/awsrunPowerShellScript/InstallAgetnsOnWindows/stdout"
        except Exception as e:
                print e.message
        return outputFile

def downloadDocument(bucketName, fileName, localPath, master_role_credentials):
  print "file to be downloaded: ", fileName
  account_cred= get_account_credentials(s3acc_id,master_role_credentials)
  s3 = boto3.resource('s3', aws_access_key_id = account_cred['AccessKeyId'],aws_secret_access_key = account_cred['SecretAccessKey'],aws_session_token = account_cred['SessionToken'])
  try:
      s3.Bucket(bucketName).download_file(fileName, localPath)
      print "success"
  except botocore.exceptions.ClientError as e:
      print e.message
      if e.response['Error']['Code'] == "404":
          print("The object does not exist.")
      else:
          raise


def uploadDocument(bucketName, outputName, key, master_role_credentials):
  print "path where output file is uploaded: ", key
  account_cred= get_account_credentials(s3acc_id,master_role_credentials)
  s3 = boto3.resource('s3', aws_access_key_id = account_cred['AccessKeyId'],aws_secret_access_key = account_cred['SecretAccessKey'],aws_session_token = account_cred['SessionToken'])
  try:
      s3.meta.client.upload_file(outputName, bucketName, key, ExtraArgs={'ACL':'public-read'})
  except botocore.exceptions.ClientError as e:
      print e.response

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
  except ClientError as e:
    print e.message
  return bucketName


def checkSSMDocument(docName, region, credentials):
  ssm = boto3.client('ssm', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
  response = ''
  try:
    response = ssm.describe_document(Name=docName)
  except botocore.exceptions.ClientError as e:
    print  e.response['Error']['Message']
    return ''
  return response


def deleteDocument(docName, region, credentials):
  ssm = boto3.client('ssm', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
  try:
    response = ssm.delete_document(Name=docName)
    print "document deleted: ", docName
  except  Exception as e:
    print e.message

def createDocument(localPath, region, docName, credentials):
  content = ''
  try:
          with open(localPath) as ssmDocumentFile:
                content = ssmDocumentFile.read()
                ssm = boto3.client('ssm', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
                response = ssm.create_document(Name = docName, Content = content, DocumentType = "Command")
                #print response
                ssmDocumentFile.close()
                print "Document Created, modifying permissions..."
                ssm.modify_document_permission(Name=docName, PermissionType='Share')
  except Exception as e:
        print e.message

def writeCsv(csvDataList):
  with open("output.csv", "w") as f:
    fieldnames = ['AccountId', 'Region', 'InstanceId', 'Platform', 'RemediationLevel', 'InitialStatus', 'FinalStatus']
    writer = csv.writer(f)
    writer.writerow(fieldnames)
    writer.writerows(csvDataList)

def writeJson(data, filename):
  try:
    with open(filename, 'w') as outfile:
      json.dump(data, outfile, indent=4)
  except Exception as e:
    print e.message

def getRemediationLevel(autoRemediationAction):
  remediationLevel=[]
  Level = ''
  for key in autoRemediationAction.keys():
        Level+=key+'-'
        remediationLevel.append(Level+autoRemediationAction[key])
  print "remediationLevel %%%%%%%%", remediationLevel
  return remediationLevel


def assume_role(role_arn, session_name, credentials):
    sts_client = boto3.client('sts',
        aws_access_key_id     = credentials['AccessKeyId'],
        aws_secret_access_key = credentials['SecretAccessKey'],
        aws_session_token     = credentials['SessionToken']
    )
    #print (sts_client.get_caller_identity())

    assumedRoleObject = sts_client.assume_role(
        RoleArn         = role_arn,
        RoleSessionName = session_name,
        DurationSeconds = 3600
    )
    return assumedRoleObject

## get_account_credentials - to get temporary credentails
def get_account_credentials(account_id, master_role_credentials):
    account_role_arn = "arn:aws:iam::" + account_id + ":role/OrganizationAccountAccessRole"
    account_role = assume_role(account_role_arn, account_id, master_role_credentials)
    account_credentials = account_role['Credentials']
    return account_credentials

def get_region_list(credentials):
    ec2 = boto3.client(
        'ec2',
        region_name='us-east-1',
        aws_access_key_id     = credentials['AccessKeyId'],
        aws_secret_access_key = credentials['SecretAccessKey'],
        aws_session_token     = credentials['SessionToken'],
    )

    regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    return regions
def get_account_list():
    with open('active.csv', mode='r') as active_account_file:
        active_accout_reader = csv.DictReader(active_account_file)
        for row in active_accout_reader:
           accounts_list.append(row["Id"])
    return accounts_list

def get_regions_list():
    regions_list = get_region_list(account_cred)
    return  regions_list

def getActiveAccountList(metadataPath, activeCsvPath):
  accountIdList=[]
  accountDetailsList=[]
  try:
    accountList=metadata.getActiveAccounts(activeCsvPath)
    if accountList == []:
      print "No active Accounts."
      sys.exit(0)
    mdata=metadata.readMetadata(metadataPath)
    if mdata == None:
      print "No meta data available."
      sys.exit(0)

    for accountId in accountList:
      accountDetails=metadata.checkAccountInMetadata(accountId, mdata)
      if accountDetails is not None:
        accountDetailsList.append(accountDetails)  
        accountIdList.append(accountId)
  except Exception as e:
    print e.message
  return accountIdList, accountDetailsList


def autoremediate(instanceId, platform, parameters, region, credentials, bucketName, currentAccount, instance, readOnly, maintenanceWindow, autoremediatetag):
  print "ReadOnly::::",readOnly
  print "maintenanceWindow::::",maintenanceWindow
  print "autoremediatetag::::",autoremediatetag
  csvDataList = []
  key = sendCommand(instanceId, platform, parameters, region, credentials, bucketName)
  print "key: ",key
  finalStatus=''
  result = ''
  if key != '':
        result=getInstallationStatus(key, credentials, bucketName)
        print result
        if "-NotInstalled" not in result:
                print "Already Installed!!"
                finalStatus=result
        else:
          if readOnly == "N" and maintenanceWindow == True and autoremediatetag == 'true':
                print "Not Installed, installing."
                ouputFile=installAgents(instanceId, platform, parameters, region, credentials, bucketName)
                print "Find Agent Installation output under this path:\n",ouputFile
                finalStatus=getInstallationStatus(ouputFile, credentials, bucketName)
          else:
            print "Not Installed, Not making any changes because ReadOnly flag is set to true."
            finalStatus="No-Changes-Done.Either-you-ran-in-readOnly-Mode-OR-the-current-time-is-outside-of-maintenance-window."
  csvData=[]
  out=[]
  final=[]
  res = result.replace("\n", " ")
  tmp = res.replace("\r","")
  out=tmp.split()
  status = finalStatus.replace("\n", " ")
  temp = status.replace("\r","")
  final = temp.split()
  csvData.append(out)
  csvData.append(final)
  csvDataList.append(csvData)
  return csvDataList


def s3_store(bucket_name,filename,bucket_folder_name,master_role_credentials):
    targetLoc= bucket_folder_name+filename
    account_cred= get_account_credentials(s3acc_id,master_role_credentials)

    s3_client = boto3.client('s3',
              aws_access_key_id     = account_cred['AccessKeyId'],
              aws_secret_access_key = account_cred['SecretAccessKey'],
              aws_session_token     = account_cred['SessionToken'])

    s3_object = boto3.resource('s3',
              aws_access_key_id     = account_cred['AccessKeyId'],
              aws_secret_access_key = account_cred['SecretAccessKey'],
              aws_session_token     = account_cred['SessionToken'])

    try:
        print('bucket_folder_name:'+bucket_folder_name+'^bucket_name:'+bucket_name+'^filename:'+filename)
        #s3_client.upload_file(filename,bucket_name,filename)
        s3_object.Bucket(bucket_name).upload_file(filename,targetLoc)
        s3_object.Object(bucket_name, targetLoc).Acl().put(ACL='public-read')
    except Exception as e:
        logging.error(e)
        logging.error( u'FAIL to upload %s to s3' % (filename) )
        pass
    url = 'https://s3.amazonaws.com/'+bucket_name+'/'+targetLoc
    return url

def get_folder_name():
    curr_t      = datetime.now()
    curr_date   = curr_t.strftime("%d-%b-%Y")
    curr_time   = curr_t.strftime("%H-%M-%S")
    bucket_folder_name = folder_name+'/'+curr_date +'/'+ curr_time +'/'
    return bucket_folder_name


def fetchTagFile(inputKey, inputS3BucketName, master_role_credentials):
  vmTags = {}
  bucketkey=inputKey+'vm-tags.json'
  downloadDocument(inputS3BucketName, bucketkey, '/tmp/vmtags.json', master_role_credentials)
  with open('/tmp/vmtags.json') as json_file:
        vmTags = json.load(json_file)
  return vmTags

def getVMStatus(instanceId, vmList):
  print "inside getVMStatus....."
  #print "vmList::::::", vmList
  for vm in vmList:
   # print "vm:", vm['InstanceId']
    #print "instanceId:", instanceId
    if instanceId == vm['InstanceId']:
      return "SSM Installed"
      
  return "SSM Not Installed."

def getReport(instance, vmList):
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
    msg = getVMStatus(instance.get("InstanceId"), vmList)
    instancedata["vm-validation-metadata"] = msg

  return instancedata

def getCompleteInstanceList(region, credentials):
     ec2Client = boto3.client('ec2', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
     try:
       response = ec2Client.describe_instances()
     except Exception as e:
       print e.message
     #print "response: ", response
     return response
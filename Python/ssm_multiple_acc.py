#VM Threads

#!/usr/bin/env python
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

logger = logging.getLogger()
logger.setLevel(logging.INFO)

print_lock = threading.Lock()

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

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
      json.dump(data, outfile)
  except Exception as e:
    print e.message

def getRemediationLevel(autoRemediationAction):
  remediationLevel=''
  for key in autoRemediationAction.keys():
        remediationLevel+=key+'-'
        remediationLevel+=autoRemediationAction[key]+' '
  return remediationLevel


#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@



## assume_role - to get temporary credentails
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

def Welcome_func(batch_accounts_list, count):
    with print_lock:
        print("Starting thread : {}".format(threading.current_thread().name))
        print ("processing batch: %s, list of accounts: %s" % (count, batch_accounts_list))
    batchList =[]
    for account in batch_accounts_list:
        try :
            account_cred= get_account_credentials(account,master_role_credentials)
            #get_print_statement(account,account_cred,batchList)
            vm_validation(account,account_cred,batchList, accountDetailsList)
        except Exception as e:
          if 'Access denied' in str(e):
              print ('Account ID ' + account + ' is not authorised to perform Assume role!!!')
          else:
             print str(e)

    
    with print_lock:
        print("Finished thread : {}".format(threading.current_thread().name))
    return
	
	
def _create_batch(acc, cols=2):
    start = 0
    for i in range(cols):
        stop = start + len(acc[i::cols])
        yield acc[start:stop]
        start = stop
    return

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


def vm_validation(account_id,credentials,batchList, accountDetailsList):
        ssm_id = []
        ssm_id_win = []
        csvDataList = []
        data={}
        vmTags={}
        try:
                        key=inputKey+metadataFileName
                        downloadDocument(inputS3BucketName, key, metadataPath, master_role_credentials)
                        
                        with open(metadataPath) as json_file:
                           data = json.load(json_file)
                        bucketkey=inputKey+'vm-tags.json'
                        downloadDocument(inputS3BucketName, bucketkey, '/tmp/vmtags.json', master_role_credentials)
                        with open('/tmp/vmtags.json') as json_file:
                            vmTags = json.load(json_file)
                        print "fetching metadata"
                        metaData = metadata.fetchMetadataForEachInstance(accountDetailsList, credentials)
                        #print "metadata: ", metaData
                        currentAccount = boto3.client('sts', aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken']).get_caller_identity()['Account']
                        print "\n\n Current Account: ",currentAccount
                        activeRegions = getActiveRegions(currentAccount, metaData)
                        print "\n Active Regions: ",activeRegions

                        if activeRegions != []:
                                for region in activeRegions:
                                        print "checking ssm document in region: ", region
                                        if checkSSMDocument(checkAgentStatusDoc, region, credentials) == '':
                                                        localPath='/tmp/pri-check.json'
                                                        key=inputKey+'pri-check.json'
                                                        downloadDocument(inputS3BucketName, key, localPath, master_role_credentials)
                                                        createDocument(localPath, region, 'pri-check', credentials)
                                        else:
                                                        localPath='/tmp/pri-check.json'
                                                        key=inputKey+'pri-check.json'
                                                        downloadDocument(inputS3BucketName, key, localPath, master_role_credentials)
                                                        deleteDocument('pri-check', region, credentials)
                                                        createDocument(localPath, region, 'pri-check', credentials)
                                        if checkSSMDocument(installAgentDoc, region, credentials) == '':
                                                        localPath='/tmp/pri-install.json'
                                                        key=inputKey+'pri-install.json'
                                                        downloadDocument(inputS3BucketName, key, localPath, master_role_credentials)
                                                        createDocument(localPath, region, 'pri-install', credentials)
                                        else:
                                                        localPath='/tmp/pri-install.json'
                                                        key=inputKey+'pri-install.json'
                                                        downloadDocument(inputS3BucketName, key, localPath, master_role_credentials)
                                                        deleteDocument('pri-install', region, credentials)
                                                        createDocument(localPath, region, 'pri-install', credentials)
                                        print "creating output bucket..."
                                        bucketName = createOutputBucket(currentAccount,credentials)
                                        activeInstances = []
                                        print "fetching VM list"
                                        vmList = getSSMInstances(region, credentials)
                                        for vm in vmList:
                                                        vmData,otherParameters = checkInstanceInMetaData(vm['InstanceId'], metaData, currentAccount)
                                                        #print ">>>>>>>>>>>>>>",vmData
                                                        if vmData:
                                                                        #print "\n\nvm: ", vm
                                                                        #print "vmData: ",vmData
                                                                        #print"\nother parameters are:",otherParameters
                                                                        activeInstances.append(vmData)
                                        print "\nFor ", region, "active Instances are: ", activeInstances
                                        if activeInstances != []:
                                                        for instance in activeInstances:
                                                                        parameters = generateParameters(instance,otherParameters,instance['Instance']['Platform'])
                                                                        instanceId = instance['Instance']['InstanceId']
                                                                        platform =  instance['Instance']['Platform']
                                                                        print "parameters for instance: ",instanceId," are: ",parameters
                                                                        key = sendCommand(instanceId, platform, parameters, region, credentials, bucketName)
                                                                        print "key: ",key
                                                                        finalStatus=''
                                                                        if key != '':
                                                                                        result=getInstallationStatus(key, credentials, bucketName)
                                                                                        print result
                                                                                        if "-NotInstalled" not in result:
                                                                                                        print "Already Installed!!"
                                                                                                        finalStatus=result
                                                                                        else:
                                                                                                        print "Not Installed, installing."
                                                                                                        ouputFile=installAgents(instanceId, platform, parameters, region, credentials, bucketName)
                                                                                                        print "Find Agent Installation output under this path:\n",ouputFile
                                                                                                        finalStatus=getInstallationStatus(ouputFile, credentials, bucketName)
                                                                        csvData=[]
                                                                        res = result.replace("\n", " ")
                                                                        out = res.replace("\r","")
                                                                        status = finalStatus.replace("\n", " ")
                                                                        final = status.replace("\r","")
                                                                        csvData.append(currentAccount)
                                                                        csvData.append(region)
                                                                        csvData.append(instanceId)
                                                                        csvData.append(platform)
                                                                        csvData.append(getRemediationLevel(instance['autoRemediateAction']))
                                                                        csvData.append(out)
                                                                        csvData.append(final)
                                                                        csvDataList.append(csvData)
                                        # Code for Vm tagging
                                        
                                        remediatedVms, notRemediatedVms = vmtag.tagVms(currentAccount, region, data, vmTags, credentials)                                        
                                        print "Uploading result..."
                                        writeJson(remediatedVms, 'remediatedvms.json')
                                        writeJson(notRemediatedVms, 'notremediatedvms.json')
                                        outputfile=outputKey+currentAccount+'-remediatedvms.json'
                                        uploadDocument(outputS3BucketName, 'remediatedvms.json', outputfile, master_role_credentials)
                                        outputfile=outputKey+currentAccount+'-notremediatedvms.json'
                                        uploadDocument(outputS3BucketName, 'notremediatedvms.json', outputfile, master_role_credentials)
                        writeCsv(csvDataList)
                        outputFileName=currentAccount+'-result.csv'
                        key=outputKey+outputFileName
                        uploadDocument(outputS3BucketName, 'output.csv', key, master_role_credentials)
                        
        except Exception as e:
                        print e.message

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
        return

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


## For debugging purpose - uncomment these lines to run from command line
os.environ['account_id']     = '185614922766'
accounts_list =[]

#s3acc_id = '334087799703'
s3acc_id = '185614922766'
#bucket_name ='wk-gbs-artifact-output'
bucket_name ='pt-test-acm'
folder_name = 'vm_validation'
accountDetailsList=[]

# get environment variables
#for variable in ['account_id']:
#    globals()[variable] = os.environ.get(variable)
globals()['log_level'] = os.environ.get('log_level')


# get credentials
with open('credentials.json') as json_data:
    master_role_credentials = dict(json.load(json_data))['Credentials']

#-------------------------Implementing Multithreading start-----------
threads = []

actList, accountDetailsList = getActiveAccountList(metadataPath, activeCsvPath)

for item in _create_batch(actList, 5):
    #print (item)
    #store_data(item)
    t = threading.Thread(target = Welcome_func, args = (item, threading.activeCount()))
    threads.append(t)
    t.start()
    #for job in threads:
    #job.start()

while threading.activeCount() > 1:
    pass
else:
    for job in threads:
        job.join()

    print_lock.acquire()

    print('Actual Output')


    print_lock.release()
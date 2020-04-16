import boto3
import time
import metadata
import json
import botocore
import csv

checkAgentStatusDoc="pri-check"
installAgentDoc="pri-install"
outputS3BucketName="wk-test-agents-bucket"
opsrampclientid = "616093"  
currentAccount = boto3.client('sts').get_caller_identity()['Account']

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


def getSSMInstances(region):
        ssm_client = boto3.client('ssm', region_name=region)
        vmList=[]
        next_token = ''
        try:
                while next_token is not None:
                        response =  ssm_client.describe_instance_information(NextToken=next_token)
                        for instancelist in response["InstanceInformationList"]:
                                if "PingStatus" and "AssociationStatus" in instancelist.keys():
                                        if instancelist["PingStatus"] !='Online' or instancelist["AssociationStatus"] != 'Success':
                                                print "Instance: ", instancelist['InstanceId']," is not connected."
                                        else:
                                                vmList.append(instancelist)
                        next_token=response.get('NextToken')
        except Exception as e:
                print e.message
        return vmList

def checkInstanceInMetaData(instanceId, metaData):
        try:
                for data in metaData['data']:
                        if data['AccountId']==currentAccount:
                                instanceDetails =  data['InstanceDetails']
                                for instance in instanceDetails:
                                        if instanceId ==  instance['Instance']['InstanceId']:
                                                print "###############",data
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
                        for key in otherParameters:
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

                        for key in otherParameters:
                                value=[]
                                data = otherParameters[key]
                                value.append(data)
                                parameters[key] = value
        except Exception as e:
                print e.message
        return parameters

def sendCommand(instanceId, platform, parameters, region):
        key = ''
        ssm_client = boto3.client('ssm', region_name=region)
        try:
                response = ssm_client.send_command( InstanceIds=[instanceId], DocumentName='pri-check', OutputS3BucketName=outputS3BucketName, Parameters=parameters)
                commandId = str(response["Command"]["CommandId"])
                time.sleep(60)
                print commandId
                if platform == 'Linux':
                        key = commandId+"/"+instanceId+"/awsrunShellScript/CheckAgentStatusOnLinux/stdout"
                else:
                        if platform == 'Windows':
                                key = commandId+"/"+instanceId+"/awsrunPowerShellScript/CheckAgentStatusOnWindows/stdout"

        except Exception as e:
                print e
        return key

def getInstallationStatus(key):
        result = ''
        s3 = boto3.client('s3')
        try:
                response = s3.get_object(Bucket=outputS3BucketName, Key=key)
                result = response["Body"].read().decode()
        except Exception as e:
                print e.message
        return result

def installAgents(instanceId, platform, parameters, region):
        outputFile = ''
        ssm_client = boto3.client('ssm', region_name=region)
        try:
                response = ssm_client.send_command( InstanceIds=[instanceId], DocumentName=installAgentDoc, OutputS3BucketName=outputS3BucketName, Parameters=parameters)
                commandId = str(response["Command"]["CommandId"])
                if platform == 'Linux':
                        outputFile = commandId+"/"+instanceId+"/awsrunShellScript/InstallAgentsOnLinux/stdout"
                else:
                        if platform == 'Windows':
                                outputFile=commandId+"/"+"awsrunPowerShellScript/InstallAgetnsOnWindows/stdout"
        except Exception as e:
                print e.message
        return outputFile

def downloadDocument(bucketName, fileName, localPath):
  s3 = boto3.resource('s3')
  try:
      s3.Bucket(bucketName).download_file(fileName, localPath)
  except botocore.exceptions.ClientError as e:
      if e.response['Error']['Code'] == "404":
          print("The object does not exist.")
      else:
          raise


def uploadDocument(bucketName, key, outputName):
  s3 = boto3.client('s3')
  try:
      s3.upload_file(key,bucketName, outputName, ExtraArgs={'ACL':'public-read'})
  except botocore.exceptions.ClientError as e:
      print e.response



def checkSSMDocument(docName, region):
  ssm = boto3.client('ssm', region_name=region)
  response = ''
  try:
    response = ssm.describe_document(Name=docName)
  except botocore.exceptions.ClientError as e:
    print  e.response['Error']['Message']
    return ''
  return response

def createDocument(localPath, region, docName):
  content = ''
  try:
          with open(localPath) as ssmDocumentFile:
                content = ssmDocumentFile.read()
                ssm = boto3.client('ssm', region_name=region)
                response = ssm.create_document(Name = docName, Content = content, DocumentType = "Command")
                print response
                ssmDocumentFile.close()
  except Exception as e:
        print e.message

def writeCsv(csvDataList):
  with open("output.csv", "w") as f:
    fieldnames = ['AccountId', 'Region', 'InstanceId', 'Platform', 'RemediationLevel', 'InitialStatus', 'FinalStatus']
    writer = csv.writer(f)
    writer.writerow(fieldnames)
    writer.writerows(csvDataList)

def getRemediationLevel(autoRemediationAction):
  remediationLevel=''
  for key in autoRemediationAction.keys():
        remediationLevel+=key+'-'
        remediationLevel+=autoRemediationAction[key]+' '
  return remediationLevel

ssm_id = []
ssm_id_win = []
metadataPath='/tmp/metadata.json'
activeCsvPath='/home/centos/priyanka/active.csv'
csvDataList = []
try:
        downloadDocument(outputS3BucketName, 'metadata.json', metadataPath)
        metaData = metadata.fetchMetadataForEachInstance(metadataPath,activeCsvPath)
#       currentAccount = boto3.client('sts').get_caller_identity()['Account']
        print "\n\n Current Account: ",currentAccount
        activeRegions = getActiveRegions(currentAccount, metaData)
        print "\n Active Regions: ",activeRegions

        for region in activeRegions:
                if checkSSMDocument(checkAgentStatusDoc, region) == '':
                        localPath='/tmp/pri-check.json'
                        downloadDocument(outputS3BucketName, 'pri-check.json', localPath)
                        createDocument(localPath, region, 'pri-check')
                if checkSSMDocument(installAgentDoc, region) == '':
                        downloadDocument(outputS3BucketName, 'pri-install.json', localPath)
                        createDocument(localPath, region, 'pri-install')
                activeInstances = []
                vmList = getSSMInstances(region)
                for vm in vmList:
                        vmData,otherParameters = checkInstanceInMetaData(vm['InstanceId'], metaData)
                        print ">>>>>>>>>>>>>>",vmData
                        if vmData:
                                print "\n\nvm: ", vm
                                print "vmData: ",vmData
                                print"\nother parameters are:",otherParameters
                                activeInstances.append(vmData)
                print "\nFor ", region, "active Instances are: ", activeInstances
                if activeInstances != []:
                        for instance in activeInstances:
                                parameters = generateParameters(instance,otherParameters,instance['Instance']['Platform'])
                                instanceId = instance['Instance']['InstanceId']
                                platform =  instance['Instance']['Platform']
                                print "parameters for instance: ",instanceId," are: ",parameters
                                key = sendCommand(instanceId, platform, parameters, region)
                                print "key: ",key
                                finalStatus=''
                                if key != '':
                                        result=getInstallationStatus(key)
                                        print result
                                        if "-NotInstalled" not in result:
                                                print "Already Installed!!"
                                        else:
                                                print "Not Installed, installing."
                                                ouputFile=installAgents(instanceId, platform, parameters, region)
                                                print "Find Agent Installation output under this path:\n",ouputFile
                                                finalStatus=getInstallationStatus(ouputFile)
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
        print "csv: ", csvDataList
        writeCsv(csvDataList)
        uploadDocument(outputS3BucketName, 'output.csv', 'result.csv')
except Exception as e:
        print e.message

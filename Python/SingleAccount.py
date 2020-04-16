import boto3
import sys, ast
import json
import supportingFunctions
import metadata
import vmtag


print "starting"
checkAgentStatusDoc="pri-check"
installAgentDoc="pri-install"
outputS3BucketName="wk-test-output"
inputS3BucketName="rainier-enterprise-cloud"
inputKey="manifest/AWS/"
outputKey="autoremediation-reports/"
metadataFileName="account-manifest.json"
s3acc_id = '334087799703'
metadataPath='/tmp/metadata.json'
master_role_credentials = {}
credentials = {}

def vm_validation(account_id,credentials,vpcList, accountDetailsList, readOnly):
        print "account_id", account_id
        print "vpcList", vpcList
        print "accountDetailsList", accountDetailsList
        print "readOnly", readOnly
        ssm_id = []
        ssm_id_win = []
        csvDataList = []
        data={}
        vmTags={}
        notRemediatedVms=[]
        remediatedVms=[]
        vmReport = []
        finalReport = []
        try:
                        key=inputKey+metadataFileName
                        supportingFunctions.downloadDocument(inputS3BucketName, key, metadataPath, master_role_credentials)
                        
                        with open(metadataPath) as json_file:
                           data = json.load(json_file)
                        bucketkey=inputKey+'vm-tags.json'
                        supportingFunctions.downloadDocument(inputS3BucketName, bucketkey, '/tmp/vmtags.json', master_role_credentials)
                        vmTags = supportingFunctions.fetchTagFile(inputKey, inputS3BucketName, master_role_credentials)
                        print "fetching metadata"
                        metaData = metadata.fetchMetadataForEachInstance(accountDetailsList, credentials)
                        print "metadata: ", metaData
                        currentAccount = account_id
                        print "\n\n Current Account: ",currentAccount
                        activeRegions = supportingFunctions.getActiveRegions(currentAccount, metaData)
                        #print "\n Active Regions: ",activeRegions

                        if activeRegions != []:
                                for region in activeRegions:
                                        print "checking ssm document in region: ", region
                                        if supportingFunctions.checkSSMDocument(checkAgentStatusDoc, region, credentials) == '':
                                                        localPath='/tmp/pri-check.json'
                                                        key=inputKey+'pri-check.json'
                                                        supportingFunctions.downloadDocument(inputS3BucketName, key, localPath, master_role_credentials)
                                                        supportingFunctions.createDocument(localPath, region, 'pri-check', credentials)
                                        else:
                                                        localPath='/tmp/pri-check.json'
                                                        key=inputKey+'pri-check.json'
                                                        supportingFunctions.downloadDocument(inputS3BucketName, key, localPath, master_role_credentials)
                                                        supportingFunctions.deleteDocument('pri-check', region, credentials)
                                                        supportingFunctions.createDocument(localPath, region, 'pri-check', credentials)
                                        if supportingFunctions.checkSSMDocument(installAgentDoc, region, credentials) == '':
                                                        localPath='/tmp/pri-install.json'
                                                        key=inputKey+'pri-install.json'
                                                        supportingFunctions.downloadDocument(inputS3BucketName, key, localPath, master_role_credentials)
                                                        supportingFunctions.createDocument(localPath, region, 'pri-install', credentials)
                                        else:
                                                        localPath='/tmp/pri-install.json'
                                                        key=inputKey+'pri-install.json'
                                                        supportingFunctions.downloadDocument(inputS3BucketName, key, localPath, master_role_credentials)
                                                        supportingFunctions.deleteDocument('pri-install', region, credentials)
                                                        supportingFunctions.createDocument(localPath, region, 'pri-install', credentials)
                                        print "creating output bucket..."
                                        bucketName = supportingFunctions.createOutputBucket(currentAccount,credentials)
                                        activeInstances = []
                                        print "fetching VM list"
                                        vmList = supportingFunctions.getSSMInstances(region, credentials)
                                        machineList=supportingFunctions.getCompleteInstanceList(region, credentials)
                                        #print "machine list: ",machineList
                                        reservations = machineList.get("Reservations")

                                        for reservation in reservations:
                                          for instance in reservation.get("Instances",[]):
                                            report = supportingFunctions.getReport(instance, vmList)
                                            vmReport.append(report)

                                        #print "report = ", vmReport   
                                        for vm in vmList:
                                                        vmData,otherParameters = supportingFunctions.checkInstanceInMetaData(vm['InstanceId'], metaData, currentAccount)
                                                        #print ">>>>>>>>>>>>>>",vmData
                                                        if vmData:
                                                                        #print "\n\nvm: ", vm
                                                                        #print "vmData: ",vmData
                                                                        #print"\nother parameters are:",otherParameters
                                                                        activeInstances.append(vmData)
                                       # print "\nFor ", region, "active Instances are: ", activeInstances
                                        if activeInstances != []:
                                                        for instance in activeInstances:
                                                                        parameters = supportingFunctions.generateParameters(instance,otherParameters,instance['Instance']['Platform'])
                                                                        instanceId = instance['Instance']['InstanceId']
                                                                        platform =  instance['Instance']['Platform']
                                                                        #print "parameters for instance: ",instanceId," are: ",parameters
                                                                        vpcId = metadata.getVPC(instanceId, region, credentials)
                                                                        if vpcId in vpcList:
                                                                          accountDetails = metadata.checkAccountInMetadata(currentAccount, data)
                                                                          maintenanceWindow = metadata.checkMaintenanceWindow(instanceId, vpcId, currentAccount, accountDetails, region, credentials)
                                                                        #print "maintenance window: ", maintenanceWindow
                                                                        #if maintenanceWindow == True:
                                                                          csvDataList = supportingFunctions.autoremediate(instanceId, platform, parameters, region, credentials, bucketName, currentAccount, instance, readOnly,maintenanceWindow)
                                                                          print "csvDataList::::", csvDataList
                                                                          for csvData in csvDataList:
                                                                          #print "csvData::::", csvData
                                                                            for report in vmReport:
                                                                            #print "report::::", report
                                                                           # print "instanceId::::", instanceId
                                                                           # print "report.get(\"instance-identifier\")::::", report.get("instance-identifier")
                                                                              remediationReport = report
                                                                            #print "remediationReport:::::::", remediationReport
                                                                              if instanceId == report.get("instance-identifier"):
                                                                             # print "Trueeeeeeeeeeeeeeeeeeee"
                                                                              #print "csvData::::", csvData
                                                                                remediationReport["vm-validation-Type"] = supportingFunctions.getRemediationLevel(instance['autoRemediateAction']) 
                                                                                remediationReport["report-output"] = csvData
                                                                              finalReport.append(remediationReport)
                                                                        #print "#################: ", finalReport
                                                                          if readOnly == "N":
                                                                              remediatedVms, notRemediatedVms = vmtag.tagVms(currentAccount, region, data, vmTags, credentials)
                                                                        #else: 
                                                                         # print "Current Time does not fall in maintenance window. Hence Not remediating."
                                        
                                                               
                                        print "Uploading result..."
                                        #print "finalReport: ", finalReport
                                        supportingFunctions.writeJson(remediatedVms, 'remediatedvms.json')
                                        supportingFunctions.writeJson(notRemediatedVms, 'notremediatedvms.json')
                                        outputfile=outputKey+currentAccount+'-remediatedvms.json'
                                        supportingFunctions.uploadDocument(outputS3BucketName, 'remediatedvms.json', outputfile, master_role_credentials)
                                        outputfile=outputKey+currentAccount+'-notremediatedvms.json'
                                        supportingFunctions.uploadDocument(outputS3BucketName, 'notremediatedvms.json', outputfile, master_role_credentials)
                        supportingFunctions.writeJson(finalReport, 'finalReport.json')
                        outputFileName=currentAccount+'-finalReport.json'
                        key=outputKey+outputFileName
                        supportingFunctions.uploadDocument(outputS3BucketName, 'finalReport.json', key, master_role_credentials)
                        
        except Exception as e:
                        print e.message


def getMetadata(accountId, vpcList, credentials, readOnly):
  
  accountDetailsList = [] 
  currentAccount = accountId
  key=inputKey+metadataFileName

  print "calling downloaddocument"
  supportingFunctions.downloadDocument(inputS3BucketName, key, metadataPath, master_role_credentials)
  if accountId != '':
    if vpcList != ():
      mdata=metadata.readMetadata(metadataPath)
      if mdata == None:
        print "No meta data available."
        sys.exit(0)
      accountDetails=metadata.checkAccountInMetadata(accountId, mdata)
      accountDetailsList.append(accountDetails)
      vm_validation(accountId,credentials, vpcList, accountDetailsList, readOnly)

      


def preRemediationActions(metaData, accountId, region, credentials):
  
      currentAccount = accountId
      print "checking ssm document in region: ", region
      if supportingFunctions.checkSSMDocument(checkAgentStatusDoc, region, credentials) == '':
        localPath='/tmp/pri-check.json'
        key=inputKey+'pri-check.json'
        supportingFunctions.downloadDocument(inputS3BucketName, key, localPath, master_role_credentials)
        supportingFunctions.createDocument(localPath, region, 'pri-check', credentials)
      else:
        localPath='/tmp/pri-check.json'
        key=inputKey+'pri-check.json'
        supportingFunctions.downloadDocument(inputS3BucketName, key, localPath, master_role_credentials)
        supportingFunctions.deleteDocument('pri-check', region, credentials)
        supportingFunctions.createDocument(localPath, region, 'pri-check', credentials)
      if supportingFunctions.checkSSMDocument(installAgentDoc, region, credentials) == '':
        localPath='/tmp/pri-install.json'
        key=inputKey+'pri-install.json'
        supportingFunctions.downloadDocument(inputS3BucketName, key, localPath, master_role_credentials)
        supportingFunctions.createDocument(localPath, region, 'pri-install', credentials)
      else:
        localPath='/tmp/pri-install.json'
        key=inputKey+'pri-install.json'
        supportingFunctions.downloadDocument(inputS3BucketName, key, localPath, master_role_credentials)
        supportingFunctions.deleteDocument('pri-install', region, credentials)
        supportingFunctions.createDocument(localPath, region, 'pri-install', credentials)
      
      print "creating output bucket..."
      bucketName = supportingFunctions.createOutputBucket(currentAccount,credentials)
      return bucketName



#Main Body
print "initial"
accountId=str(sys.argv[1])
print "accountId: ", accountId
vpcList = (sys.argv[2]).split(",")
print "vpcList: ", vpcList
readOnly=str(sys.argv[3])
with open('credentials.json') as json_data:
    master_role_credentials = dict(json.load(json_data))['Credentials']

credentials = supportingFunctions.get_account_credentials(accountId,master_role_credentials)
getMetadata(accountId, vpcList, credentials, readOnly)
      
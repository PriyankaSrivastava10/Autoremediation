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
import supportingFunctions

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



def Welcome_func(batch_accounts_list, count):
    with print_lock:
        print("Starting thread : {}".format(threading.current_thread().name))
        print ("processing batch: %s, list of accounts: %s" % (count, batch_accounts_list))
    batchList =[]
    for account in batch_accounts_list:
        try :
            account_cred= supportingFunctions.get_account_credentials(account,master_role_credentials)
            #get_print_statement(account,account_cred,batchList)
            vm_validation(account,account_cred,batchList, accountDetailsList, readOnly)
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


def vm_validation(account_id,credentials,batchList, accountDetailsList, readOnly):
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
                        #print "metadata: ", metaData
                        currentAccount = boto3.client('sts', aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken']).get_caller_identity()['Account']
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
                                                                        accountDetails = metadata.checkAccountInMetadata(currentAccount, data)
                                                                        maintenanceWindow = metadata.checkMaintenanceWindow(instanceId, vpcId, currentAccount, accountDetails, region, credentials)
                                                                        autoremediatetag = metadata.getAutoRemediationTag(instanceId, region, credentials)
                                                                        #print "maintenance window: ", maintenanceWindow
                                                                        #if maintenanceWindow == True:
                                                                        csvDataList = supportingFunctions.autoremediate(instanceId, platform, parameters, region, credentials, bucketName, currentAccount, instance, readOnly,maintenanceWindow, autoremediatetag)
                                                                        #print "csvDataList::::", csvDataList
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

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
        return

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

readOnly=str(sys.argv[1])
print "readonly = ",readOnly

key=inputKey+metadataFileName
supportingFunctions.downloadDocument(inputS3BucketName, key, metadataPath, master_role_credentials)                  

actList, accountDetailsList = supportingFunctions.getActiveAccountList(metadataPath, activeCsvPath)

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
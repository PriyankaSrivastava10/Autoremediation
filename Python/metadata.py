import boto3
import json
import csv
import sys

#filepath="data.json"
#activeFile="active.csv"


def readMetadata(filepath):
        try:
                with open(filepath) as json_file:
                        metadata = json.load(json_file)
                        return metadata
        except Exception as e:
                print e.message
                exit


def getActiveAccounts(activeFile):
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

def checkAccountInMetadata(accountId, metadata):
        try:
                for account in metadata['AccountMetadata']:
                    if accountId == account['AccountId']:
                        print "accountId Matched."
                        return (account)
        except Exception as e:
                print e.message
#       return None

def fetchActiveRegion(accountId, account):
        activeRegions=''
        try:
                activeRegions = account['ActiveRegion']
        except Exception as e:
                print("no active Region")
                print(e.message)
        return activeRegions

def getOtherParameters(accountDetails):
        otherParameters={}
        try:
                otherParameters['BU']=accountDetails['BU']
                otherParameters['CU']=accountDetails['CU']
                otherParameters['OuPath']=accountDetails['McafeeOu']
                otherParameters['OpsRampClientID']=accountDetails['OpsRampClientId']
                otherParameters['OpsRampClientAgentUri']=accountDetails['OpsRampClientAgentUri']
           #     print "\n\n\nOther Parameters are: ",otherParameters
        except Exception as e:
                print e.message
        return otherParameters


def getInstanceList(region, credentials):
        next_token=''
        instanceDetails=[]

        try:
                ssm_client = boto3.client('ssm', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
                while next_token is not None:
                        response = ssm_client.describe_instance_information(NextToken=next_token)
                        for instancelist in response["InstanceInformationList"]:
                                instanceData={}
                                instanceId=instancelist["InstanceId"]
                                platform=instancelist["PlatformType"]
                                instanceData['InstanceId']=instanceId
                                instanceData['Platform']=platform
                                instanceDetails.append(instanceData)

                        next_token=response.get('NextToken')
        except Exception as e:
                print e.message

        return instanceDetails


def getVPC(instanceId, region, credentials):

        vpcId=''
        try:
                ec2_client=boto3.client('ec2', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
                response=response=ec2_client.describe_instances(InstanceIds=[instanceId])
                vpcId=response['Reservations'][0]['Instances'][0].get('VpcId')
        except Exception as e:
                print e.message

        return vpcId

def checkVpcInMetadata(vpcId, accountDetails):
        vpcDetails=[]
        try:
                vpcDetails=accountDetails['VDC']
                for vpc in vpcDetails:
                        if vpcId == vpc['VdcId']:
                                return vpcDetails
        except Exception as e:
                print e.message


def checkAutoRemediateExemption(vpcDetails):
        exemptStatus = ''
        try:
                exemptStatus=vpcDetails[0].get('VdcAutoRemediateExempt')
        except Exception as e:
                print e.message
        return exemptStatus

def  checkAutoremediateActions(accountDetails, instanceData):
        autoRemediateAction=''
        action={}
        try:
                if instanceData['Platform']=="Windows":
                        autoRemediateAction=accountDetails['Autoremediate']['Windows']
                else:
                        if instanceData['Platform']=="Linux":
                                autoRemediateAction=accountDetails['Autoremediate']['Linux']
                action['Instance']=instanceData
                action['autoRemediateAction']=autoRemediateAction
        except Exception as e:
                print e.message

        return action

def convertToJson(instanceAction):
        try:
                return json.dumps(instanceAction)
        except Exception as e:
                print e.message



def fetchMetadataForEachInstance(accountList, credentials):
        print "inside fetchMetadataForEachInstance"
        msg = ''
        defaultVMList = []
        noCheckAccountList = []
        instanceAction=[]
        finalOutput={}
        data=[]
        try:
                print " Processing Metadata..."
                #print "activeFile: ",activeFile
                #print "filepath: ",filepath
                #accountList=getActiveAccounts(activeFile)
               # print "Active Accounts List: ",accountList
                #if accountList == []:
                 #       print "No active Accounts."
                  #      sys.exit(0)
                #metadata=readMetadata(filepath)
               # print "MetaData Information: ",metadata
                #if metadata == None:
                 #       print "No meta data available."
                  #      sys.exit(0)
                for accountDetails in accountList:
            #            accountDetails=checkAccountInMetadata(accountId, metadata)
                       # print "accountDetails: ",accountDetails
                        accountId=accountDetails['AccountId']
                        if accountDetails is not None:
                                accountData={}
                                accountData['AccountId']=accountId
                                otherParameters = getOtherParameters(accountDetails)
                                if otherParameters:
                                        accountData['otherParameters']=otherParameters
                                activeRegions = fetchActiveRegion(accountId, accountDetails)
                       #         print "Active Regions for Account ",accountId," are: ",activeRegions
                                if activeRegions != '':

                                        accountData['activeRegions']=activeRegions
                                        for region in activeRegions:
                        #                        print "Getting Details in region : ",region," of account: ",accountId
                                                instanceDetails=getInstanceList(region, credentials)
               #                                 print "Instance Details: ",instanceDetails
                                                if instanceDetails !=[]:
                                                        for instanceData in instanceDetails:
                #                                                print "Fetching vpc Id for instance: ",instanceData['InstanceId']
                                                                vpcId = getVPC(instanceData['InstanceId'], region, credentials)
                 #                                               print "vpc id: ",vpcId
                                                                if vpcId != '':
                  #                                                      print "Checking VPC in Meta Data"
                                                                        vpcDetails=checkVpcInMetadata(vpcId, accountDetails)
                   #                                                     print "vpc Details: ",vpcDetails
                                                                        if vpcDetails is not None:
                                                                                exemptStatus = checkAutoRemediateExemption(vpcDetails)
                                                                                if exemptStatus == "false" or exemptStatus == "False":
                                                                                        actions = checkAutoremediateActions(accountDetails, instanceData)
                                                                                        instanceAction.append(actions)
                                                                                        accountData['InstanceDetails']=instanceAction
                                                                                        #       print "final: ",finalOutput
                                                                                else:
                                                                                        default = {accountId, region, instanceId, vpcId, exemptStatus}
                                                                                        defaultVMList.append(default)
                                                                                        msg = "The exempt status for the vpc: "+vpcId+"is True. Hence no action taken on the instance: "+instanceData['InstanceId']
                                                                                        noCheckAccountList.append(msg)
                                                                        else:
                                                                                msg = "VPCId: "+ vpcId+" in account "+accountId+" is not present in metadata hence no action taken on instance: "+instanceData['InstanceId']
                                                                                noCheckAccountList.append(msg)
                                                else:
                                                        msg = "AccountId: "+accountId+" does not have any instance in the active region: "+region
                                                        noCheckAccountList.append(msg)
                                        data.append(accountData)
                                        finalOutput['data']=data
                                else:
                                        msg = "AccountId: "+accountId+" does not have any active region. Hence No action taken on this account"
                                        noCheckAccountList.append(msg)
                        else:
                                msg="AccountId: "+accountId+" does not exists in metadata file. Hence No action taken on this account"
                                noCheckAccountList.append(msg)
                print "\n\n\n\n Auto Remediation actions:\n",finalOutput
                #print "\nn defaultVMList: ", defaultVMList
                #print "\nn noCheckAccountList: ", noCheckAccountList

                return finalOutput
        except Exception as e:
                print e.message
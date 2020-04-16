import os, sys, datetime, tzlocal, csv, logging
import boto3, botocore, threading, time, json, urllib3

header = [['AccountId','Name','Email','InstanceName','PrivateIpAddress','PatchTag','State','Platform','SSM-Status','OpsRamp-Status','SAM-Status','Falcon-Status','McAfee-Status','Patch-Status','KB-Id']]
accEC2List = []
inaccessibleAccounts = []
dt = datetime.datetime.now()
file = str(os.getcwd())+'/PatchreportLatest'+dt.strftime("%d")+dt.strftime("%b")+dt.strftime("%y")+'.csv'

################Begining of get_account_list###########
def get_account_list(credentials):
    account_details = {}
    account_list = []
    client = boto3.client(
        'organizations',
        aws_access_key_id     = credentials['AccessKeyId'],
        aws_secret_access_key = credentials['SecretAccessKey'],
        aws_session_token     = credentials['SessionToken'],
    )

    response = client.list_accounts()
    for account in response['Accounts']:
        account_details['Id'] = account['Id']
#        account_details['Id'] = account['Name']
#        account_details['Id'] = account['Email']

    if 'NextToken' in response:
        while 'NextToken' in response:
            response = client.list_accounts(NextToken=response['NextToken'])
            for account in response['Accounts']:
#               account_list.append(account['Id'])
                account_list.append(account['Name'])
                account_list.append(account['Email'])
                accEC2List.append(account_list)
    try:
       lock.acquire()
       writeToCSV(file,'a',account_list)
    finally:
        lock.release()
        del account_list[0:]
    return account_list

################End of get_account_list###########


###########Begining of assume_role##############
def assume_role(role_arn, session_name, credentials = None):
    if credentials == None:
        sts_client = boto3.client('sts')
    else:
        sts_client = boto3.client('sts',
            aws_access_key_id = credentials['AccessKeyId'],
            aws_secret_access_key = credentials['SecretAccessKey'],
            aws_session_token = credentials['SessionToken']
        )
    #print (sts_client.get_caller_identity())

    assumedRoleObject = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        DurationSeconds=3600
    )
    return assumedRoleObject

###########End of assume_role##############

###########Begining of generate_credentials##############

def generate_credentials(client_account):
    result = { "Credentials": {} }
    client_role = {}
    #master_account_id = os.environ['MASTER_ACC_ID']
    #master_account_id = '297538631377'
    master_account_id = '297538631377'

    master_account_role = 'CrossAccountAccessForJenkinsRole'
    client_account_id = client_account
    # get credentials from master or client account
    try:
        #logging.info( u'Assuming master account admin role...' )
        session_name = client_account_id if client_account_id else master_account_id
        master_role_arn = "arn:aws:iam::" + master_account_id + ":role/" + master_account_role
        master_role = assume_role(master_role_arn, session_name)
        #print 'Master account ARN is',master_role_arn
    except botocore.exceptions.ClientError as ex:
        if ex.response['Error']['Code'] == 'AccessDenied':
            #logging.critical( u'FAIL to assume admin role in master account: %s. Not authorized to perform sts:AssumeRole.' % (master_account_id) )
            print 'Fail to assume master role, not authorized'
            exit(1)
        else:
            #logging.critical( u'FAIL to assume admin role in master account: %s. Check traceback.' % (master_account_id) )
            #raise ex
            print 'Fail to assume admin role in master account'
            exit(1)
    if client_account_id:
         try:
             #logging.info( u'Assuming client account admin role...' )
             client_role_arn = "arn:aws:iam::" + client_account_id + ":role/OrganizationAccountAccessRole"
             client_role = assume_role(client_role_arn, session_name, master_role['Credentials'])
             #print 'Client account ARN is',client_role_arn
         except botocore.exceptions.ClientError as ex:
             if ex.response['Error']['Code'] == 'AccessDenied':
                 #logging.critical( u'FAIL to assume admin role in client account: %s. Not authorized to perform sts:AssumeRole.' % (client_account_id) )
                 print 'Fail to assume admin role in client account %s, not authorized.' % (client_account_id)
                 client_role['Credentials'] = {}
                 #print 'client_role value is',bool(client_role)
                 #exit(1)
             else:
                #logging.critical( u'FAIL to assume admin role in client account: %s. Check traceback.' % (master_account_id) )
                #raise ex
                print 'Fail to assume admine role in master account'
                client_role['Credentials'] = {}
         result["Credentials"] = client_role['Credentials']

    else:
        result["Credentials"] = master_role['Credentials']
        #logging.info( u'Got credentials to master account' )
        print 'Fail to assume admine role in master account'
    return result["Credentials"]

###########End of generate_credentials##############

############Begining of get_result######################
def get_result(ssmClient,cmdResponse,regionInstanceInfo,account,reg):
    cmdID = cmdResponse['Command']['CommandId']
    cmdInsList = cmdResponse['Command']['InstanceIds']
    cmdStatus = cmdResponse['Command']['Status']
    print 'Command',cmdID,'is running in region',reg,'of account',account,'instace list is',cmdInsList,'and status is',cmdStatus
    while True:
          cmdListRes = ssmClient.list_commands(CommandId=cmdID)
          cmdStatus = cmdListRes['Commands'][0]['Status']
          print 'Command',cmdID,'status is',cmdStatus
          if(cmdStatus not in ['Pending','InProgress']):
             break
          else:
             time.sleep(5)
    for ins in cmdInsList:
        res = ssmClient.get_command_invocation(CommandId=cmdID,InstanceId=str(ins))
        waitTime = 0
        while True:
              if (res['Status'] == 'Success'):
                  output = str(res['StandardOutputContent'])
                  #output = output[:-1]
                  break
              elif (waitTime > 10):
                  output = 'Timeout'
                  break
              else:
                  print 'Waiting for script execution to be completed on instance',ins
                  time.sleep(5)
                  waitTime = waitTime + 5
        if (output != 'Timeout'):
             try:
                if(regionInstanceInfo[ins][4]=='windows'):
                   regionInstanceInfo[ins].append(output.split(',')[0])
                   regionInstanceInfo[ins].append(output.split(',')[1])
                   regionInstanceInfo[ins].append(output.split(',')[2])
                   regionInstanceInfo[ins].append(output.split(',')[3])
                   regionInstanceInfo[ins].append(output.split(',')[4].strip())
                   regionInstanceInfo[ins].append(output.split(',')[5])
                else:
                   regionInstanceInfo[ins].append(output.split(',')[0])
                   regionInstanceInfo[ins].append(output.split(',')[1])
                   regionInstanceInfo[ins].append(output.split(',')[2])
                   regionInstanceInfo[ins].append(output.split(',')[3])
                   regionInstanceInfo[ins].append(output.split(',')[4].strip())

             except Exception as e:
                   print e
        else:
            for i in range(5):
                regionInstanceInfo[ins].append(output)
    return regionInstanceInfo

############End of get_result######################

###########Begining of get_ssm_status##########
def get_agent_status(ssm,vmDict,account,region):
    ssmRes = ssm.describe_instance_information(InstanceInformationFilterList=[{'key': 'PingStatus','valueSet': ['Online']}])
    managed_linux_instances = []
    managed_win_instances = []
    for instance in ssmRes['InstanceInformationList']:
        if(instance['PlatformType'] == 'Linux'):
           managed_linux_instances.append(instance['InstanceId'])
        if(instance['PlatformType'] == 'Windows'):
           managed_win_instances.append(instance['InstanceId'])
    if 'NextToken' in ssmRes:
        while 'NextToken' in ssmRes:
               ssmRes = ssm.describe_instance_information(InstanceInformationFilterList=[{'key': 'PingStatus','valueSet': ['Online']}],NextToken=ssmRes['NextToken'])
               for instance in ssmRes['InstanceInformationList']:
                   if(instance['PlatformType'] == 'Linux'):
                      managed_linux_instances.append(instance['InstanceId'])
                   if(instance['PlatformType'] == 'Windows'):
                      managed_win_instances.append(instance['InstanceId'])
    for instanceId in vmDict.keys():
        if(instanceId in managed_linux_instances):
           vmDict[instanceId].append('Managed')
        elif(instanceId in managed_win_instances):
           vmDict[instanceId].append('Managed')
        else:
           vmDict[instanceId].append('Unmanaged')
           for i in range(5):
               vmDict[instanceId].append('NA')
    shellScript = ["rm -f /tmp/check_agent_status.*","yum list installed wget &> /dev/null","if [ $? -ne 0 ]","then","yum install wget -y &> /dev/null","fi","wget 'https://wk-agents.s3.amazonaws.com/Linux_Agents_Status.sh' -O /tmp/check_agent_status.sh","chmod a+x /tmp/check_agent_status.sh","sed -i 's/\r$//g' /tmp/check_agent_status.sh","sh /tmp/check_agent_status.sh"]

    psScript    = ["$src = 'https://wk-agents.s3.amazonaws.com/win_check_agents_status-V2.ps1'", "$dst = $env:TEMP+'\\'+'win_check_agents_status.ps1'", "Invoke-WebRequest $src -OutFile $dst", "PowerShell.exe -ExecutionPolicy UnRestricted $dst","Remove-Item -Path $dst"]


    if (len(managed_linux_instances) > 0 and len(managed_linux_instances) <= 50):
        cmdRes = ssm.send_command(InstanceIds=managed_linux_instances,DocumentName='AWS-RunShellScript',TimeoutSeconds=60,Parameters={'commands':shellScript,'executionTimeout':['60']})
        vmDict = get_result(ssm,cmdRes,vmDict,account,region)
    if (len(managed_linux_instances) > 50):
        start = 0
        end   = 50
        cmdRes = ssm.send_command(InstanceIds=managed_linux_instances[start:end],DocumentName='AWS-RunShellScript',TimeoutSeconds=60,Parameters={'commands':shellScript,'executionTimeout':['60']})
        vmDict = get_result(ssm,cmdRes,vmDict,account,region)
        while (end < len(managed_linux_instances)):
               #cmdRes = ssm.send_command(InstanceIds=managed_linux_instances[start:end],DocumentName='AWS-RunShellScript',TimeoutSeconds=60,Parameters={'commands':shellScript,'executionTimeout':['60']})
               #vmDict = get_result(ssm,cmdRes,vmDict,account,region)
               start  = end
               if(len(managed_linux_instances)-start > 50):
                  end   = start + 50
               else:
                  end   = len(managed_linux_instances)
               cmdRes = ssm.send_command(InstanceIds=managed_linux_instances[start:end],DocumentName='AWS-RunShellScript',TimeoutSeconds=60,Parameters={'commands':shellScript,'executionTimeout':['60']})
               vmDict = get_result(ssm,cmdRes,vmDict,account,region)


    if (len(managed_win_instances) > 0 and len(managed_win_instances) <= 50):
        cmdRes = ssm.send_command(InstanceIds=managed_win_instances,DocumentName='AWS-RunPowerShellScript',TimeoutSeconds=60,Parameters={'commands':psScript,'executionTimeout':['60']})
        vmDict = get_result(ssm,cmdRes,vmDict,account,region)
    if (len(managed_win_instances) > 50):
        start = 0
        end   = 50
        cmdRes = ssm.send_command(InstanceIds=managed_win_instances[start:end],DocumentName='AWS-RunPowerShellScript',TimeoutSeconds=60,Parameters={'commands':psScript,'executionTimeout':['60']})
        vmDict = get_result(ssm,cmdRes,vmDict,account,region)
        while (end < len(managed_win_instances)):
               start = end
               if(len(managed_win_instances)-start > 50):
                  end   = start + 50
               else:
                  end   = len(managed_win_instances)
               cmdRes = ssm.send_command(InstanceIds=managed_win_instances[start:end],DocumentName='AWS-RunPowerShellScript',TimeoutSeconds=60,Parameters={'commands':psScript,'executionTimeout':['60']})
               vmDict = get_result(ssm,cmdRes,vmDict,account,region)

    #try:
       #ssmStatus = ssmResponse['InstanceInformationList'][0]['PingStatus']
    #except:
       #ssmStatus = 'Not a ssm managed instance'
    return vmDict
###########End of get_ssm_status###############

###########Begining of get_InstanceName##########
def get_InstanceName(tags):
    try:
        for tag in tags:
            if(tag['Key']=='Name'):
              insName=tag['Value']
              break
    except:
          insName = 'NotDefined'
    return insName
###########End of get_InstanceName###############

###########Begining of get_Instance_patch_tag##########
def get_Instance_patch_tag(tags):
    try:
        for tag in tags:
            if(tag['Key']=='wk_patch_class'):
              insName=tag['Value']
              break
    except:
          insName = 'NotDefined'
    return insName
###########End of get_Instance_patch_tag###############


###########Begining of get_instance_info##########
def get_instance_info(account,instance,ec2,ssm):
    keys = ['InstanceName','PrivateIpAddress','PatchTag','State','Platform']
    #keys = ['InstanceId','InstanceType','State','InstanceName','PrivateIpAddress','SubnetId','Placement','VpcId','SecurityGroups','ImageId','KeyName','BlockDeviceMappings','Tags']
    ec2List = []
    ec2List.append(account['Id'])
	
    #ec2List.append(gbs_bo_awsAccounts[account])
    for key in keys:
        if(key == 'State'):
          element = instance[key]['Name']
          ec2List.append(element)
          continue
        if(key == 'InstanceName'):
          try:
             element =  get_InstanceName(instance['Tags'])
          except:
             element = 'NotDefined'
          ec2List.append(element)
          continue
        if(key == 'PatchTag'):
          try:
             element =  get_Instance_patch_tag(instance['Tags'])
          except:
             element = 'NotDefined'
          ec2List.append(element)
          continue
        if(key == 'Platform'):
           try:
              ec2List.append(instance[key])
           except:
              ec2List.append('Linux')

           continue
        try:
           ec2List.append(instance[key])
        except:
           ec2List.append('NotDefined')
    #instanceId = []
    #instanceId.append(instance['InstanceId'])
    #ssmRes = ssm.describe_instance_information(InstanceInformationFilterList=[{'key': 'InstanceIds','valueSet': instanceId}])
    #ssmStatus = get_ssm_status(ssmRes)
    #ec2List.append(ssmStatus)
    return ec2List
###########End of get_instance_info###############

##########Begining of writeToCSV#################
def writeToCSV(fileName,mode,rows):
    with open(fileName,mode) as csvFile:
         writer = csv.writer(csvFile)
         writer.writerows(rows)
    csvFile.close()
##########End of writeToCSV######################

#############Begining of get_vm_inventory#########
def get_vm_inventory(accCredentials,accID):
    ec2 = boto3.client(
        'ec2',
        region_name='us-east-1',
        aws_access_key_id     = accCredentials['AccessKeyId'],
        aws_secret_access_key = accCredentials['SecretAccessKey'],
        aws_session_token     = accCredentials['SessionToken'],
    )
    #resRegions = ec2.describe_regions()
    regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    #keys = ['InstanceId','PrivateIpAddress','InstanceType','Tags']
    
    lock = threading.Lock()
    for region in regions:
        accEC2List.append(region)
        ec2Client = boto3.client(
                 'ec2',
                 region_name=region,
                 aws_access_key_id     = accCredentials['AccessKeyId'],
                 aws_secret_access_key = accCredentials['SecretAccessKey'],
                 aws_session_token     = accCredentials['SessionToken'],
        )
        ssmClient = boto3.client(
                 'ssm',
                 region_name=region,
                 aws_access_key_id     = accCredentials['AccessKeyId'],
                 aws_secret_access_key = accCredentials['SecretAccessKey'],
                 aws_session_token     = accCredentials['SessionToken'],
        )

        region_vm_info = {}
        ec2Res = ec2Client.describe_instances()
        for rsv in ec2Res['Reservations']:
            for instance in rsv['Instances']:
                instanceInfo = get_instance_info(accID,instance,ec2Client,ssmClient)
                region_vm_info[instance['InstanceId']] = instanceInfo
                #accEC2List.append(instanceInfo)
        if 'NextToken' in ec2Res:
           while 'NextToken' in ec2Res:
               ec2Res = ec2Client.describe_instances(NextToken=ec2Res['NextToken'])
               for rsv in ec2Res['Reservations']:
                   for instance in rsv['Instances']:
                       instanceInfo = get_instance_info(accID,instance,ec2Client,ssmClient)
                       region_vm_info[instance['InstanceId']] = instanceInfo
                       #accEC2List.append(instanceInfo)
        region_vm_info = get_agent_status(ssmClient,region_vm_info,accID,region)
        for instanceId in region_vm_info.keys():
            accEC2List.append(region_vm_info[instanceId])

    try:
       lock.acquire()
       writeToCSV(file,'a',accEC2List)
    finally:
        lock.release()
        del accEC2List[0:]
#############End of get_vm_inventory##############

############Begining of manageThread################
def manageThread(threadPool):
    global inaccessibleAccounts
    threads = []
    for account in threadPool:
        accCredDic =  generate_credentials(account)
        if not bool(accCredDic):
           inaccessibleAccounts.append(account)
        else:
           t = threading.Thread(name=account, target=get_vm_inventory, args=(accCredDic,account,))
           t.start()
           threads.append(t)
           threadName = t.getName()
           print 'Thread %s has been started ' %(threadName)
    for t in threads:
        #if t is not main_thread:
        threadName = t.getName()
        t.join()
        print 'Exiting from the thread',threadName

############End of manageThread####################

#################Begining of create_thread#########
def create_thread(client_accounts):
    client_acc_id = ""
    master_acc_cred = generate_credentials(client_acc_id)
    num_of_acc = len(client_accounts)
    loopCount = 0
    threadPool = []
    for clientAcc in client_accounts:
        loopCount+=1
        threadPool.append(clientAcc)
        if(len(threadPool) == 5):
           manageThread(threadPool)
           del threadPool[0:]
        if((num_of_acc - loopCount) == 0):
            manageThread(threadPool)
            del threadPool[0:]
#################End of create_thread#########


#################Begining of main#########
def main():
        writeToCSV(file,'w',header)
        logging.basicConfig(level=logging.INFO, format='[%(levelname)s] (%(threadName)-9s) %(message)s',)
        logging.debug('Starting main  thread')
        client_acc_id = ""
        master_acc_cred = generate_credentials(client_acc_id)
        if('-AWSaccounts' not in sys.argv):
           sys.exit()
        elif('All' in sys.argv):
             client_accounts = get_account_list(master_acc_cred)
        else:
             client_accounts = sys.argv
             del client_accounts[0:2]
        if (len(client_accounts) > 30):
            start = 0
            end   = 30
            create_thread(client_accounts[start:end])
            while (end < len(client_accounts)):
                   start  = end
                   if(len(client_accounts)-start > 30):
                      end   = start + 30
                   else:
                      end   = len(client_accounts)
                   create_thread(client_accounts[start:end])
        else:
            create_thread(client_accounts)

        print 'Inaccessible AWS accounts are',inaccessibleAccounts
        logging.debug('Exiting from  main  thread')
#################Ending of main#########

if __name__ == '__main__':
     main()

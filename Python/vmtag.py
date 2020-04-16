import boto3
import json


def fetchInstances(region, credentials):
  ec2 = boto3.client('ec2', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
  instances=[]
  try:
    nextToken=''
    while nextToken is not None:
      response=ec2.describe_instances(NextToken=nextToken)
      reservations=response.get("Reservations", [])
      for reservation in reservations:
        for instance in reservation.get("Instances",[]):
          instanceData={}
          instanceId=instance.get('InstanceId')
          instanceData['InstanceId']=instanceId
          vpcId=instance.get('VpcId')
          instanceData['VpcId']=vpcId
          if 'Tags' in instance.keys():
            tags=instance.get('Tags')
            instanceData['Tags']=tags
          instances.append(instanceData)
      nextToken=response.get('NextToken')
    return instances
  except  Exception as e:
    print e.message

def checkVmTagingExempt(tags):
    exemptStatus='false'
    if tags != []:
      for tag in tags:
        #print "%%%%%%%%%tag:", tag
        #print "%%%%%%%%%tag['Key']:", tag['Key']
        if tag['Key']=='wk_cms_std_enf_exempt':
         # print "%%%%%%%%%tag['Value']:", tag['Value']
          return tag['Value']
    return exemptStatus

def checkTags(tags, vmTags):
  newTagList=[]
  for vmtag in vmTags['tags']:
    tagKey=vmtag['tag_key']
    if tags != []:
      for tag in tags:
        if tagKey not in tag.values():
          newTag={}
          newTag['Key']=tagKey
          newTag['Value']=vmtag['default_value']
          newTagList.append(newTag)
    else:
     newTag={}
     newTag['Key']=tagKey
     newTag['Value']=vmtag['default_value']
     newTagList.append(newTag)
  return newTagList

def addTags(newTagList,instanceId,region, credentials):
  ec2=boto3.client('ec2', region_name=region, aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
  try:
    ec2.create_tags(Resources=[instanceId], Tags=newTagList)
    #print "Added tags..."
  except Exception as e:
    print e.message

def checkVpcId(currentAccount, vpcId, metadata):
    #print "metadata: ", metadata
    vpcStatus=''
    for account in metadata['AccountMetadata']:
      if currentAccount == account['AccountId']:
        vpcList = account['VDC']
        for vpc in vpcList:
          if vpcId == vpc['VdcId']:
             vpcStatus = 'Exists'
    return vpcStatus



def tagVms(currentAccount, region, data, vmTags, credentials):
 # print "inside tagVms..."
  notRemediatedVms=[]
  remediatedVms=[]
  tags=[]
  instances=[]
 # print "fetching instances..."
  instances = fetchInstances(region, credentials)
  if instances !=[]:
 # print "instances: ", instances
    for instance in instances:
      vpcId= instance.get('VpcId')
  #   print "vpcId: ", vpcId
      instanceId=instance.get('InstanceId')
      if 'Tags' in instance.keys():
        tags=instance.get('Tags')
  #    print "checking exempt status..."
      vpcStatus = checkVpcId(currentAccount, vpcId, data)
  #    print "exemptStatus: ", exemptStatus
      if vpcStatus == '':
        notRemediated = {}
        notRemediated[instanceId]="VPC for this instance is not mentioned in metadata file"
        notRemediatedVms.append(notRemediated)
      else:
        exemptStatus=checkVmTagingExempt(tags)
        #print "exempt Status for instance Id: ",instanceId, "is: ", exemptStatus
        if exemptStatus == 'True' or exemptStatus == 'true':
          #print "inside true..."
          notRemediated = {}
          notRemediated[instanceId]="The exemption flag for this VM is set to True"
          notRemediatedVms.append(notRemediated)
        else:
          if exemptStatus == 'False' or exemptStatus == 'false':
           # print "inside false..checking tags"
            newTagList = []
            newTagList=checkTags(tags, vmTags)
            #print "newTagList: ", newTagList
            if newTagList != []:
             # print "Adding Tags"
              addTags(newTagList,instanceId,region, credentials)
              taggedVm={}
              taggedVm[instanceId]="Tags Added"
            # taggedVm['AddedTags']=newTagList
              remediatedVms.append(taggedVm)
            else:
              print "No new tags found to be added."
  else:
    print "There are no instances in ",region," region of account ",currentAccount  
  #print "resultss..."
  #print remediatedVms, notRemediatedVms
  return remediatedVms, notRemediatedVms

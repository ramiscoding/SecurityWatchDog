#!/usr/bin/env python

import ConfigParser
import sys
import boto3
import time
import feedparser
import pprint
from slacker import Slacker

def print_usage():
  """ Method to print the usage message for the program. """
  print "Usage: ./sec-watchdog-final.py [filename] [config-file]"
  print 'Arguments:'
  print "filename : Name of the file which contains the list of instances"
  print "config-file : File that contains the slack api and aws profile name"


def createBucket(aClient, aBucketName):
  """ Method to create the S3 bucket.
      S3 bucket is used to store the output from SSM command
      as the output is huge and SSM truncates output greater than
      2500 characters.
  """
  try:
    response = aClient.create_bucket(Bucket=aBucketName)
    return response['location']
  except Exception as error:
    print error


def removeBucket(aClient, aBucketName):
  """ Method to delete the bucket after the work is done. """
  myBucket = aClient.Bucket(aBucketName)
  try:
    for key in myBucket.objects.all():
      response = key.delete()
    response = myBucket.delete()
  except Exception as error:
    print error


def getAffectedPackages(aFeed):
  """ Method to get the list of vulnerable packages from Amazon feed.
      This method fetches the latest 100 vulnerable packages from the Amazon
      Linux AMI security feed.
  """
  myAffectedPackages = []
  myAffectedList = aFeed.entries
  myLimitedList = myAffectedList[:100]
  myEtag = aFeed.etag
  myModifiedTime = aFeed.modified
  for package in myLimitedList:
    myAffectedPackages.append(package.title.split(":")[-1].strip())
  return myAffectedPackages


def getFeeds(aFeed):
  """ Helper method to get the feed list. """
  myFeedsList = aFeed.entries
  return myFeedsList


def parseSSMOutput(aClient, aDict, anInstance, aS3Client, aBucketName):
  """ Method to parse the SSM command output and find vulnerable packages. 
      This method gets the list of packages on the instance and compare
      it with the vulnerable packages to produce the result.
  """ 
  aNewDict = {}
  bucket_name = aBucketName
  myPackages = []
  myUPackagesList = []
  myBucket = aS3Client.Bucket(bucket_name)
  for obj in myBucket.objects.all():
    key = obj.key
    body = obj.get()['Body'].read()
  myUPackagesList = body.split('\n')
  for key in myBucket.objects.all():
    response = key.delete()
  for line in myUPackagesList:
    myPackages.append(line.split(" ")[0])

  myVPackages = []
  instPackages = aDict[anInstance]
  for pack in instPackages:
    for myPack in myPackages:
      if pack in myPack:
	myVPackages.append(pack) 
      else:
	if pack in instPackages:
	  instPackages.remove(pack)
  aNewDict[anInstance] = myVPackages
  return aNewDict


def parseSSMOutputFromBucket(aClient, aBucketName):
  """ Method to get package list from S3 bucket. """ 
  myPackagesList = []
  body = ""
  bucket_name = aBucketName
  myBucket = aClient.Bucket(bucket_name)
  for obj in myBucket.objects.all():
    key = obj.key
    body = obj.get()['Body'].read()
  myPackagesList = []
  myPackagesList = body.split('\n')
  for key in myBucket.objects.all():
    response = key.delete()
  return myPackagesList


def getInstanceList(aFileName):
  """ Helper method to get instance list from the file. """
  myInstanceList = []
  file = open(aFileName, 'r')
  for line in file: 
    myInstanceList.append(line)
  return myInstanceList


def getCVEList():
  """ Method to parse the feed and get the affected packages list. """
  rFeed = feedparser.parse('https://alas.aws.amazon.com/alas.rss')
  feedDetails = getFeeds(rFeed)
  myCVEList = getAffectedPackages(rFeed)
  return myCVEList


def getPackageListFromInstances(anInstanceList, anAWSClient, aS3Client, aBucketName):
  """ Method to get the list of packages in the instance.
      SSM command is executed on the instance to get the list of packages in 
      the instance.
  """
  myInstancesPackageList = {}
  for instanceID in anInstanceList:
    myId = instanceID.strip()
    ssmOutput = anAWSClient.send_command(InstanceIds=[myId], DocumentName='AWS-RunShellScript', OutputS3BucketName=aBucketName, Comment='Get Instance Package List', Parameters={"commands":["rpm -qa | sort"]})
    myCommandId = ssmOutput['Command']['CommandId']
    time.sleep(2)
    myPackages = parseSSMOutputFromBucket(aS3Client, aBucketName)
    myInstancesPackageList.update({myId:myPackages})
  return myInstancesPackageList


def checkForVulnerablePackages(aCVEList, anInstancesPackageList):
  """ Method to check for vulnerable packages in the instance. """
  myReport = {}
  uniquePackages = []
  for instance in anInstancesPackageList:
    instanceId = instance
    packs = anInstancesPackageList[instance]
    for package in aCVEList:
      for pack in packs:
	if package in pack:
	  if instanceId in myReport:
	    existingList = myReport[instanceId]
	    existingList.append(package)
	  else:
	    myReport.update({instanceId:[package]})
    if instanceId not in myReport:
      myReport.update({instanceId:packs})
  pprint.pprint(myReport)
  for ins in myReport:
    uniquePackages = list(set(myReport[ins]))
    myReport[ins] = uniquePackages
  return myReport


def checkForPackageUpdates(aClient, anInstanceDict, aS3Client, aBucketName):
  """ Method to check if vulnerable package identified has an update. 
      This method is used to determine if the package is in its latest version 
      or still not patched and vulnerable.
  """
  myFinalReport = {}
  for instance in anInstanceDict:
      myVPacksList = anInstanceDict[instance]
    #for package in myVPacksList:
      myCommand = "yum check-update"
      ssmOutput = aClient.send_command(InstanceIds=[instance], DocumentName='AWS-RunShellScript', OutputS3BucketName=aBucketName, Comment='Check Update available', Parameters={"commands":[myCommand]})
      myCommandId = ssmOutput['Command']['CommandId']
      time.sleep(5)
      myFinalReport.update(parseSSMOutput(aClient, anInstanceDict, instance, aS3Client, aBucketName))
  return myFinalReport


def writeToFile(aDict):
  """ Method to write the output to the file to make it look nicer. """
  aParser = ConfigParser.ConfigParser()
  myOutputFile = open("report.ini", 'w')
  for instance in aDict:
    aParser.add_section(instance)
    for pack in aDict[instance]:
      aParser.set(instance,pack,"Update-Required")
  aParser.write(myOutputFile)
  myOutputFile.close()


def readFileAsString():
  """ Method to read the report file. """
  with open('report.ini', 'r') as myfile:
    data=myfile.read()
    #data=myfile.read().replace('\n', '')
  return data


if len(sys.argv)!=3:
  print_usage()
  sys.exit(1)

config = ConfigParser.ConfigParser()
config.read(sys.argv[2])
slackkey = config.get('PROFILE', 'slack')
profile = config.get('PROFILE', 'aws-profile')

slack = Slacker(slackkey)

print "Connecting to AWS Infrastructure..."
session = boto3.Session(profile_name=profile)
ssm_client = session.client('ssm')


print "Getting Latest Vulnerable Package List..."
vulnerablePackagesList = getCVEList()
print "-------------"

print "Getting the list of Instances..."
instanceList = getInstanceList(sys.argv[1])
#print instanceList
print "-------------"

print "Creating S3 bucket..."
s3_client = session.resource('s3')
bucket_name = "infra-sec-package-list-56781234"
bucket_name1 = "infra-sec-update-list-56781234"
my_bucket = createBucket(s3_client, bucket_name)
my_bucket2 = createBucket(s3_client, bucket_name1)
print "-------------"

print "Getting list of packages installed on the instances..."
instancesPackageList = getPackageListFromInstances(instanceList, ssm_client, s3_client, bucket_name)
#pprint.pprint(instancesPackageList)
print "-------------"

print "Scanning for Vulnerable packages on the instances..."
report = checkForVulnerablePackages(vulnerablePackagesList, instancesPackageList)
#pprint.pprint(report)
print "-------------"

print "Checking if the Vulnerable packages are updated..."
final_report = checkForPackageUpdates(ssm_client, report, s3_client, bucket_name1)
for ins in final_report:
    uniquePackages = list(set(final_report[ins]))
    final_report[ins] = uniquePackages
pprint.pprint(final_report)

writeToFile(final_report)
slack_message = readFileAsString() 
slack.chat.post_message('#test-infra-sec', slack_message)

removeBucket(s3_client, bucket_name)
removeBucket(s3_client, bucket_name1)

print "Success!!!"

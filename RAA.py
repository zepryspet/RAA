#!/usr/bin/python

import argparse         #Read CLI input
import requests         #libary to perform HTTP calls
import ipaddress        #Validate IP addresses
import calendar         #Epoch generator
import time             #time
import os               #To delete files
import xml.etree.ElementTree as ET  #XML parser to analyze logs
from collections import Counter     #To create log dictionary

def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def DeleteFile (filename): 
    ## get input ##
    ## check if a file exists on disk ##
    ## if exists, delete it else show message on screen ##
    if os.path.exists(filename):
        try:
            os.remove(filename)
            return ("File removed")
        except OSError as e:
            return ("Error: %s - %s." % (e.filename,e.strerror))
    else:  
        return ("Sorry, I can not find %s file." % filename)        

def Commit (url, apikey):
    APIcommit = '?type=commit&cmd=<commit></commit>'
    CommitAPI = url + APIcommit + apikey
    CommitResponse = requests.get(CommitAPI)
    #Getting the job Id to verify that the commit went through fin
    JobID= find_between( CommitResponse.text, "<job>", "</job>" )
    ShowJob = Url + '?type=op&cmd=<show><jobs><id>' + JobID + '</id></jobs></show>' + APIkey
    PendingCommit = 1
    print ("Waiting for commit to finish...", end='',flush=True)  
    while (PendingCommit == 1):
    #check commit status every 2 seconds
        time.sleep(2)
        CommitStatus = requests.get(ShowJob)
        if find_between( CommitStatus.text, "<status>", "</status>" ) == 'FIN':
            result= find_between( CommitStatus.text, "</stoppable><result>", "</result>" ) 
            if result== 'OK':
                print ("Commit done successfully \n")
                return result
            else:
                print ("Commit failed, printing reason please validate manually \n")
                print (CommitStatus.text)
                return CommitStatus.text
            PendingCommit = 0
        else:  
            print ("...", end='',flush=True)    

def AppAnalyzer(XmlLogs):
    listing = []
    root = ET.fromstring(XmlLogs)
    for entry in root.findall("./result/log/logs/entry"):
        app = entry.find('app').text
        proto = entry.find('proto').text
        dport = entry.find('dport').text
        #print (entry.attribute)
        listing.append(app+" / "+proto+" / "+dport)
    dictionary = Counter(listing)
    print ("-----------------------------------------------------------")
    print ("the applications used are:")
    print ("Sessions\tApplication / protocol / port")
    for k, v in dictionary.items():
        print(str(v) + "\t\t" + k)
    print ("-----------------------------------------------------------")    

#The IP Argument is required, parsing it and saving in args.ip
parser = argparse.ArgumentParser()
parser.add_argument("ip", help="Allow all outgoing ports to the internet from this source")
args = parser.parse_args()

#Building the API call
Url= 'https://firewall.com/api'
SourceZone = 'Trust'
DestinationZone = 'Untrust'
APIkey = '&key=XXXXXXXXX'
APIset= '?type=config&action=set'
APImove= '?type=config&action=move'
APIDelete = "?type=config&action=delete"
#Creating Xpath to a new policy and using the Epoch time to name it.
Epoch = str(calendar.timegm(time.gmtime()))  #Epoch time to name security policies, typecasting into string instead of int.
PolicyName = 'Epoch-' + Epoch
XpathPolicy = '&xpath=/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/rulebase/security/rules/entry[@name=\'' + PolicyName+ '\']'
RuleQuery= "?type=log&log-type=traffic&query=( rule eq " + PolicyName + " )"

#API calls
MoveTop= Url + APImove + APIkey + XpathPolicy + '&where=top'
LogAPI = Url + RuleQuery + APIkey
DeleteAPI = Url + APIDelete + APIkey + XpathPolicy
    
#validate that the provided argument is a valid IP address
try:
    ipaddress.ip_address(args.ip)
except ValueError:                      #If it's invalid
    print("Invalid IP\n")
else:                                   #If the IP is valid create the security policy
    #Building security policy based on the provided IP
    Element = ("&element="
            "<to><member>" + DestinationZone + "</member></to>"
            "<from><member>" + SourceZone + "</member></from>"
            "<source><member>" + args.ip + "</member></source>"
            "<destination><member>any</member></destination>"
            "<source-user><member>any</member></source-user>"
            "<category><member>any</member></category>"
            "<application><member>any</member></application>"
            "<service><member>any</member></service>"
            "<hip-profiles><member>any</member></hip-profiles>"
            "<action>allow</action>")
    #Building get request        
    request = Url + APIset + APIkey + XpathPolicy + Element    
    #Sending HTTP resquest, without verifying certificate!!! and Saving HTTP response    
    response = requests.get(request)
    #Verifying that we get an OK response and printing it (HTTP code 200)
    if response.status_code == 200: 
        #Moving policy to the top of the ruleset
        print("Security policy created")
        MovingResponse = requests.get(MoveTop)
        if MovingResponse.status_code == 200: 
            print("Security policy moved to the top of the ruleset")
            Commit (Url, APIkey)
        else:
            print("failed to move security policy to the top of the ruleset \n" + MovingResponse.text)
    else:                                       
       print("failed to create security policy \n" + response.text)   

############## Wait Until Test is done #########################       
print ("Press ctrl + C when the test is done so I can analyze the logs\n")
#loop until the user press ctrl+c
try:
    while True:
        time.sleep(2)
except KeyboardInterrupt:
    pass
#################################################################
#Getting the job ID  to get the logs based on the previous security policy name
CommitResponse = requests.get(LogAPI)
JobID= find_between( CommitResponse.text, "<job>", "</job>" )
print ("\n Analyzing logs...")
#print ("Debug: the job ID is " + JobID)
#Getting the logs checking the Job ID
ShowJob = Url + '?type=log&action=get&job-id=' + JobID + APIkey
PendingCommit = 1
while (PendingCommit == 1):
    #check commit status every 2 seconds
    time.sleep(2)
    CommitStatus = requests.get(ShowJob)
    if find_between( CommitStatus.text, "<status>", "</status>" ) == 'FIN':             
        PendingCommit = 0    

#Analyzing logs 
AppAnalyzer(CommitStatus.text)
#Deleting test policy  

DeletePolicy = requests.get(DeleteAPI)
if DeletePolicy.status_code == 200: 
    print ("\nThe test security policy has been deleted")
    Commit (Url, APIkey)

#Saving logs to a file in case a manual analysis is needed
DeleteFile ('Logs.txt')             #Delete Previous logs if they exist
try:
    with open('Logs.txt', "a+" ) as File:
        File.write(CommitStatus.text)
except OSError as e:
    print ("Error: %s - %s." % (e.filename,e.strerror))     

  



RAA - Rapid Application Analyzer
Script that uses the Palo Alto XML API to analyze the applications being used by an specific source.

The script will follow the next flow:
1. Create an open security policy (Named epoch-XXXXXXXXXXX) from the defined zones in the script (Trust to Untrust) based on the provided source IP
2. Commit the changes
3. Is moved to idle state until the test is finished.
4. Remove the previously created security policy.
5. Analyze the logs and provide the applications/port/protocols being used.

Requirements:
Python 3
https://www.python.org/download/releases/3.0/

Requests
http://docs.python-requests.org/en/master/

Modify the folllowing variables to create your own rules:
Url= 'https://firewall.com/api' --Change firewall.com for your IP or hostname
SourceZone = 'Trust'			--Change Trust for source zone
DestinationZone = 'Untrust'		--Change Unstrust for your destination zone
APIkey = '&key=XXXXXXXXXXX'		--Change XXXXXXXXXX for your API call

Execution:
# python3 RAA.py <Ip-address>

Command output example:
$ python3 RAA.py 172.16.1.101
Security policy created
Security policy moved to the top of the ruleset
Waiting for commit to finish................................................................................................................................................Commit done successfully 

Press ctrl + C when the test is done so I can analyze the logs

^C
 Analyzing logs...
-----------------------------------------------------------
the applications used are:
Sessions	Application / protocol / port
1		whatsapp-base / tcp / 5222
8		ssl / tcp / 443
1		gmail-base / tcp / 443
1		office365-consumer-access / tcp / 443
3		imap / tcp / 993
-----------------------------------------------------------

The test security policy has been deleted
Waiting for commit to finish................................................................................................................................................Commit done successfully 

Tested on
Hosts: windows 7, raspbian, MACos el capitan.
PAN-OS: 7.1

Known issues:
1. The certificate must be trusted by the endpoint executing the script otherwise the HTTPs call will faill. The script could be modified to not verify the certificate but it's not recommended.
http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification

#!/usr/bin/python3
import subprocess
import countries #Dictionary of country codes


def formatter(c1): #Accepts input from whoisSearch function and looks for key words to obtain country and organization name from whois search results
	orgCapture = subprocess.run(['grep', '-E', 'OrgName|org-name|CustName|owner', '-m', '1'], capture_output=True, text=True, input=c1.stdout)
	orgNameCut = subprocess.run(['cut', '-d', ':', '-f', '2'], capture_output=True, text=True, input=orgCapture.stdout)
	orgName = orgNameCut.stdout
	orgFormat = orgName.strip()

	netCapture = subprocess.run(['grep', 'netname', '-m', '1'], capture_output=True, text=True, input=c1.stdout)
	netNameCut = subprocess.run(['cut', '-d', ':', '-f', '2'], capture_output=True, text=True, input=netCapture.stdout)
	netName = netNameCut.stdout
	netFormat = netName.strip()

	countryCapture = subprocess.run(['grep', '-E','Country|country', '-m', '1'], capture_output=True, text=True, input=c1.stdout)
	countryNameCut = subprocess.run(['cut', '-d', ':', '-f', '2'], capture_output=True, text=True, input=countryCapture.stdout)
	country = countryNameCut.stdout
	countryFormat = country.strip()

	if orgFormat == '':
		return netFormat, countryFormat
	else:
		return orgFormat, countryFormat

def whoisSearch(ip): #Runs WHOIS search on supplied IP address
	c1 = subprocess.run(['whois', ip], capture_output=True, text=True)
	if 'Found a referral to' in str(c1):
		ref = subprocess.run(['grep','Found a referral to'], capture_output=True, text=True, input=c1.stdout)
		refNameCut = subprocess.run(['cut', '-d', ' ', '-f', '5'], capture_output=True, text=True, input=ref.stdout)
		refName = refNameCut.stdout
		refStrip = refName.strip()

		c2 = subprocess.run(['whois', '-h', refStrip, ip], capture_output=True, text=True)
		return c2
	else:
		return c1

def host(ip): #Runs a hostname lookup based on supplied IP
	host = subprocess.run(['host', ip], capture_output=True, text=True)
	if 'not found' in str(host):
		return None
	else:
		hostCapture = subprocess.run(['cut', '-d', ' ', '-f', '5'], capture_output=True, text=True, input=host.stdout)
		hostName = hostCapture.stdout
		hostFormat = hostName.strip()
		return hostFormat


print('IP address to WHOIS search: ', end='')
ip = input()
orgname, country = formatter(whoisSearch(ip))
country = countries.countryCode(country)
host = host(ip)

print('Did OTX Flag as malicious? (y/n): ', end='')
otx = input().upper()

if otx == 'Y' and host != None:
	flagged = '%s - WHOIS returned %s (OTX flagged as malicious) - Hostname: %s - %s IP' % (ip, orgname, host, country)
	print(flagged)
elif otx == 'Y' and host == None:
	flagged = '%s - WHOIS returned %s (OTX flagged as malicious) - %s IP' % (ip,orgname,country)
	print(flagged)
elif otx and host != None:
		flagged = '%s - WHOIS returned %s - Hostname: %s - %s IP' % (ip,orgname,host,country)
		print(flagged)
elif otx and host == None:
		flagged = '%s - WHOIS returned %s - %s IP' % (ip,orgname,country)
		print(flagged)

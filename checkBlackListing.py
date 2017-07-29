import pandas as pd
import sys
import requests
import ConfigParser

if ((len(sys.argv) < 2)):
    print """\
This script check for blacklisted URLs

Usage:  python checkBlackListing.py <URL-Dataset file>
"""
    sys.exit(1)

config = ConfigParser.ConfigParser()
config.readfp(open('apikeys.txt'))
urlFile = sys.argv[1]

# Reading csv data using ; as separator
data = pd.read_csv(urlFile, sep = ';')

# GoogleSafeBrowsing Info
def checkGoogleSafeBrowsing(urlToCheck):
	url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
	payload = {'client': {'clientId': "mycompany", 'clientVersion': "0.1"},
	        'threatInfo': {'threatTypes': ["SOCIAL_ENGINEERING", "MALWARE"],
	                       'platformTypes': ["ANY_PLATFORM"],
	                       'threatEntryTypes': ["URL"],
	                       'threatEntries': [{'url': urlToCheck}]}}
	params = {'key': config.get('API Keys', 'googlesafebrowsing_api_key')}
	response = requests.post(url, params=params, json=payload)
	print response.json()
	return response.json()

# PhishTank Info
def checkPhishTank(urlToCheck):
	data = {'url':urlToCheck,
        'format':'json',
        'app_key': config.get('API Keys', 'phishtank_api_key')}
	response = requests.post(url = "http://checkurl.phishtank.com/checkurl/", data = data)
	print response.json()
	return response.json()

# Virus Total Info
def checkVirusTotal(urlToCheck):
	try:
		params = {'apikey': config.get('API Keys', 'virustotal_api_key'), 'url': urlToCheck}
		response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
		print response.json()
		return response.content
	except:
		pass

# Web-of-Trust Info
def checkWOT(urlToCheck):
	print urlToCheck
	params = {'hosts': urlToCheck, 'callback':	'process', 'key': config.get('API Keys', 'wot_api_key')}
	response = requests.get(url='http://api.mywot.com/0.4/public_link_json2', params=params)
	print response.content
	return response.content


result = {}	

# Iterate each row of data
for index, row in data.iterrows():
	result[row['url']] = {}
	result[row['url']]['googleSafeBrowsing'] = checkGoogleSafeBrowsing(row['url'])
	result[row['url']]['PhishTank'] = checkPhishTank(row['url'])
	result[row['url']]['VirusTotal'] = checkVirusTotal(row['url'])
	result[row['url']]['wot'] = checkWOT(row['url'])



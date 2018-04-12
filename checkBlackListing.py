import pandas as pd
import sys
import requests
import ConfigParser
from urlunshort import resolve

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
with open(urlFile) as fr:
	content = fr.readlines()

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
	print "GoogleSafeBrowsing", response.json()
	return response.json()

# PhishTank Info
def checkPhishTank(urlToCheck):
	data = {'url':urlToCheck,
        'format':'json',
        'app_key': config.get('API Keys', 'phishtank_api_key')}
	response = requests.post(url = "http://checkurl.phishtank.com/checkurl/", data = data)
	# print "PhishTank", response.json()
	isSpam = False
	if 'results' in response.json():
		return response.json()['results']['in_database']
	else:
		return isSpam
# Virus Total Info
def checkVirusTotal(urlToCheck):
	try:
		params = {'apikey': config.get('API Keys', 'virustotal_api_key'), 'url': urlToCheck}
		response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
		# print "VirusTotal", response.json()
		return response.content
	except:
		pass

# Web-of-Trust Info
def checkWOT(urlToCheck):
	params = {'hosts': urlToCheck, 'callback':	'process', 'key': config.get('API Keys', 'wot_api_key')}
	response = requests.get(url='http://api.mywot.com/0.4/public_link_json2', params=params)
	# print "WOT", response.content
	isSpam = False
	try:
		content = eval(response.content[8:-1])
		print content

		repu = []
		conf = []
		if repu:
			if (sum(repu)/len(repu)) > 60 and (sum(conf)/len(conf) < 10):
				isSpam = True
		for keys in content:
			repu.append(content[keys]['0'][0])
			repu.append(content[keys]['1'][0])
			repu.append(content[keys]['2'][0])
			repu.append(content[keys]['4'][0])
			conf.append(content[keys]['0'][1])
			conf.append(content[keys]['1'][1])
			conf.append(content[keys]['2'][1])
			conf.append(content[keys]['4'][1])
				# repu.append(vals['1'])
	except:
		pass
	return isSpam

result = {}	

# Iterate each row of data
for lines in content:
	url1 = lines.split("\t")[1].replace("\n","")
	urlLink = resolve(url1)
	print urlLink
	result[urlLink] = {}
	# result[urlLink]['googleSafeBrowsing'] = checkGoogleSafeBrowsing(urlLink)
	phishtank_res = checkPhishTank(urlLink)
	virusTotal_res = checkVirusTotal(urlLink)
	wot_res = checkWOT(urlLink)
	
	with open('finalUrlSpam.csv','a+') as fw:
		fw.write(lines.split("\t")[0] + "," + lines.split("\t")[1].replace("\n","") + "," + str(phishtank_res) + "," + str(wot_res) + "\n")



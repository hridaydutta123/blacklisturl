# BlacklistChecker


BlacklistChecker can be used to check URLs with help from various online URL scanning service. Presently it checks the following online services:

  - Google SafeBrowsing API
  - PhishTank API
  - VirusTotal API
  - Web-of-Trust API

### Usage
```sh
python checkBlackListing.py <URL-Dataset file>
```

Create a file named apikeys.txt and place the credentials as follows...

```sh
[API Keys]
googlesafebrowsing_api_key = <API-Key>
phishtank_api_key = <API-Key>
virustotal_api_key = <API-Key>
wot_api_key = <API-Key>
```
For any issue contact Hridoy Dutta hridaydutta123@gmail.com
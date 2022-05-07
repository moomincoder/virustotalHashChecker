import requests
import json
import time
import virustotal_python
import re
import sys
# Made by Isaiah Davis-Stober 5-6-2022
# Specs:
    # Write a Python or PowerShell script that accepts a file hash value (MD5 or SHA256) from the user and submits the hash to VirusTotal via an API call.
    # If VirusTotal finds more than 5 AV engines detected the file as malicious, output a message that informs the user and tells them how many AV engines detected the file.
    # If VirusTotal finds that less than 5 AV engines reported the file as malicious, output a message that indicates the file may be malicious and tells the user how many AV engines detected the file.
    # If no AV engines indicate the file is malicious, output a message that tells the user that the file is clean.

# if less than 5 AVs detect something it may be dirty, if more than 5 it is dirty, and if 0 its clean. 

# checking the hash that was given to make sure its MD5 or SHA256
def checkHash():
	validHash = False
	validHash = bool(reExpression.match(strInputHash))
	if validHash:
		print("Valid hash")
		return
	else:
		print("Invalid hash, exiting")
		sys.exit()

# getting user input
def askForUserInput():
	print("Please input the file hash: ")
	strInputHash = input()
	print("Please input your Virustotal API key: ")
	strInputKEY = input()
	if strInputKEY == "Blank":
		print("Invalid Virustotal API key")
		sys.exit()
	else:
		return strInputHash, strInputKEY

# input validation
# sha256 re ^[A-Fa-f0-9]{64}$
# md5 re /^([a-f\d]{32}|[A-F\d]{32})$/
reExpression = re.compile('^[A-Fa-f0-9]{64}$|^([a-f\d]{32}|[A-F\d]{32})$')

strInputHash = "Blank"
strInputKEY = "Blank"

# strInputHash = '36ab33fe616240cad10a72eb0403987a55e6a833bf0348552d38ca10930a6a45'
# strInputKEY = 'b96a0a596af68dfd28cfef1e2f29f374d5fea2d857d11f0114b65c3f23a8ab50'

strInputHash, strInputKEY = askForUserInput()
checkHash()

with virustotal_python.Virustotal(strInputKEY) as vtotal:
	response = vtotal.request(f"files/{strInputHash}")
	responseCode = response.status_code
	if responseCode != 200:
		print(f"The API call failed with error code {responseCode}")
	else:
		print(f"The HTTP response code was {responseCode}") # http response code

	jsonResponse = json.loads(response.text)
	totalPositives = jsonResponse['data']['attributes']['last_analysis_stats']['malicious']

	if totalPositives <= 0:
		print(f"Clean, total number of postives was {totalPositives}")
	elif totalPositives <= 5:
		print(f"Possibly dirty, total number of postives was {totalPositives}")
	else:
		print(f"Dirty, total number of postives was {totalPositives}")



# API key for VT
# b96a0a596af68dfd28cfef1e2f29f374d5fea2d857d11f0114b65c3f23a8ab50
import json
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
	# uses regex to determine if the given hash is valid, and respondes appropriately, if this fails it exits the script
	validHash = bool(reExpression.match(strInputHash))
	if validHash:
		print("Valid hash")
		return
	else:
		print("Invalid hash, exiting")
		sys.exit()

# getting user input, takes no input and returns strInputHash and strInputKEY, if the API key hasn't changed it exits out of the program, not sure if I should have it check to make sure the key is a SHA256 hash
def askForUserInput():
	print("Please input the file hash: ")
	strInputHash = input()
	print("Please input your Virustotal API key: ")
	strInputKEY = input()
	# if there was no input for the API key display an error and exit out
	if strInputKEY == "Blank":
		print("Invalid Virustotal API key")
		sys.exit()
	else:
		return strInputHash, strInputKEY
# input validation
# sha256 re ^[A-Fa-f0-9]{64}$
# md5 re /^([a-f\d]{32}|[A-F\d]{32})$/
# the first part of the this is for checking SHA256, and after the first "|" is for MD5
reExpression = re.compile('^[A-Fa-f0-9]{64}$|^([a-f\d]{32}|[A-F\d]{32})$')
# create the variables and set them to the string "Blank"
strInputHash = "Blank"
strInputKEY = "Blank"
# uses the askForUserInput func to get user input 
strInputHash, strInputKEY = askForUserInput()
# call the checkHash func to validate the hash that was given to make sure its either SHA256 or MD5
checkHash()
# Use the Virustotal API python package to send a request for the validated hash, with the API key that was given
with virustotal_python.Virustotal(strInputKEY) as vtotal:
	response = vtotal.request(f"files/{strInputHash}")
	# this block handles what happens if the response code is anything other than 200 
	responseCode = response.status_code # http response code
	if responseCode != 200:
		print(f"The API call failed with error code {responseCode}")
	else:
		print(f"The HTTP response code was {responseCode}") 
	# load the json into a dict
	jsonResponse = json.loads(response.text)
	# pull out the "malicious" variable from under data.attributes.last_analysis_stats and set totalPositives to it
	totalPositives = jsonResponse['data']['attributes']['last_analysis_stats']['malicious']
	# this block handles the output for whether or not the hash comes back clean
	if totalPositives <= 0:
		print(f"Clean, total number of postives was {totalPositives}")
	elif totalPositives <= 5:
		print(f"Possibly dirty, total number of postives was {totalPositives}")
	else:
		print(f"Dirty, total number of postives was {totalPositives}")
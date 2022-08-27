import virustotal_python
import argparse
import json
import sys
import re
# Made by Net_Code 5-6-2022
# A script to check a SHA256 or MD5 hash against Virustotals database
# Specs:
    # Write a Python or PowerShell script that accepts a file hash value (MD5 or SHA256) from the user and submits the hash to VirusTotal via an API call.
    # If VirusTotal finds more than 5 AV engines detected the file as malicious, output a message that informs the user and tells them how many AV engines detected the file.
    # If VirusTotal finds that less than 5 AV engines reported the file as malicious, output a message that indicates the file may be malicious and tells the user how many AV engines detected the file.
    # If no AV engines indicate the file is malicious, output a message that tells the user that the file is clean.

	# Validate user input to verify that the user has entered a valid hash.
    # Require the user to enter their API information (required to make API calls to VirusTotal).
    # Return an error message if an invalid hash is entered by the user or if they do not input their API information.
    # Output the API call's status code (200, 404, etc.)
    # Inform the user that the API call failed if status code is not 200. 

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
# use argparse to get the input hash and API key, or display the help menu
parser = argparse.ArgumentParser(description='A script to check a SHA256 or MD5 hash against Virustotals database')
parser.add_argument('--hash', dest='inputHash', type=str, help='The hash that you want to check(MD5 or SHA256)')
parser.add_argument('--key', dest='inputKey', type=str, help="Your API key for Virustotal (this should be SHA256)")
args = parser.parse_args()
# input validation
# sha256 re ^[A-Fa-f0-9]{64}$
# md5 re /^([a-f\d]{32}|[A-F\d]{32})$/
# the first part of the this is for checking SHA256, and after the first "|" is for MD5
reExpression = re.compile('^[A-Fa-f0-9]{64}$|^([a-f\d]{32}|[A-F\d]{32})$')
reSHA256Expression = re.compile('^[A-Fa-f0-9]{64}$')
# create the variables and set them to their corrasponding argparse arguments
strInputHash = ""
strInputKey = ""
strInputHash = args.inputHash
strInputKey = args.inputKey
# check to see if the the user gave an API key and if so, is it a valid SHA256 key, if not it exits out with an error
boolInputKeyValid = bool(reSHA256Expression.match(strInputKey))
if not boolInputKeyValid:
	print("Invalid Virustotal API key")
	sys.exit()
# call the checkHash func to validate the hash that was given to make sure its either SHA256 or MD5
checkHash()
# Use the Virustotal API python package to send a request for the validated hash, with the API key that was given
with virustotal_python.Virustotal(strInputKey) as vtotal:
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
		print("The file is clean, zero engines detected anything")
	elif totalPositives <= 5:
		print(f"Possibly dirty, total number of postives was {totalPositives}")
	else:
		print(f"Dirty, total number of postives was {totalPositives}")

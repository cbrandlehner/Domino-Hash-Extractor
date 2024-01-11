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
pip3 install request
pip3 install beautifulsoup4
```

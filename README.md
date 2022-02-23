# aad-sso-enum-brute-spray

Proof of Concept in Go from [Secureworks' research](https://www.secureworks.com/research/undetected-azure-active-directory-brute-force-attacks) on Azure Active Directory Brute-Force Attacks. Inspired by [@treebuilder's POC on PowerShell](https://github.com/treebuilder/aad-sso-enum-brute-spray).

## Description

This code is a proof of concept developed in go of the Azure Active Directory password brute-force vulnerability recently disclosed by Secureworks.

Currently it is only possible to perform a user enumeration or password spray attack without being blocked, because as explained in the Secureworks article Azure AD Smart Lockout prevents the brute force attack.

This repository has been inspired by @treebuilder's proof of concept. The purpose of doing it in go is to create a much faster tool in enumerating users during an Ethical Hacking.

## Installation 🛠

- Github repository option:
```
$ git clone https://github.com/MrTuxx/aad-sso-enum-brute-spray
$ cd aad-sso-enum-brute-spray/cmd; go build -o 'aad-sso-enum-brute-spray'
$ ./aad-sso-enum-brute-spray -h
```
<!---
- Go module option:
```
$ go get github.com/MrTuxx/aad-sso-enum-brute-spray
```
- Download a prebuilt binary from releases page. -->

## Usage 🚀

User enumeration, password spraying and brute force attacks can be performed.

- User enumeration: When it returns "bad password" or any value other than "no user" or "Invalid STS request" it indicates that the user exists. Also a return of "locked" may mean that the account is locked, or that Smart Lockout is temporarily preventing interaction with the account.

- Password spraying and brute force: "Correct credentials" message indicates that the correct username and password combination has been found.

### User enumeration and password spraying

`./aad-sso-enum-brute-spray -emails-file users.txt -password "password"`

### Brute force

`./aad-sso-enum-brute-spray -emails-file users.txt -passwords-file passwords.txt`

>NOTE: Microsoft's Smart Lockout feature will start falsely claiming that accounts are locked if you hit the API endpoint too quickly from the same IP address

### Paired attack

`./aad-sso-enum-brute-spray -paired users_passwords.txt`

>NOTE: The file users_passwords.txt contains the list of credentials in username:password format

## References :books:

- [Secureworks' research](https://www.secureworks.com/research/undetected-azure-active-directory-brute-force-attacks)
- [@treebuilder's POC on PowerShell](https://github.com/treebuilder/aad-sso-enum-brute-spray)
- [Arstechnica Article](https://arstechnica.com/information-technology/2021/09/new-azure-active-directory-password-brute-forcing-flaw-has-no-fix/)
- [Dr. Nestori Syynimaa's AADInternals project](https://raw.githubusercontent.com/Gerenios/AADInternals/eade775c6cd4f8ed16bd77602e1ea12a02fe265e/KillChain_utils.ps1)

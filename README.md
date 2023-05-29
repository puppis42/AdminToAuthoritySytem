# AdminToAuthoritySytem
Inject DLL to Winlogon for elevating process to NT Authority/System privileges after UAC Bypass with Slui file handler hijack

| Project Information |                                    |
|:------------------- |:---------------------------------- |
| Tested on           | Windows 7-10, x64 7601/19044/19045 |

* NOTE: Slui file handler hijack is not working on Windows 7 some versions, it works if you open it manually with admin privileges or you can use another uac bypass technique

## Proof Of Concept
![PoC](https://raw.githubusercontent.com/l0ngspace/AdminToAuthoritySytem/master/img/win10.gif)
![PoC](https://raw.githubusercontent.com/l0ngspace/AdminToAuthoritySytem/master/img/win7.gif)

# References

* https://github.com/bytecode77/slui-file-handler-hijack-privilege-escalation

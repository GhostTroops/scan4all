# ZeroLogon Exploit

A Python script that uses the Impacket library to exploit Zerologon (CVE-2020-1472).

It attempts to perform the Netlogon authentication bypass. The script will currently change the password to a null value. 
When a domain controller is patched, the detection script will give up after sending 2000 pairs of RPC calls and conclude the target is not vulnerable 
(with a false negative chance of 0.04%).

## Installation

The installation instructions are as follows:
    
    apt install python3-venv
    python3 -m venv impacketEnv
    source impacketEnv/bin/activate
    git clone https://github.com/SecureAuthCorp/impacket /opt/impacket
    cd /opt/impacket
    pip3 install .
    python3 setup.py install

Note that running `pip3 install impacket` should work as well, as long as the script is not broken by future Impacket 
versions.

## Running the script

The script targets can be used to target a DC or backup DC. It likely also works against a read-only DC, but this has 
not been tested. Given a domain controller named `EXAMPLE-DC` with IP address `1.2.3.4`, run the script as follows:

    ./zeroLogon-NullPass.py EXAMPLE-DC 1.2.3.4

The DC name should be its NetBIOS computer name. If this name is not correct, the script will likely fail with a 
`STATUS_INVALID_COMPUTER_NAME` error.

A Whitepaper on this vulnerability will be published here: https://www.secura.com/blog/zero-logon on Monday 14 sept. 

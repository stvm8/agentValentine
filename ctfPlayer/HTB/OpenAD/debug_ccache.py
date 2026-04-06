#!/usr/bin/env python3
import sys, os

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

from impacket.krb5.ccache import CCache

ccache_file = '/tmp/krb5cc_1600801117_Qxs0zd'
cc = CCache.loadFile(ccache_file)
print(f"credentials count: {len(cc.credentials)}")
for i, cred in enumerate(cc.credentials):
    print(f"\n--- cred[{i}] ---")
    print(f"  type(cred): {type(cred)}")
    print(f"  dir(cred): {[x for x in dir(cred) if not x.startswith('__')]}")
    try:
        print(f"  cred.server type: {type(cred.server)}")
        print(f"  cred.server dir: {[x for x in dir(cred.server) if not x.startswith('__')]}")
        if hasattr(cred.server, 'components'):
            for j, comp in enumerate(cred.server.components):
                print(f"  server.components[{j}]: type={type(comp)}, val={comp}")
        if hasattr(cred.server, 'realm'):
            print(f"  server.realm: {cred.server.realm}")
    except Exception as e:
        print(f"  server error: {e}")
    try:
        tgt = cred.toTGT()
        print(f"  toTGT() keys: {list(tgt.keys()) if isinstance(tgt, dict) else type(tgt)}")
    except Exception as e:
        print(f"  toTGT() error: {e}")
    try:
        print(f"  cred['key']: {cred['key']}")
    except Exception as e:
        print(f"  cred['key'] error: {e}")

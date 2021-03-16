#!/usr/bin/env python3

import sf

sf.sf_init()
sf.sf_include("forth/strongforth.zf")
resps = sf.sf_eval([b"prikey pubkey genkey pubkey b32tell", b"44 . "])
print(resps)

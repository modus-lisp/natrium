#!/usr/bin/env python3
"""Convert Wycheproof (C2SP/wycheproof) JSON test vectors into the dependency-free
Lisp s-expression data that test.lisp reads (natrium has no JSON parser and no
dependencies).  Fetch the sources first, e.g.:

  base=https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1
  for n in ed25519 x25519 chacha20_poly1305; do
    curl -sL "$base/${n}_test.json" -o /tmp/wp_${n}.json
  done
  python3 test/wycheproof-convert.py

Emits test/wycheproof-{ed25519,x25519,aead}.sexp.  Only the RFC-standard
96-bit-nonce ChaCha20-Poly1305 group is taken (natrium implements RFC 8439)."""
import json

def emit(path, rows):
    with open(path, 'w') as f:
        f.write(";;; Auto-generated from Wycheproof (C2SP/wycheproof testvectors_v1). Do not edit.\n(\n")
        for r in rows:
            f.write("(" + " ".join(r) + ")\n")
        f.write(")\n")

# ed25519: (tcId "pk" "msg" "sig" valid) — verify must accept valid, reject invalid
d = json.load(open('/tmp/wp_ed25519.json'))
rows = []
for g in d['testGroups']:
    pk = g['publicKey']['pk']
    for t in g['tests']:
        rows.append([str(t['tcId']), f'"{pk}"', f'"{t["msg"]}"', f'"{t["sig"]}"',
                     'T' if t['result'] == 'valid' else 'NIL'])
emit('test/wycheproof-ed25519.sexp', rows)

# x25519: (tcId "private" "public" "shared") — computed secret must match (valid+acceptable)
dx = json.load(open('/tmp/wp_x25519.json'))
rows = [[str(t['tcId']), f'"{t["private"]}"', f'"{t["public"]}"', f'"{t["shared"]}"']
        for t in dx['testGroups'][0]['tests']]
emit('test/wycheproof-x25519.sexp', rows)

# chacha20-poly1305: (tcId "key" "iv" "aad" "msg" "ct" "tag" valid), ivSize=96 only
da = json.load(open('/tmp/wp_chacha20_poly1305.json'))
rows = []
for g in da['testGroups']:
    if g['ivSize'] != 96:
        continue
    for t in g['tests']:
        rows.append([str(t['tcId']), f'"{t["key"]}"', f'"{t["iv"]}"', f'"{t["aad"]}"',
                     f'"{t["msg"]}"', f'"{t["ct"]}"', f'"{t["tag"]}"',
                     'T' if t['result'] == 'valid' else 'NIL'])
emit('test/wycheproof-aead.sexp', rows)

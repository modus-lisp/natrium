# natrium

**A dependency-free, portable Common Lisp crypto suite.** No FFI, no external
libraries — its own hashing, its own arithmetic. `natrium` implements the modern
constant-time primitive set (the [NaCl](https://nacl.cr.yp.to/) / libsodium
family): SHA-2 + HMAC, ChaCha20-Poly1305, X25519, Ed25519.

The name is the Latin for sodium — the *Na* in NaCl. The suite is chosen on
purpose: these primitives are **safe to implement without secret-dependent
tables or branches**, which is exactly what a hand-written, auditable
implementation needs. (AES-GCM, RSA, and the NIST P-curves — the
timing-footgun primitives — are deliberately *not* here.)

## Why it exists

It's the crypto floor for a **non-SBCL, multi-architecture Lisp OS**
([`modus`](https://github.com/modus-lisp)), where the usual answer (ironclad)
is a poor fit: ironclad's speed comes from SBCL VOPs that don't port, so on a
different compiler it runs as a slow portable fallback anyway. If we're going to
run portable, we'd rather run *our own* code — self-contained, readable, and
written in a constant-time discipline from the start.

The design mirrors [`secp256k1-fast`](https://github.com/ynniv): a **portable
reference is the default and the differential oracle**, and any per-architecture
fast path (widening multiply / add-with-carry, expressed as a small set of
compiler intrinsics, *not* whole-operation assembly) slots in behind it and is
checked against the reference. Correctness is arch-independent; speed lands
incrementally, per arch, without touching the crypto above it.

## Design principles

- **Self-contained.** Zero dependencies. `:depends-on ()`.
- **Constant-time for secret keys.** Secret-key paths use fixed-width limbs and
  no data-dependent branches or table indexing. Public-data paths (e.g.
  signature *verification*) may relax this.
- **Reference-as-oracle.** The portable definition is the source of truth; a
  native backend must match it byte-for-byte.
- **Vectors are the gate.** Every primitive is checked against its published
  test vectors (FIPS 180-4, RFC 4231/7748/8032/8439) plus Wycheproof edge cases
  before it ships.

## Status

**Done, each gated on published vectors:**

| primitive | vectors |
|---|---|
| SHA-256, SHA-512 | FIPS 180-4 |
| HMAC-SHA256, HMAC-SHA512 | RFC 4231 |
| HMAC-DRBG (CSPRNG) | NIST SP 800-90A / CAVP known-answer |
| ChaCha20 | RFC 8439 (block KAT + encryption) |
| Poly1305 | RFC 8439 |
| ChaCha20-Poly1305 AEAD | RFC 8439 (+ round-trip + tamper-reject) |

```lisp
(natrium:sha256 (natrium:ascii->bytes "abc"))   ; => 32-byte digest
(natrium:sha512 msg-bytes)                       ; => 64-byte digest
(natrium:hmac-sha256 key-bytes msg-bytes)        ; => 32-byte tag
(natrium:bytes= tag-a tag-b)                     ; constant-time compare

(natrium:random-bytes 32)                        ; CSPRNG (HMAC-DRBG over *os-entropy*)
(natrium:chacha20 key nonce data :counter 1)     ; RFC 8439 stream XOR
(natrium:chacha20-poly1305-encrypt key nonce pt aad)  ; => (values ciphertext tag)
(natrium:chacha20-poly1305-decrypt key nonce ct tag aad)  ; => plaintext, or NIL if forged
```

`*os-entropy*` is the sole OS-coupled seam — a one-argument function returning
raw entropy bytes. The default reads `/dev/urandom`; **modus rebinds it** to its
hardware entropy source, and everything above it (the HMAC-DRBG behind
`random-bytes`) is pure, portable computation.

**Roadmap:** the Curve25519 field (radix-2⁵¹) → X25519 → Ed25519 → the per-arch
intrinsic backend. The symmetric side is complete.

## Running the tests

```sh
./run-tests.sh          # or: sbcl ... (asdf:test-system "natrium")
```

MIT. Research / educational; **not audited** — do not protect real keys with
this without an independent side-channel review.

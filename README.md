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
| HKDF-SHA256, HKDF-SHA512 | RFC 5869 |
| HMAC-DRBG (CSPRNG) | NIST SP 800-90A / CAVP known-answer |
| ChaCha20 | RFC 8439 (block KAT + encryption) |
| Poly1305 | RFC 8439 |
| ChaCha20-Poly1305 AEAD | RFC 8439 (+ round-trip + tamper-reject) |
| X25519 | RFC 7748 (§5.2 incl. 1000×, §6.1 DH) |
| Ed25519 | RFC 8032 §7.1 (+ forgery/wrong-msg reject) |

```lisp
(natrium:sha256 (natrium:ascii->bytes "abc"))   ; => 32-byte digest
(natrium:sha512 msg-bytes)                       ; => 64-byte digest
(natrium:hmac-sha256 key-bytes msg-bytes)        ; => 32-byte tag
(natrium:bytes= tag-a tag-b)                     ; constant-time compare

(natrium:random-bytes 32)                        ; CSPRNG (HMAC-DRBG over *os-entropy*)
(natrium:chacha20 key nonce data :counter 1)     ; RFC 8439 stream XOR
(natrium:chacha20-poly1305-encrypt key nonce pt aad)  ; => (values ciphertext tag)
(natrium:chacha20-poly1305-decrypt key nonce ct tag aad)  ; => plaintext, or NIL if forged
(natrium:x25519-keypair)                         ; => (values private public)
(natrium:x25519 my-private their-public)         ; => 32-byte shared secret
(natrium:ed25519-keypair)                        ; => (values secret public)
(natrium:ed25519-sign secret message)            ; => 64-byte signature (deterministic)
(natrium:ed25519-verify public message sig)      ; => t / nil
(natrium:hkdf-sha256 salt shared-secret info 64) ; => 64 bytes of session keys
```

`*os-entropy*` is the sole OS-coupled seam — a one-argument function returning
raw entropy bytes. The default reads `/dev/urandom`; **modus rebinds it** to its
hardware entropy source, and everything above it (the HMAC-DRBG behind
`random-bytes`) is pure, portable computation.

**The NaCl primitive set is complete** — hashing, AEAD, key agreement, and
signatures, all vector-gated.

### Constant-time

Every secret-key path is implemented in a constant-time discipline:

- **`fe25519`** — GF(2²⁵⁵−19) in radix-2⁵¹ limbs; add/sub/mul/sq/invert/cmov
  with a fixed operation sequence and no data-dependent branch, index, or count.
- **X25519** — the Montgomery ladder over `fe25519`, fixed 255 iterations,
  branch-free `cswap`.
- **Ed25519** — point arithmetic over `fe25519`; scalar multiplication is
  double-and-add-*always* with a branch-free point `cmov`; scalar reduction
  mod L is Barrett with fixed-size operands.
- **Poly1305** — 26-bit-limb accumulator, fixed 5×5-limb multiply per block.

These are the *public* entry points; the original big-integer implementations
are kept in-tree as `*-reference` and are the **differential oracle** — the
constant-time code is checked against them on tens of thousands of random inputs
(and both pass the RFC/NIST vectors).

### Edge-case gating (Wycheproof)

Beyond the RFC/NIST happy-path vectors, the suite runs the
[Wycheproof](https://github.com/C2SP/wycheproof) adversarial vectors — **984**
of them: Ed25519 verify (signature malleability, small-order `R`, non-canonical
keys), X25519 (low-order and non-canonical public points → zero shared secret),
and ChaCha20-Poly1305 (tag forgery, truncation). These caught a real freeze bug
in the constant-time field (a non-canonical zero from a low-order point
serialized as `19`) that the RFC vectors and random differential tests both
missed — the reason edge-case gating earns its place.

The discipline is *structural* constant-time: fixed control and data flow. The
portable limb multiply is still CL `*`; the one remaining step is a per-arch
backend that lowers the limb multiply to a widening-multiply / add-with-carry
intrinsic (with the pure-Lisp fallback these references provide), closing the
last instruction-level gap on hardware that has data-dependent multiply timing.

**Roadmap:** that intrinsic backend, and the pure-CL SSH/git transport this
suite was built to unblock.

## Running the tests

```sh
./run-tests.sh          # or: sbcl ... (asdf:test-system "natrium")
```

MIT. Research / educational; **not audited** — do not protect real keys with
this without an independent side-channel review.

;;;; packages.lisp — natrium

(defpackage #:natrium
  (:use #:cl)
  (:documentation
   "natrium — a dependency-free, portable Common Lisp implementation of the modern
    constant-time crypto suite (the NaCl/libsodium primitive set): SHA-2 + HMAC,
    ChaCha20-Poly1305, X25519, Ed25519.  No FFI, no external libraries.  Chosen
    because these primitives are safe to implement without secret-dependent tables
    or branches; secret-key paths are written in a constant-time discipline and
    gated on RFC/NIST/Wycheproof vectors.

    The full primitive set is implemented and vector-gated: SHA-256/512 + HMAC,
    HMAC-DRBG (CSPRNG), ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, X25519, and
    Ed25519.  Field/scalar arithmetic is currently a portable big-integer
    reference; the constant-time limb backend is the remaining hardening step.")
  (:export
   ;; hashing
   #:sha256 #:sha384 #:sha512
   #:hmac #:hmac-sha256 #:hmac-sha384 #:hmac-sha512
   ;; key derivation
   #:hkdf #:hkdf-extract #:hkdf-expand #:hkdf-sha256 #:hkdf-sha384 #:hkdf-sha512
   ;; entropy + CSPRNG
   #:*os-entropy* #:os-entropy #:random-bytes
   #:drbg-instantiate #:drbg-generate #:drbg-reseed
   ;; stream cipher + AEAD
   #:chacha20 #:chacha20-block
   #:poly1305-mac #:poly1305-key-gen
   #:chacha20-poly1305-encrypt #:chacha20-poly1305-decrypt
   ;; X25519 key agreement
   #:x25519 #:x25519-base #:x25519-keypair
   ;; Ed25519 signatures
   #:ed25519-public-key #:ed25519-sign #:ed25519-verify #:ed25519-keypair
   ;; small helpers
   #:ascii->bytes #:make-u8v #:u8cat #:bytes= #:u8v))

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

    Phase 0 (this build): the hashing floor — SHA-256, SHA-512, HMAC.")
  (:export
   ;; hashing
   #:sha256 #:sha512
   #:hmac #:hmac-sha256 #:hmac-sha512
   ;; entropy + CSPRNG
   #:*os-entropy* #:os-entropy #:random-bytes
   #:drbg-instantiate #:drbg-generate #:drbg-reseed
   ;; stream cipher
   #:chacha20 #:chacha20-block
   ;; small helpers
   #:ascii->bytes #:make-u8v #:u8cat #:bytes= #:u8v))

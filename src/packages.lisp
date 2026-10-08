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

    The full primitive set is implemented and vector-gated: SHA-256/384/512 +
    HMAC, HKDF, HMAC-DRBG (CSPRNG), ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD,
    X25519, and Ed25519.  The public curve/field paths ARE the constant-time
    limb backend (fe25519 + the constant-time X25519/Ed25519/Poly1305); each
    keeps its big-integer implementation in-tree as a *-reference differential
    oracle.  The remaining hardening step is a per-architecture intrinsic backend
    (widening multiply / add-with-carry) that lowers the portable limb multiply.")
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
   #:chacha20-original #:chacha20-original-block
   #:poly1305-mac #:poly1305-key-gen
   #:chacha20-poly1305-encrypt #:chacha20-poly1305-decrypt
   ;; X25519 key agreement
   #:x25519 #:x25519-base #:x25519-keypair
   ;; Ed25519 signatures
   #:ed25519-public-key #:ed25519-sign #:ed25519-verify #:ed25519-keypair
   ;; small helpers
   #:ascii->bytes #:make-u8v #:u8cat #:bytes= #:u8v))

(defpackage #:natrium.noise
  (:use #:cl)
  (:local-nicknames (#:n #:natrium))
  (:documentation
   "The Noise IK and XK handshakes and transport, generic over the DH group.  The curve
    enters only through a NOISE-SUITE (key generation, encoding, DH, pre-message).
    See src/noise.lisp for the authority and the FIPS deviations it implements.")
  (:export
   #:noise-suite #:make-noise-suite #:noise-suite-name #:noise-suite-ik-name
   #:noise-suite-xk-name #:noise-suite-pubkey-size
   #:noise-error #:noise-error-reason
   #:ik-msg1-size #:ik-msg2-size #:xk-msg1-size #:xk-msg2-size #:xk-msg3-size
   #:make-ik-initiator #:make-ik-responder
   #:ik-write-message-1 #:ik-read-message-1
   #:ik-write-message-2 #:ik-read-message-2
   #:make-xk-initiator #:make-xk-responder
   #:xk-write-message-1 #:xk-read-message-1
   #:xk-write-message-2 #:xk-read-message-2
   #:xk-write-message-3 #:xk-read-message-3
   #:handshake-hash #:hs-remote-epoch #:hs-remote-static #:hs-progress
   #:ik-try-read-message-2 #:xk-try-read-message-2 #:xk-try-read-message-3
   #:handshake-into-session #:session-encrypt #:session-decrypt
   #:session-decrypt-with-counter #:session-handshake-hash
   #:session-current-send-counter #:session-encrypt-with-aad
   #:session-check-replay #:session-decrypt-with-replay-check
   #:session-reset-replay-window #:session-replay
   ;; replay window (replay.rs)
   #:+replay-window-size+ #:replay-window #:make-replay-window
   #:replay-window-highest #:replay-check #:replay-accept #:replay-reset))

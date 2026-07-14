;;;; natrium.asd

(defsystem "natrium"
  :description "A dependency-free, portable Common Lisp implementation of the
                modern constant-time crypto suite (the NaCl/libsodium primitive
                set): SHA-2 + HMAC, ChaCha20-Poly1305, X25519, Ed25519.  No FFI,
                no external libraries.  Secret-key paths use a constant-time
                discipline; hot arithmetic is factored so a native intrinsic
                backend (widening multiply / add-with-carry) can slot in behind
                the portable reference, which stays as the differential oracle.
                Phase 0: the hashing floor (SHA-256, SHA-512, HMAC)."
  :version "0.1.0"
  :author "ynniv"
  :license "MIT"
  :depends-on ()
  :serial t
  :components
  ((:module "src"
    :serial t
    :components ((:file "packages")
                 (:file "util")
                 (:file "sha256")
                 (:file "sha512")
                 (:file "hmac")
                 (:file "hkdf")
                 (:file "entropy")
                 (:file "drbg")
                 (:file "chacha20")
                 (:file "poly1305")
                 (:file "aead")
                 (:file "x25519")
                 (:file "fe25519")
                 (:file "x25519-ct")
                 (:file "ed25519")
                 (:file "ed25519-ct"))))
  :in-order-to ((test-op (test-op "natrium/test"))))

(defsystem "natrium/test"
  :description "Correctness tests against published vectors: FIPS 180-4 SHA-256 /
                SHA-512 and RFC 4231 HMAC-SHA256 / HMAC-SHA512."
  :depends-on ("natrium")
  :serial t
  :components ((:module "test" :components ((:file "test"))))
  :perform (test-op (o c) (uiop:symbol-call '#:natrium.test '#:run-all)))

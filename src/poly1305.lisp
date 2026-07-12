;;;; poly1305.lisp — Poly1305 one-time authenticator (RFC 8439 2.5).
;;;;
;;;; This is the portable big-integer reference: the accumulator is a CL integer
;;;; reduced mod 2^130-5 each block.  It's exact and RFC-vector-gated, and serves
;;;; as the differential oracle for a future constant-time 26-bit-limb backend.
;;;; NOTE: big-integer arithmetic is not constant-time; since (r,s) is secret,
;;;; the constant-time limb form is the eventual target for the hardened build.
;;;; Poly1305 is a ONE-TIME MAC — never reuse a key across two messages.

(in-package #:natrium)

(defun poly1305-mac (key msg)
  "Poly1305 tag of MSG under the 32-byte one-time KEY → fresh 16-byte tag."
  (declare (type u8v key msg))
  (let* ((r (logand (le->uint key 0 16) #x0ffffffc0ffffffc0ffffffc0fffffff)) ; clamp r
         (s (le->uint key 16 16))
         (p (- (ash 1 130) 5))
         (a 0)
         (len (length msg)))
    (loop for i from 0 below len by 16 do
      (let* ((blen (min 16 (- len i)))
             (n (logior (le->uint msg i blen) (ash 1 (* 8 blen))))) ; append the high 1 bit
        (setf a (mod (* (+ a n) r) p))))
    (uint->le (logand (+ a s) (1- (ash 1 128))) 16)))               ; + s mod 2^128

(defun poly1305-key-gen (key nonce)
  "RFC 8439 2.6: derive a Poly1305 one-time key = first 32 bytes of the ChaCha20
   keystream block at counter 0.  KEY 32 bytes, NONCE 12 bytes."
  (subseq (chacha20-block key 0 nonce) 0 32))

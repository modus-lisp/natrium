;;;; aead.lisp — ChaCha20-Poly1305 AEAD (RFC 8439 2.8).
;;;;
;;;; The first *composed* primitive: ChaCha20 for confidentiality, Poly1305 for
;;;; integrity over (aad ‖ ciphertext ‖ lengths).  This is what modern TLS/SSH
;;;; default to.  Decrypt verifies the tag with a constant-time compare BEFORE
;;;; returning any plaintext — a bad tag yields NIL, never partial output.

(in-package #:natrium)

(declaim (inline %pad16))
(defun %pad16 (n)
  "Bytes of zero padding to round N up to a 16-byte boundary (0 if aligned)."
  (mod (- 16 (mod n 16)) 16))

(defun %poly1305-mac-data (aad ciphertext)
  "RFC 8439 2.8: aad ‖ pad16(aad) ‖ ciphertext ‖ pad16(ciphertext) ‖
   le64(len aad) ‖ le64(len ciphertext)."
  (u8cat aad (make-u8v (%pad16 (length aad)))
         ciphertext (make-u8v (%pad16 (length ciphertext)))
         (uint->le (length aad) 8)
         (uint->le (length ciphertext) 8)))

(defun chacha20-poly1305-encrypt (key nonce plaintext &optional (aad (make-u8v 0)))
  "AEAD seal (RFC 8439 2.8).  KEY 32 bytes, NONCE 12 bytes, PLAINTEXT and AAD
   byte vectors.  Returns (values CIPHERTEXT TAG16)."
  (declare (type u8v key nonce plaintext aad))
  (let* ((otk (poly1305-key-gen key nonce))
         (ct (chacha20 key nonce plaintext :counter 1))
         (tag (poly1305-mac otk (%poly1305-mac-data aad ct))))
    (values ct tag)))

(defun chacha20-poly1305-decrypt (key nonce ciphertext tag &optional (aad (make-u8v 0)))
  "AEAD open (RFC 8439 2.8).  Verifies TAG (16 bytes) with a constant-time
   compare; returns the decrypted PLAINTEXT on success, or NIL if authentication
   fails.  No plaintext is produced for a bad tag."
  (declare (type u8v key nonce ciphertext tag aad))
  (let* ((otk (poly1305-key-gen key nonce))
         (expected (poly1305-mac otk (%poly1305-mac-data aad ciphertext))))
    (when (bytes= expected tag)
      (chacha20 key nonce ciphertext :counter 1))))

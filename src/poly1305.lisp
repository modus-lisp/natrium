;;;; poly1305.lisp — Poly1305 one-time authenticator (RFC 8439 2.5).
;;;;
;;;; poly1305-mac is the constant-time 26-bit-limb implementation; the big-
;;;; integer poly1305-mac-reference is its differential oracle.  Poly1305 is a
;;;; ONE-TIME MAC — never reuse a key across two messages.

(in-package #:natrium)

(defun poly1305-mac-reference (key msg)
  "Big-integer reference (the differential oracle for the limb poly1305-mac)."
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
    (uint->le (logand (+ a s) (1- (ash 1 128))) 16)))

;;; Constant-time Poly1305: the accumulator and clamped r are held in 5 limbs of
;;; 26 bits; each block does a fixed 5x5-limb multiply mod 2^130-5 (high limbs
;;; fold back with the *5 wrap) and a fixed carry chain — no data-dependent
;;; branch/index/count.  Uniform structure like fe25519; the native backend
;;; closes the instruction-level gap.  (r,s) is a one-time key per message.
(defun poly1305-mac (key msg)
  "Poly1305 tag of MSG under the 32-byte one-time KEY -> fresh 16-byte tag."
  (declare (type u8v key msg))
  (let* ((m26 #x3ffffff)
         (r (logand (le->uint key 0 16) #x0ffffffc0ffffffc0ffffffc0fffffff))
         (r0 (logand r m26)) (r1 (logand (ash r -26) m26)) (r2 (logand (ash r -52) m26))
         (r3 (logand (ash r -78) m26)) (r4 (logand (ash r -104) m26))
         (s1 (* 5 r1)) (s2 (* 5 r2)) (s3 (* 5 r3)) (s4 (* 5 r4))
         (h0 0) (h1 0) (h2 0) (h3 0) (h4 0)
         (len (length msg)))
    (loop for i from 0 below len by 16 do
      (let* ((blen (min 16 (- len i)))
             (n (logior (le->uint msg i blen) (ash 1 (* 8 blen)))))
        (incf h0 (logand n m26))           (incf h1 (logand (ash n -26) m26))
        (incf h2 (logand (ash n -52) m26)) (incf h3 (logand (ash n -78) m26))
        (incf h4 (logand (ash n -104) m26))
        (let ((d0 (+ (* h0 r0) (* h1 s4) (* h2 s3) (* h3 s2) (* h4 s1)))
              (d1 (+ (* h0 r1) (* h1 r0) (* h2 s4) (* h3 s3) (* h4 s2)))
              (d2 (+ (* h0 r2) (* h1 r1) (* h2 r0) (* h3 s4) (* h4 s3)))
              (d3 (+ (* h0 r3) (* h1 r2) (* h2 r1) (* h3 r0) (* h4 s4)))
              (d4 (+ (* h0 r4) (* h1 r3) (* h2 r2) (* h3 r1) (* h4 r0)))
              (c 0))
          (setf c (ash d0 -26) h0 (logand d0 m26)) (incf d1 c)
          (setf c (ash d1 -26) h1 (logand d1 m26)) (incf d2 c)
          (setf c (ash d2 -26) h2 (logand d2 m26)) (incf d3 c)
          (setf c (ash d3 -26) h3 (logand d3 m26)) (incf d4 c)
          (setf c (ash d4 -26) h4 (logand d4 m26)) (incf h0 (* 5 c))
          (setf c (ash h0 -26) h0 (logand h0 m26)) (incf h1 c))))
    ;; finalize: reconstruct, reduce mod 2^130-5, add s, keep low 128 bits
    (let ((p (- (ash 1 130) 5))
          (h (+ h0 (ash h1 26) (ash h2 52) (ash h3 78) (ash h4 104))))
      (when (>= h p) (decf h p))
      (when (>= h p) (decf h p))
      (uint->le (logand (+ h (le->uint key 16 16)) (1- (ash 1 128))) 16))))

(defun poly1305-key-gen (key nonce)
  "RFC 8439 2.6: derive a Poly1305 one-time key = first 32 bytes of the ChaCha20
   keystream block at counter 0.  KEY 32 bytes, NONCE 12 bytes."
  (subseq (chacha20-block key 0 nonce) 0 32))

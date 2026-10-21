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
         ;; Clamped r as five 26-bit limbs straight from the key bytes (donna):
         ;; the masks are the RFC 8439 clamp applied limb by limb.
         (r0 (logand (u32le key 0) #x3ffffff))
         (r1 (logand (ash (u32le key 3) -2) #x3ffff03))
         (r2 (logand (ash (u32le key 6) -4) #x3ffc0ff))
         (r3 (logand (ash (u32le key 9) -6) #x3f03fff))
         (r4 (logand (ash (u32le key 12) -8) #x00fffff))
         (s1 (* 5 r1)) (s2 (* 5 r2)) (s3 (* 5 r3)) (s4 (* 5 r4))
         (h0 0) (h1 0) (h2 0) (h3 0) (h4 0)
         (pad (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (len (length msg)))
    (loop for i from 0 below len by 16 do
      ;; Limbs straight from the bytes (poly1305-donna): four overlapping
      ;; little-endian u32 reads, shifted and masked -- all fixnum.  Decoding
      ;; the block into one 128-bit integer first made every block a bignum
      ;; (plus a 2^128 pad bit), which dominated the MAC on any Lisp whose
      ;; bignums are slow.  A short final block is copied into a zeroed
      ;; 16-byte buffer with the RFC 8439 0x01 pad byte after it, and then
      ;; carries no 2^128 bit, exactly as donna does.
      (let* ((blen (min 16 (- len i)))
             (b (if (= blen 16) msg pad))
             (o (if (= blen 16) i 0))
             (hibit (if (= blen 16) #x1000000 0)))
        (when (< blen 16)
          (fill pad 0)
          (replace pad msg :start2 i :end2 (+ i blen))
          (setf (aref pad blen) 1))
        (incf h0 (logand (u32le b o) m26))
        (incf h1 (logand (ash (u32le b (+ o 3)) -2) m26))
        (incf h2 (logand (ash (u32le b (+ o 6)) -4) m26))
        (incf h3 (ash (u32le b (+ o 9)) -6))
        (incf h4 (logior (ash (u32le b (+ o 12)) -8) hibit))
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
    ;; Finalize (donna), all in fixnum limbs: carry fully, reduce mod 2^130-5
    ;; by computing h - p and choosing it with a mask (no branch on the
    ;; secret accumulator), add s mod 2^128, write little-endian.
    (let ((c 0))
      (setf c (ash h1 -26) h1 (logand h1 m26)) (incf h2 c)
      (setf c (ash h2 -26) h2 (logand h2 m26)) (incf h3 c)
      (setf c (ash h3 -26) h3 (logand h3 m26)) (incf h4 c)
      (setf c (ash h4 -26) h4 (logand h4 m26)) (incf h0 (* 5 c))
      (setf c (ash h0 -26) h0 (logand h0 m26)) (incf h1 c)
      (let* ((g0 (+ h0 5))         (c0 (ash g0 -26)) (g0 (logand g0 m26))
             (g1 (+ h1 c0))        (c1 (ash g1 -26)) (g1 (logand g1 m26))
             (g2 (+ h2 c1))        (c2 (ash g2 -26)) (g2 (logand g2 m26))
             (g3 (+ h3 c2))        (c3 (ash g3 -26)) (g3 (logand g3 m26))
             (g4 (- (+ h4 c3) (ash 1 26)))
             ;; -1 when h < p (keep h), 0 when h >= p (take g = h - p).
             (keep (ash g4 -30))
             (take (lognot keep)))
        (flet ((pick (h g) (logior (logand h keep) (logand g take))))
          (setf h0 (pick h0 g0) h1 (pick h1 g1) h2 (pick h2 g2)
                h3 (pick h3 g3) h4 (pick h4 (logand g4 m26)))))
      (let* ((m32 #xffffffff)
             (w0 (logand (logior h0 (ash h1 26)) m32))
             (w1 (logand (logior (ash h1 -6) (ash h2 20)) m32))
             (w2 (logand (logior (ash h2 -12) (ash h3 14)) m32))
             (w3 (logand (logior (ash h3 -18) (ash h4 8)) m32))
             (f 0)
             (out (make-u8v 16)))
        (setf f (+ w0 (u32le key 16))              w0 (logand f m32)
              f (+ w1 (u32le key 20) (ash f -32))  w1 (logand f m32)
              f (+ w2 (u32le key 24) (ash f -32))  w2 (logand f m32)
              f (+ w3 (u32le key 28) (ash f -32))  w3 (logand f m32))
        (loop for w in (list w0 w1 w2 w3) for o from 0 by 4 do
          (setf (aref out o)       (logand #xff w)
                (aref out (+ o 1)) (logand #xff (ash w -8))
                (aref out (+ o 2)) (logand #xff (ash w -16))
                (aref out (+ o 3)) (logand #xff (ash w -24))))
        out))))

(defun poly1305-key-gen (key nonce)
  "RFC 8439 2.6: derive a Poly1305 one-time key = first 32 bytes of the ChaCha20
   keystream block at counter 0.  KEY 32 bytes, NONCE 12 bytes."
  (subseq (chacha20-block key 0 nonce) 0 32))

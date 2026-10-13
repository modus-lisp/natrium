;;;; sha512.lisp — SHA-512 (FIPS 180-4), pure Common Lisp, no dependencies.
;;;;
;;;; 64-bit words, 80 rounds, 128-byte blocks, 128-bit big-endian length field,
;;;; 64-byte big-endian digest.  Needed by Ed25519 (RFC 8032) and by
;;;; HMAC-SHA512 / PBKDF2.  Same shape as sha256.lisp with 64-bit lanes.

(in-package #:natrium)

(deftype u64 () '(unsigned-byte 64))

(declaim (type (simple-array u64 (80)) +sha512-k+))
(defparameter +sha512-k+
  (make-array 80 :element-type 'u64 :initial-contents
   '(#x428a2f98d728ae22 #x7137449123ef65cd #xb5c0fbcfec4d3b2f #xe9b5dba58189dbbc
     #x3956c25bf348b538 #x59f111f1b605d019 #x923f82a4af194f9b #xab1c5ed5da6d8118
     #xd807aa98a3030242 #x12835b0145706fbe #x243185be4ee4b28c #x550c7dc3d5ffb4e2
     #x72be5d74f27b896f #x80deb1fe3b1696b1 #x9bdc06a725c71235 #xc19bf174cf692694
     #xe49b69c19ef14ad2 #xefbe4786384f25e3 #x0fc19dc68b8cd5b5 #x240ca1cc77ac9c65
     #x2de92c6f592b0275 #x4a7484aa6ea6e483 #x5cb0a9dcbd41fbd4 #x76f988da831153b5
     #x983e5152ee66dfab #xa831c66d2db43210 #xb00327c898fb213f #xbf597fc7beef0ee4
     #xc6e00bf33da88fc2 #xd5a79147930aa725 #x06ca6351e003826f #x142929670a0e6e70
     #x27b70a8546d22ffc #x2e1b21385c26c926 #x4d2c6dfc5ac42aed #x53380d139d95b3df
     #x650a73548baf63de #x766a0abb3c77b2a8 #x81c2c92e47edaee6 #x92722c851482353b
     #xa2bfe8a14cf10364 #xa81a664bbc423001 #xc24b8b70d0f89791 #xc76c51a30654be30
     #xd192e819d6ef5218 #xd69906245565a910 #xf40e35855771202a #x106aa07032bbd1b8
     #x19a4c116b8d2d0c8 #x1e376c085141ab53 #x2748774cdf8eeb99 #x34b0bcb5e19b48a8
     #x391c0cb3c5c95a63 #x4ed8aa4ae3418acb #x5b9cca4f7763e373 #x682e6ff3d6b2b8a3
     #x748f82ee5defb2fc #x78a5636f43172f60 #x84c87814a1f0ab72 #x8cc702081a6439ec
     #x90befffa23631e28 #xa4506cebde82bde9 #xbef9a3f7b2c67915 #xc67178f2e372532b
     #xca273eceea26619c #xd186b8c721c0c207 #xeada7dd6cde0eb1e #xf57d4f7fee6ed178
     #x06f067aa72176fba #x0a637dc5a2c898a6 #x113f9804bef90dae #x1b710b35131c471b
     #x28db77f523047d84 #x32caab7b40c72493 #x3c9ebe0a15c9bebc #x431d67c49c100d4c
     #x4cc5d4becb3e42b6 #x597f299cfc657e2a #x5fcb6fab3ad6faec #x6c44198c4a475817)))

(declaim (inline ror64 shr64))
(defun ror64 (x n) (declare (type u64 x) (type (integer 0 63) n))
  (logand #xffffffffffffffff (logior (ash x (- n)) (ash x (- 64 n)))))
(defun shr64 (x n) (declare (type u64 x)) (ash x (- n)))

(declaim (type (simple-array u64 (8)) +sha512-init+ +sha384-init+))
(defparameter +sha512-init+
  (make-array 8 :element-type 'u64 :initial-contents
    '(#x6a09e667f3bcc908 #xbb67ae8584caa73b #x3c6ef372fe94f82b #xa54ff53a5f1d36f1
      #x510e527fade682d1 #x9b05688c2b3e6c1f #x1f83d9abfb41bd6b #x5be0cd19137e2179)))
(defparameter +sha384-init+
  (make-array 8 :element-type 'u64 :initial-contents
    '(#xcbbb9d5dc1059ed8 #x629a292a367cd507 #x9159015a3070dd17 #x152fecd8f70e5939
      #x67332667ffc00b31 #x8eb44a8768581511 #xdb0c2e0d64f98fa7 #x47b5481dbefa4fa4)))

(defun %sha512-digest (msg init nbytes)
  "Run the SHA-512 compression over MSG from the 8-word INIT; return the leading
   NBYTES of the big-endian hash (64 for SHA-512, 48 for SHA-384)."
  (let* ((ml (length msg))
         (bitlen (* ml 8))
         ;; pad to a multiple of 128; need +1 (0x80) +16 (128-bit length)
         (padlen (let ((r (mod (+ ml 17) 128))) (if (zerop r) (+ ml 17) (+ ml 17 (- 128 r)))))
         (m (make-array padlen :element-type '(unsigned-byte 8) :initial-element 0))
         (h (make-array 8 :element-type 'u64))
         (w (make-array 80 :element-type 'u64 :initial-element 0)))
    (replace h init)
    (replace m msg)
    (setf (aref m ml) #x80)
    (dotimes (i 16)                                 ; 128-bit big-endian bit length
      (setf (aref m (- padlen 1 i)) (logand #xff (ash bitlen (* -8 i)))))
    (loop for base from 0 below padlen by 128 do
      (dotimes (i 16)
        (let ((j (+ base (* i 8))) (v 0))
          (declare (type u64 v))
          (dotimes (b 8) (setf v (logior (ash v 8) (aref m (+ j b)))))
          (setf (aref w i) v)))
      (loop for i from 16 below 80 do
        (let ((s0 (logxor (ror64 (aref w (- i 15)) 1) (ror64 (aref w (- i 15)) 8) (shr64 (aref w (- i 15)) 7)))
              (s1 (logxor (ror64 (aref w (- i 2)) 19) (ror64 (aref w (- i 2)) 61) (shr64 (aref w (- i 2)) 6))))
          (setf (aref w i) (logand #xffffffffffffffff (+ (aref w (- i 16)) s0 (aref w (- i 7)) s1)))))
      (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
            (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
        (dotimes (i 80)
          (let* ((bs1 (logxor (ror64 e 14) (ror64 e 18) (ror64 e 41)))
                 (ch (logxor (logand e f) (logand (logxor e #xffffffffffffffff) g)))
                 (t1 (logand #xffffffffffffffff (+ hh bs1 ch (aref +sha512-k+ i) (aref w i))))
                 (bs0 (logxor (ror64 a 28) (ror64 a 34) (ror64 a 39)))
                 (maj (logxor (logand a b) (logand a c) (logand b c)))
                 (t2 (logand #xffffffffffffffff (+ bs0 maj))))
            (setf hh g  g f  f e  e (logand #xffffffffffffffff (+ d t1))
                  d c  c b  b a  a (logand #xffffffffffffffff (+ t1 t2)))))
        (setf (aref h 0) (logand #xffffffffffffffff (+ (aref h 0) a))
              (aref h 1) (logand #xffffffffffffffff (+ (aref h 1) b))
              (aref h 2) (logand #xffffffffffffffff (+ (aref h 2) c))
              (aref h 3) (logand #xffffffffffffffff (+ (aref h 3) d))
              (aref h 4) (logand #xffffffffffffffff (+ (aref h 4) e))
              (aref h 5) (logand #xffffffffffffffff (+ (aref h 5) f))
              (aref h 6) (logand #xffffffffffffffff (+ (aref h 6) g))
              (aref h 7) (logand #xffffffffffffffff (+ (aref h 7) hh)))))
    (let ((out (make-array nbytes :element-type '(unsigned-byte 8))))
      (dotimes (i (ceiling nbytes 8))
        (let ((v (aref h i)) (o (* i 8)))
          (dotimes (b 8)
            (when (< (+ o b) nbytes)
              (setf (aref out (+ o b)) (logand #xff (ash v (* -8 (- 7 b)))))))))
      out)))

;;; --- modus: 64-bit words as PAIRS of 32-bit halves ----------------------
;;; A u64 is not a fixnum on modus (fixnums are 63-bit), so the portable code
;;; above makes every message word, state word and round temporary a bignum:
;;; 43% of an Ed25519 signature was SHA-512's bignum shifts and limb lists.
;;; Here each word is two u32 fixnums (HI, LO) -- the classic 32-bit-platform
;;; SHA-512.  Every shift is a constant computed at macroexpansion, and the
;;; low bits are masked BEFORE shifting left, so no intermediate exceeds 2^32
;;; except the carry sums (< 6 * 2^32).  The portable definition above stays
;;; the oracle; this one replaces it on modus only (last definition wins).
#+modus
(progn
(defmacro %s5-hi-ror (h l n)
  "HI half of the 64-bit rotate-right of (H,L) by constant N, 0 < N < 64."
  (if (< n 32)
      `(logior (ash ,h ,(- n)) (ash (logand ,l ,(1- (ash 1 n))) ,(- 32 n)))
      (let ((m (- n 32)))
        (if (= m 0) l
            `(logior (ash ,l ,(- m)) (ash (logand ,h ,(1- (ash 1 m))) ,(- 32 m)))))))
(defmacro %s5-lo-ror (h l n)
  "LO half of the 64-bit rotate-right of (H,L) by constant N."
  `(%s5-hi-ror ,l ,h ,n))
(defmacro %s5-hi-shr (h l n) (declare (ignore l))
  "HI half of the 64-bit logical shift-right of (H,L) by constant N < 32."
  `(ash ,h ,(- n)))
(defmacro %s5-lo-shr (h l n)
  "LO half of the 64-bit logical shift-right of (H,L) by constant N < 32."
  `(logior (ash ,l ,(- n)) (ash (logand ,h ,(1- (ash 1 n))) ,(- 32 n))))

(defun %s5-split (v)
  "A u64 V as (values HI LO), 32 bits each."
  (values (ldb (byte 32 32) v) (ldb (byte 32 0) v)))

(defvar *%s5-k* nil)
(defun %s5-k ()
  "+SHA512-K+ split once into a 160-slot (hi lo hi lo ...) vector."
  (or *%s5-k*
      (let ((v (make-array 160 :initial-element 0)))
        (dotimes (i 80)
          (multiple-value-bind (hi lo) (%s5-split (aref +sha512-k+ i))
            (setf (aref v (* 2 i)) hi (aref v (1+ (* 2 i))) lo)))
        (setq *%s5-k* v))))

(defun %sha512-digest (msg init nbytes)
  "SHA-512 / SHA-384 compression on 32-bit halves (modus)."
  (let* ((ml (length msg))
         (bitlen (* ml 8))
         (padlen (let ((r (mod (+ ml 17) 128))) (if (zerop r) (+ ml 17) (+ ml 17 (- 128 r)))))
         (m (make-array padlen :element-type '(unsigned-byte 8) :initial-element 0))
         (hv (make-array 16 :initial-element 0))     ; state, (hi lo) pairs
         (wv (make-array 160 :initial-element 0))    ; schedule, (hi lo) pairs
         (kv (%s5-k))
         (mask #xffffffff))
    (dotimes (i 8)
      (multiple-value-bind (hi lo) (%s5-split (aref init i))
        (setf (aref hv (* 2 i)) hi (aref hv (1+ (* 2 i))) lo)))
    (replace m msg)
    (setf (aref m ml) #x80)
    (dotimes (i 16)
      (setf (aref m (- padlen 1 i)) (logand #xff (ash bitlen (* -8 i)))))
    (loop for base from 0 below padlen by 128 do
      (dotimes (i 32)                                ; 32 big-endian u32 halves
        (let ((j (+ base (* i 4))))
          (setf (aref wv i) (logior (ash (aref m j) 24) (ash (aref m (+ j 1)) 16)
                                    (ash (aref m (+ j 2)) 8) (aref m (+ j 3))))))
      (loop for i from 16 below 80 do
        (let* ((ah (aref wv (* 2 (- i 15)))) (al (aref wv (1+ (* 2 (- i 15)))))
               (bh (aref wv (* 2 (- i 2))))  (bl (aref wv (1+ (* 2 (- i 2)))))
               (s0h (logxor (%s5-hi-ror ah al 1) (%s5-hi-ror ah al 8) (%s5-hi-shr ah al 7)))
               (s0l (logxor (%s5-lo-ror ah al 1) (%s5-lo-ror ah al 8) (%s5-lo-shr ah al 7)))
               (s1h (logxor (%s5-hi-ror bh bl 19) (%s5-hi-ror bh bl 61) (%s5-hi-shr bh bl 6)))
               (s1l (logxor (%s5-lo-ror bh bl 19) (%s5-lo-ror bh bl 61) (%s5-lo-shr bh bl 6)))
               (lo (+ (aref wv (1+ (* 2 (- i 16)))) s0l (aref wv (1+ (* 2 (- i 7)))) s1l))
               (hi (+ (aref wv (* 2 (- i 16))) s0h (aref wv (* 2 (- i 7))) s1h (ash lo -32))))
          (setf (aref wv (* 2 i)) (logand hi mask)
                (aref wv (1+ (* 2 i))) (logand lo mask))))
      (let ((ah (aref hv 0)) (al (aref hv 1)) (bh (aref hv 2)) (bl (aref hv 3))
            (ch (aref hv 4)) (cl (aref hv 5)) (dh (aref hv 6)) (dl (aref hv 7))
            (eh (aref hv 8)) (el (aref hv 9)) (fh (aref hv 10)) (fl (aref hv 11))
            (gh (aref hv 12)) (gl (aref hv 13)) (hh (aref hv 14)) (hl (aref hv 15)))
        (dotimes (i 80)
          (let* ((bs1h (logxor (%s5-hi-ror eh el 14) (%s5-hi-ror eh el 18) (%s5-hi-ror eh el 41)))
                 (bs1l (logxor (%s5-lo-ror eh el 14) (%s5-lo-ror eh el 18) (%s5-lo-ror eh el 41)))
                 (chh (logxor (logand eh fh) (logand (logxor eh mask) gh)))
                 (chl (logxor (logand el fl) (logand (logxor el mask) gl)))
                 (t1l (+ hl bs1l chl (aref kv (1+ (* 2 i))) (aref wv (1+ (* 2 i)))))
                 (t1h (logand (+ hh bs1h chh (aref kv (* 2 i)) (aref wv (* 2 i)) (ash t1l -32)) mask))
                 (t1l (logand t1l mask))
                 (bs0h (logxor (%s5-hi-ror ah al 28) (%s5-hi-ror ah al 34) (%s5-hi-ror ah al 39)))
                 (bs0l (logxor (%s5-lo-ror ah al 28) (%s5-lo-ror ah al 34) (%s5-lo-ror ah al 39)))
                 (majh (logxor (logand ah bh) (logand ah ch) (logand bh ch)))
                 (majl (logxor (logand al bl) (logand al cl) (logand bl cl)))
                 (t2l (+ bs0l majl))
                 (t2h (+ bs0h majh (ash t2l -32)))
                 (el2 (+ dl t1l))
                 (al2 (+ t1l (logand t2l mask))))
            (setq hh gh hl gl  gh fh gl fl  fh eh fl el
                  eh (logand (+ dh t1h (ash el2 -32)) mask) el (logand el2 mask)
                  dh ch dl cl  ch bh cl bl  bh ah bl al
                  ah (logand (+ t1h t2h (ash al2 -32)) mask) al (logand al2 mask))))
        (macrolet ((acc (i xh xl)
                     `(let ((lo (+ (aref hv ,(1+ (* 2 i))) ,xl)))
                        (setf (aref hv ,(* 2 i)) (logand (+ (aref hv ,(* 2 i)) ,xh (ash lo -32)) mask)
                              (aref hv ,(1+ (* 2 i))) (logand lo mask)))))
          (acc 0 ah al) (acc 1 bh bl) (acc 2 ch cl) (acc 3 dh dl)
          (acc 4 eh el) (acc 5 fh fl) (acc 6 gh gl) (acc 7 hh hl))))
    (let ((out (make-array nbytes :element-type '(unsigned-byte 8))))
      (dotimes (b nbytes)
        (let ((half (aref hv (floor b 4))) (sh (* -8 (- 3 (mod b 4)))))
          (setf (aref out b) (logand #xff (ash half sh)))))
      out)))
)

(defun sha512 (msg)
  "SHA-512 of byte vector MSG → fresh 64-byte big-endian digest."
  (%sha512-digest msg +sha512-init+ 64))

(defun sha384 (msg)
  "SHA-384 (FIPS 180-4) of byte vector MSG → fresh 48-byte big-endian digest."
  (%sha512-digest msg +sha384-init+ 48))

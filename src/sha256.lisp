;;;; sha256.lisp — SHA-256 (FIPS 180-4), pure Common Lisp, no dependencies.
;;;;
;;;; Operates on (unsigned-byte 8) vectors; returns a fresh 32-byte big-endian
;;;; digest.  Ported from secp256k1-fast (kept independent — natrium does not
;;;; depend on that library; both stay self-contained).  This is the portable
;;;; reference; a native build may override with a hardware-accelerated version.

(in-package #:natrium)

(deftype u32 () '(unsigned-byte 32))

(declaim (type (simple-array u32 (64)) +sha256-k+))
(defparameter +sha256-k+
  (make-array 64 :element-type 'u32 :initial-contents
   '(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
     #xd807aa98 #x12835b01 #x243185be #x550c7dc3 #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
     #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
     #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
     #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13 #x650a7354 #x766a0abb #x81c2c92e #x92722c85
     #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
     #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
     #x748f82ee #x78a5636f #x84c87814 #x8cc70208 #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)))

(declaim (inline ror32 shr32))
(defun ror32 (x n) (declare (type u32 x) (type (integer 0 31) n))
  (logand #xffffffff (logior (ash x (- n)) (ash x (- 32 n)))))
(defun shr32 (x n) (declare (type u32 x)) (ash x (- n)))

(defun sha256 (msg)
  "SHA-256 of byte vector MSG → fresh 32-byte big-endian digest."
  (let* ((ml (length msg))
         (bitlen (* ml 8))
         (padlen (let ((r (mod (+ ml 9) 64))) (if (zerop r) (+ ml 9) (+ ml 9 (- 64 r)))))
         (m (make-array padlen :element-type '(unsigned-byte 8) :initial-element 0))
         (h (make-array 8 :element-type 'u32 :initial-contents
              '(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
                #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)))
         (w (make-array 64 :element-type 'u32 :initial-element 0)))
    (replace m msg)
    (setf (aref m ml) #x80)
    (dotimes (i 8)                                  ; 64-bit big-endian bit length
      (setf (aref m (- padlen 1 i)) (logand #xff (ash bitlen (* -8 i)))))
    (loop for base from 0 below padlen by 64 do
      (dotimes (i 16)
        (let ((j (+ base (* i 4))))
          (setf (aref w i) (logior (ash (aref m j) 24) (ash (aref m (+ j 1)) 16)
                                   (ash (aref m (+ j 2)) 8) (aref m (+ j 3))))))
      (loop for i from 16 below 64 do
        (let ((s0 (logxor (ror32 (aref w (- i 15)) 7) (ror32 (aref w (- i 15)) 18) (shr32 (aref w (- i 15)) 3)))
              (s1 (logxor (ror32 (aref w (- i 2)) 17) (ror32 (aref w (- i 2)) 19) (shr32 (aref w (- i 2)) 10))))
          (setf (aref w i) (logand #xffffffff (+ (aref w (- i 16)) s0 (aref w (- i 7)) s1)))))
      (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
            (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
        (dotimes (i 64)
          (let* ((bs1 (logxor (ror32 e 6) (ror32 e 11) (ror32 e 25)))
                 (ch (logxor (logand e f) (logand (logxor e #xffffffff) g)))
                 (t1 (logand #xffffffff (+ hh bs1 ch (aref +sha256-k+ i) (aref w i))))
                 (bs0 (logxor (ror32 a 2) (ror32 a 13) (ror32 a 22)))
                 (maj (logxor (logand a b) (logand a c) (logand b c)))
                 (t2 (logand #xffffffff (+ bs0 maj))))
            ;; sequential setf: each rhs reads the pre-shift value
            (setf hh g  g f  f e  e (logand #xffffffff (+ d t1))
                  d c  c b  b a  a (logand #xffffffff (+ t1 t2)))))
        (setf (aref h 0) (logand #xffffffff (+ (aref h 0) a))
              (aref h 1) (logand #xffffffff (+ (aref h 1) b))
              (aref h 2) (logand #xffffffff (+ (aref h 2) c))
              (aref h 3) (logand #xffffffff (+ (aref h 3) d))
              (aref h 4) (logand #xffffffff (+ (aref h 4) e))
              (aref h 5) (logand #xffffffff (+ (aref h 5) f))
              (aref h 6) (logand #xffffffff (+ (aref h 6) g))
              (aref h 7) (logand #xffffffff (+ (aref h 7) hh)))))
    (let ((out (make-array 32 :element-type '(unsigned-byte 8))))
      (dotimes (i 8)
        (let ((v (aref h i)) (o (* i 4)))
          (setf (aref out o) (logand #xff (ash v -24))
                (aref out (+ o 1)) (logand #xff (ash v -16))
                (aref out (+ o 2)) (logand #xff (ash v -8))
                (aref out (+ o 3)) (logand #xff v))))
      out)))

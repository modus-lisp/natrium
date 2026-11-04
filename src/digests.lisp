;;;; digests.lisp — the public-data hashes Bitcoin and Tor still need:
;;;; RIPEMD-160 (HASH160), SHA-1 (OP_SHA1, legacy protocols) and SHA3-256
;;;; (Tor v3 onion checksums).  Pure Common Lisp, no dependencies.
;;;;
;;;; These hash PUBLIC data (scripts, addresses, keys), so unlike SHA-256 /
;;;; SHA-512 they use ordinary heap scratch rather than the FIXED pool.
;;;;
;;;; FIXNUM-SAFE BY CONSTRUCTION.  Every word is a u32 and every left shift
;;;; masks BEFORE it shifts (%SHL32), so no intermediate leaves 32 bits.  On
;;;; modus, whose fixnums are 62 bits, an unmasked (ash u32 31) is a bignum; on
;;;; SBCL the declarations keep it all in machine words.  SHA3's 64-bit lanes are
;;;; pairs of u32 halves for the same reason, one implementation for both Lisps.

(in-package #:natrium)

(declaim (inline %shl32 %rol32 %add32))
(defun %shl32 (x n)
  (declare (type (unsigned-byte 32) x) (type (integer 0 32) n))
  (if (= n 32) 0 (ash (logand x (1- (ash 1 (- 32 n)))) n)))
(defun %rol32 (x n)
  (declare (type (unsigned-byte 32) x) (type (integer 0 31) n))
  (if (zerop n) x (logior (%shl32 x n) (ash x (- n 32)))))
(defun %add32 (&rest xs)
  (let ((s 0)) (dolist (x xs s) (setf s (logand #xffffffff (+ s x))))))

(defun %md-pad (msg big-endian-p)
  "MSG padded MD-style to a multiple of 64 bytes with its 64-bit bit length,
   big- or little-endian."
  (let* ((n (length msg))
         (total (* 64 (ceiling (+ n 9) 64)))
         (out (make-u8v total))
         (bits (* 8 n)))
    (replace out msg)
    (setf (aref out n) #x80)
    (dotimes (i 8 out)
      (setf (aref out (if big-endian-p (- total 1 i) (+ (- total 8) i)))
            (ldb (byte 8 (* 8 i)) bits)))))

;;; --- SHA-1 (FIPS 180-4) ----------------------------------------------------

(defun sha1 (msg)
  "SHA-1 of the byte vector MSG: a fresh 20-byte vector."
  (let* ((m (%md-pad msg t))
         (h (list #x67452301 #xefcdab89 #x98badcfe #x10325476 #xc3d2e1f0))
         (w (make-array 80 :element-type '(unsigned-byte 32))))
    (loop for off from 0 below (length m) by 64 do
      (dotimes (i 16)
        (let ((j (+ off (* 4 i))))
          (setf (aref w i) (logior (%shl32 (aref m j) 24) (%shl32 (aref m (+ j 1)) 16)
                                   (%shl32 (aref m (+ j 2)) 8) (aref m (+ j 3))))))
      (loop for i from 16 below 80 do
        (setf (aref w i) (%rol32 (logxor (aref w (- i 3)) (aref w (- i 8))
                                         (aref w (- i 14)) (aref w (- i 16))) 1)))
      (destructuring-bind (a b c d e) h
        (dotimes (i 80)
          (multiple-value-bind (f k)
              (cond ((< i 20) (values (logior (logand b c) (logand (logxor b #xffffffff) d)) #x5a827999))
                    ((< i 40) (values (logxor b c d) #x6ed9eba1))
                    ((< i 60) (values (logior (logand b c) (logand b d) (logand c d)) #x8f1bbcdc))
                    (t (values (logxor b c d) #xca62c1d6)))
            (let ((tmp (%add32 (%rol32 a 5) f e k (aref w i))))
              (setf e d d c c (%rol32 b 30) b a a tmp))))
        (setf h (mapcar #'%add32 h (list a b c d e)))))
    (let ((out (make-u8v 20)))
      (loop for x in h for i from 0 do
        (dotimes (k 4) (setf (aref out (+ (* 4 i) k)) (ldb (byte 8 (- 24 (* 8 k))) x))))
      out)))

;;; --- RIPEMD-160 (Dobbertin, Bosselaers, Preneel 1996) ---------------------

(defparameter +rmd-r+
  (coerce '(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15  7 4 13 1 10 6 15 3 12 0 9 5 2 14 11 8
            3 10 14 4 9 15 8 1 2 7 0 6 13 11 5 12  1 9 11 10 0 8 12 4 13 3 7 15 14 5 6 2
            4 0 5 9 7 12 2 10 14 1 3 8 11 6 15 13) 'simple-vector))
(defparameter +rmd-rr+
  (coerce '(5 14 7 0 9 2 11 4 13 6 15 8 1 10 3 12  6 11 3 7 0 13 5 10 14 15 8 12 4 9 1 2
            15 5 1 3 7 14 6 9 11 8 12 2 10 0 4 13  8 6 4 1 3 11 15 0 5 12 2 13 9 7 10 14
            12 15 10 4 1 5 8 7 6 2 13 14 0 3 9 11) 'simple-vector))
(defparameter +rmd-s+
  (coerce '(11 14 15 12 5 8 7 9 11 13 14 15 6 7 9 8  7 6 8 13 11 9 7 15 7 12 15 9 11 7 13 12
            11 13 6 7 14 9 13 15 14 8 13 6 5 12 7 5  11 12 14 15 14 15 9 8 9 14 5 6 8 6 5 12
            9 15 5 11 6 8 13 12 5 12 13 14 11 8 5 6) 'simple-vector))
(defparameter +rmd-ss+
  (coerce '(8 9 9 11 13 15 15 5 7 7 8 11 14 14 12 6  9 13 15 7 12 8 9 11 7 7 12 7 6 15 13 11
            9 7 15 11 8 6 6 14 12 13 5 14 13 13 7 5  15 5 8 11 14 14 6 14 6 9 12 9 12 5 15 8
            8 5 12 9 12 5 14 6 8 13 6 5 15 13 11 11) 'simple-vector))
(defparameter +rmd-kl+ #(#x00000000 #x5a827999 #x6ed9eba1 #x8f1bbcdc #xa953fd4e))
(defparameter +rmd-kr+ #(#x50a28be6 #x5c4dd124 #x6d703ef3 #x7a6d76e9 #x00000000))

(defun %rmd-f (j x y z)
  (let ((ny (logxor y #xffffffff)) (nz (logxor z #xffffffff)) (nx (logxor x #xffffffff)))
    (cond ((< j 16) (logxor x y z))
          ((< j 32) (logior (logand x y) (logand nx z)))
          ((< j 48) (logxor (logior x ny) z))
          ((< j 64) (logior (logand x z) (logand y nz)))
          (t (logxor x (logior y nz))))))

(defun ripemd160 (msg)
  "RIPEMD-160 of the byte vector MSG: a fresh 20-byte vector."
  (let* ((m (%md-pad msg nil))
         (h (vector #x67452301 #xefcdab89 #x98badcfe #x10325476 #xc3d2e1f0))
         (x (make-array 16 :element-type '(unsigned-byte 32))))
    (loop for off from 0 below (length m) by 64 do
      (dotimes (i 16)
        (let ((j (+ off (* 4 i))))
          (setf (aref x i) (logior (aref m j) (%shl32 (aref m (+ j 1)) 8)
                                   (%shl32 (aref m (+ j 2)) 16) (%shl32 (aref m (+ j 3)) 24)))))
      (let ((al (aref h 0)) (bl (aref h 1)) (cl (aref h 2)) (dl (aref h 3)) (el (aref h 4))
            (ar (aref h 0)) (br (aref h 1)) (cr (aref h 2)) (dr (aref h 3)) (er (aref h 4)))
        (dotimes (j 80)
          (let* ((rnd (floor j 16))
                 (tl (%add32 (%rol32 (%add32 al (%rmd-f j bl cl dl) (aref x (svref +rmd-r+ j))
                                             (svref +rmd-kl+ rnd))
                                     (svref +rmd-s+ j))
                             el))
                 (tr (%add32 (%rol32 (%add32 ar (%rmd-f (- 79 j) br cr dr) (aref x (svref +rmd-rr+ j))
                                             (svref +rmd-kr+ rnd))
                                     (svref +rmd-ss+ j))
                             er)))
            (setf al el el dl dl (%rol32 cl 10) cl bl bl tl
                  ar er er dr dr (%rol32 cr 10) cr br br tr)))
        (let ((tmp (%add32 (aref h 1) cl dr)))
          (setf (aref h 1) (%add32 (aref h 2) dl er)
                (aref h 2) (%add32 (aref h 3) el ar)
                (aref h 3) (%add32 (aref h 4) al br)
                (aref h 4) (%add32 (aref h 0) bl cr)
                (aref h 0) tmp))))
    (let ((out (make-u8v 20)))
      (dotimes (i 5 out)
        (dotimes (k 4) (setf (aref out (+ (* 4 i) k)) (ldb (byte 8 (* 8 k)) (aref h i))))))))

(defun hash160 (msg)
  "RIPEMD-160 of SHA-256 of MSG: Bitcoin's HASH160."
  (ripemd160 (sha256 msg)))

;;; --- SHA3-256 (FIPS 202), lanes as (lo . hi) u32 halves --------------------

(defparameter +keccak-rho+
  #(0 1 62 28 27 36 44 6 55 20 3 10 43 25 39 41 45 15 21 8 18 2 61 56 14))
(defparameter +keccak-rc-lo+
  #(#x00000001 #x00008082 #x0000808a #x80008000 #x0000808b #x80000001 #x80008081 #x00008009
    #x0000008a #x00000088 #x80008009 #x8000000a #x8000808b #x0000008b #x00008089 #x00008003
    #x00008002 #x00000080 #x0000800a #x8000000a #x80008081 #x00008080 #x80000001 #x80008008))
(defparameter +keccak-rc-hi+
  #(#x00000000 #x00000000 #x80000000 #x80000000 #x00000000 #x00000000 #x80000000 #x80000000
    #x00000000 #x00000000 #x00000000 #x00000000 #x00000000 #x80000000 #x80000000 #x80000000
    #x80000000 #x80000000 #x00000000 #x80000000 #x80000000 #x80000000 #x00000000 #x80000000))

(defun %rol64 (lo hi n)
  "Rotate the 64-bit lane HI:LO left by N; returns (values lo hi)."
  (cond ((zerop n) (values lo hi))
        ((= n 32) (values hi lo))
        ((> n 32) (%rol64 hi lo (- n 32)))
        (t (values (logior (%shl32 lo n) (ash hi (- n 32)))
                   (logior (%shl32 hi n) (ash lo (- n 32)))))))

(defun %keccak-f (lo hi)
  (let ((clo (make-array 5)) (chi (make-array 5))
        (blo (make-array 25)) (bhi (make-array 25)))
    (dotimes (round 24)
      ;; theta
      (dotimes (x 5)
        (setf (svref clo x) (logxor (svref lo x) (svref lo (+ x 5)) (svref lo (+ x 10))
                                    (svref lo (+ x 15)) (svref lo (+ x 20)))
              (svref chi x) (logxor (svref hi x) (svref hi (+ x 5)) (svref hi (+ x 10))
                                    (svref hi (+ x 15)) (svref hi (+ x 20)))))
      (dotimes (x 5)
        (multiple-value-bind (rl rh) (%rol64 (svref clo (mod (1+ x) 5)) (svref chi (mod (1+ x) 5)) 1)
          (let ((dl (logxor (svref clo (mod (+ x 4) 5)) rl))
                (dh (logxor (svref chi (mod (+ x 4) 5)) rh)))
            (dotimes (y 5)
              (let ((i (+ x (* 5 y))))
                (setf (svref lo i) (logxor (svref lo i) dl)
                      (svref hi i) (logxor (svref hi i) dh)))))))
      ;; rho + pi
      (dotimes (x 5)
        (dotimes (y 5)
          (let ((i (+ x (* 5 y))))
            (multiple-value-bind (rl rh) (%rol64 (svref lo i) (svref hi i) (svref +keccak-rho+ i))
              (let ((d (+ y (* 5 (mod (+ (* 2 x) (* 3 y)) 5)))))
                (setf (svref blo d) rl (svref bhi d) rh))))))
      ;; chi
      (dotimes (y 5)
        (dotimes (x 5)
          (let ((i (+ x (* 5 y)))
                (i1 (+ (mod (+ x 1) 5) (* 5 y)))
                (i2 (+ (mod (+ x 2) 5) (* 5 y))))
            (setf (svref lo i) (logxor (svref blo i) (logand (logxor (svref blo i1) #xffffffff) (svref blo i2)))
                  (svref hi i) (logxor (svref bhi i) (logand (logxor (svref bhi i1) #xffffffff) (svref bhi i2)))))))
      ;; iota
      (setf (svref lo 0) (logxor (svref lo 0) (svref +keccak-rc-lo+ round))
            (svref hi 0) (logxor (svref hi 0) (svref +keccak-rc-hi+ round))))))

(defun %sha3 (msg rate outlen)
  (let* ((lo (make-array 25 :initial-element 0))
         (hi (make-array 25 :initial-element 0))
         (n (length msg))
         (padded (make-u8v (* rate (1+ (floor n rate))))))
    (replace padded msg)
    (setf (aref padded n) (logxor (aref padded n) #x06))
    (let ((last (1- (length padded))))
      (setf (aref padded last) (logxor (aref padded last) #x80)))
    (loop for off from 0 below (length padded) by rate do
      (dotimes (k (floor rate 8))
        (let ((j (+ off (* 8 k))))
          (setf (svref lo k) (logxor (svref lo k)
                                     (logior (aref padded j) (%shl32 (aref padded (+ j 1)) 8)
                                             (%shl32 (aref padded (+ j 2)) 16) (%shl32 (aref padded (+ j 3)) 24)))
                (svref hi k) (logxor (svref hi k)
                                     (logior (aref padded (+ j 4)) (%shl32 (aref padded (+ j 5)) 8)
                                             (%shl32 (aref padded (+ j 6)) 16) (%shl32 (aref padded (+ j 7)) 24))))))
      (%keccak-f lo hi))
    (let ((out (make-u8v outlen)))
      (dotimes (i outlen out)
        (let* ((lane (floor i 8)) (b (mod i 8))
               (w (if (< b 4) (svref lo lane) (svref hi lane))))
          (setf (aref out i) (ldb (byte 8 (* 8 (mod b 4))) w)))))))

(defun sha3-256 (msg)
  "SHA3-256 (FIPS 202) of the byte vector MSG: a fresh 32-byte vector."
  (%sha3 msg 136 32))

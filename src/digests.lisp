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
;;; From seal (src/crypto/sha1.lisp), the fastest of the org's four on SBCL: 100 MB/s
;;; against 20 for the padded-copy version this replaced.  Blocks are folded straight
;;; from the caller's buffer, and SHA1-INIT / -UPDATE / -FINAL let a caller hash pieces
;;; (git's "<type> <size>\0" header, then the content) without concatenating them.
;;; The unmasked shift in %SHA1-ROL32 may make a bignum on Modus before the LOGAND; the
;;; answer is right either way, only slower there.

;;; On SBCL a 32-bit rotate is one ROL through its sb-rotate-byte contrib (part of SBCL,
;;; no foreign code); the portable shift-and-or is six instructions there.
#+sbcl (eval-when (:compile-toplevel :load-toplevel :execute) (require :sb-rotate-byte))

(declaim (inline %sha1-rol32))
(defun %sha1-rol32 (x n)
  (declare (type (unsigned-byte 32) x) (type (integer 0 31) n)
           (optimize (speed 3) (safety 0)))
  #+sbcl (sb-rotate-byte:rotate-byte n (byte 32 0) x)
  #-sbcl (logand #xffffffff (logior (ash x n) (ash x (- n 32)))))

(deftype %sha1-h () '(simple-array (unsigned-byte 32) (5)))
(deftype %sha1-w () '(simple-array (unsigned-byte 32) (80)))

(defun %sha1-compress (h w src off)
  "Fold the 64-byte block SRC[OFF, OFF+64) into the state H, using W as scratch."
  (declare (type %sha1-h h) (type %sha1-w w) (type (simple-array (unsigned-byte 8) (*)) src)
           (type fixnum off) (optimize (speed 3) (safety 0)))
  (dotimes (i 16)
    (let ((j (+ off (* i 4))))
      (declare (type fixnum j))
      (setf (aref w i) (logior (ash (aref src j) 24) (ash (aref src (+ j 1)) 16)
                               (ash (aref src (+ j 2)) 8) (aref src (+ j 3))))))
  (loop for i of-type fixnum from 16 below 80 do
    (setf (aref w i) (%sha1-rol32 (logxor (aref w (- i 3)) (aref w (- i 8))
                                          (aref w (- i 14)) (aref w (- i 16))) 1)))
  ;; Fully unrolled: round I's five working variables are the previous round's under
  ;; rotated NAMES, so the expansion moves nothing.  The per-round choice of F and K is
  ;; made at macroexpansion time.  SBCL: 109 MB/s for a loop choosing F/K per round,
  ;; ~180 unrolled with ROL.  (ironclad's 364 is x86-64 assembly, not Lisp.)
  (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3)) (e (aref h 4)))
    (declare (type (unsigned-byte 32) a b c d e))
    (macrolet ((all-rounds ()
                 (let ((vars (list 'a 'b 'c 'd 'e)) (forms '()))
                   (dotimes (i 80)
                     (destructuring-bind (va vb vc vd ve) vars
                       (let ((f (cond ((< i 20) `(logxor ,vd (logand ,vb (logxor ,vc ,vd))))   ; = (b&c)|(~b&d)
                                      ((< i 40) `(logxor ,vb ,vc ,vd))
                                      ((< i 60) `(logior (logand ,vb ,vc) (logand ,vb ,vd) (logand ,vc ,vd)))
                                      (t `(logxor ,vb ,vc ,vd))))
                             (k (cond ((< i 20) #x5a827999) ((< i 40) #x6ed9eba1)
                                      ((< i 60) #x8f1bbcdc) (t #xca62c1d6))))
                         ;; new A goes into E's variable; B becomes rol30(B) in place
                         (push `(setf ,ve (logand #xffffffff (+ (%sha1-rol32 ,va 5) ,f ,ve ,k (aref w ,i)))
                                      ,vb (%sha1-rol32 ,vb 30))
                               forms)
                         (setf vars (list ve va vb vc vd)))))
                   ;; after 80 rounds (a multiple of 5) the names are back where they began
                   `(progn ,@(nreverse forms)))))
      (all-rounds))
    (setf (aref h 0) (logand #xffffffff (+ (aref h 0) a))
          (aref h 1) (logand #xffffffff (+ (aref h 1) b))
          (aref h 2) (logand #xffffffff (+ (aref h 2) c))
          (aref h 3) (logand #xffffffff (+ (aref h 3) d))
          (aref h 4) (logand #xffffffff (+ (aref h 4) e)))))

(defstruct (sha1-state (:conc-name %s1-) (:constructor %make-sha1-state))
  (h (make-array 5 :element-type '(unsigned-byte 32) :initial-contents
       '(#x67452301 #xefcdab89 #x98badcfe #x10325476 #xc3d2e1f0)) :type %sha1-h)
  (w (make-array 80 :element-type '(unsigned-byte 32)) :type %sha1-w)
  (block (make-array 64 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (64)))
  (fill 0 :type fixnum)
  (len 0 :type unsigned-byte))

(defun sha1-init () "A fresh streaming SHA-1 state." (%make-sha1-state))

(defun sha1-update (state src &optional (start 0) (end (length src)))
  "Feed SRC[START, END) into STATE.  Whole 64-byte blocks are folded straight from
   SRC; a trailing partial block is buffered for the next call."
  (declare (type sha1-state state) (type fixnum start end)
           (optimize (speed 3) (safety 1)))
  (unless (typep src '(simple-array (unsigned-byte 8) (*)))  ; a copy of just the range
    (setf src (coerce (subseq src start end) '(simple-array (unsigned-byte 8) (*)))
          end (- end start) start 0))
  (let ((block (%s1-block state)) (h (%s1-h state)) (w (%s1-w state)))
    (incf (%s1-len state) (- end start))
    (let ((fill (%s1-fill state)))
      (declare (type fixnum fill))
      (when (plusp fill)
        (loop while (and (< start end) (< fill 64)) do
          (setf (aref block fill) (aref src start)) (incf fill) (incf start))
        (when (= fill 64) (%sha1-compress h w block 0) (setf fill 0)))
      (loop while (<= (+ start 64) end) do
        (%sha1-compress h w src start) (incf start 64))
      (loop while (< start end) do
        (setf (aref block fill) (aref src start)) (incf fill) (incf start))
      (setf (%s1-fill state) fill)))
  state)

(defun sha1-final (state)
  "Finish STATE and return its 20-byte big-endian digest."
  (declare (type sha1-state state))
  (let ((block (%s1-block state)) (h (%s1-h state)) (w (%s1-w state))
        (fill (%s1-fill state)) (bitlen (* (%s1-len state) 8)))
    (declare (type fixnum fill))
    (setf (aref block fill) #x80) (incf fill)
    (when (> fill 56)
      (loop while (< fill 64) do (setf (aref block fill) 0) (incf fill))
      (%sha1-compress h w block 0) (setf fill 0))
    (loop while (< fill 56) do (setf (aref block fill) 0) (incf fill))
    (dotimes (i 8) (setf (aref block (+ 56 i)) (logand #xff (ash bitlen (* -8 (- 7 i))))))
    (%sha1-compress h w block 0)
    (let ((out (make-u8v 20)))
      (dotimes (i 5)
        (let ((v (aref h i)) (o (* i 4)))
          (setf (aref out o) (logand #xff (ash v -24))
                (aref out (+ o 1)) (logand #xff (ash v -16))
                (aref out (+ o 2)) (logand #xff (ash v -8))
                (aref out (+ o 3)) (logand #xff v))))
      out)))

(defun sha1-copy-state (state)
  "A new SHA-1 state that continues independently from STATE (for a running digest
   read part-way, as Tor's relay cells do)."
  (%make-sha1-state :h (copy-seq (%s1-h state)) :w (make-array 80 :element-type '(unsigned-byte 32))
                    :block (copy-seq (%s1-block state)) :fill (%s1-fill state) :len (%s1-len state)))

(defun sha1 (msg)
  "SHA-1 of the byte vector MSG: a fresh 20-byte vector."
  (let ((s (sha1-init))) (sha1-update s msg) (sha1-final s)))

;;; --- MD5 (RFC 1321) -----------------------------------------------------------
;;; Broken for collisions; here for protocols that still name it -- TURN's long-term
;;; credential key, frp's login digest, PDF's RC4 handlers.  Not for anything new.

(declaim (type (simple-array (unsigned-byte 32) (64)) +md5-k+)
         (type (simple-array (unsigned-byte 8) (64)) +md5-s+))
(defparameter +md5-k+
  (make-array 64 :element-type '(unsigned-byte 32) :initial-contents
   '(#xd76aa478 #xe8c7b756 #x242070db #xc1bdceee #xf57c0faf #x4787c62a #xa8304613 #xfd469501
     #x698098d8 #x8b44f7af #xffff5bb1 #x895cd7be #x6b901122 #xfd987193 #xa679438e #x49b40821
     #xf61e2562 #xc040b340 #x265e5a51 #xe9b6c7aa #xd62f105d #x02441453 #xd8a1e681 #xe7d3fbc8
     #x21e1cde6 #xc33707d6 #xf4d50d87 #x455a14ed #xa9e3e905 #xfcefa3f8 #x676f02d9 #x8d2a4c8a
     #xfffa3942 #x8771f681 #x6d9d6122 #xfde5380c #xa4beea44 #x4bdecfa9 #xf6bb4b60 #xbebfbc70
     #x289b7ec6 #xeaa127fa #xd4ef3085 #x04881d05 #xd9d4d039 #xe6db99e5 #x1fa27cf8 #xc4ac5665
     #xf4292244 #x432aff97 #xab9423a7 #xfc93a039 #x655b59c3 #x8f0ccc92 #xffeff47d #x85845dd1
     #x6fa87e4f #xfe2ce6e0 #xa3014314 #x4e0811a1 #xf7537e82 #xbd3af235 #x2ad7d2bb #xeb86d391)))
(defparameter +md5-s+
  (make-array 64 :element-type '(unsigned-byte 8) :initial-contents
   '(7 12 17 22 7 12 17 22 7 12 17 22 7 12 17 22  5 9 14 20 5 9 14 20 5 9 14 20 5 9 14 20
     4 11 16 23 4 11 16 23 4 11 16 23 4 11 16 23  6 10 15 21 6 10 15 21 6 10 15 21 6 10 15 21)))

(defun md5 (msg)
  "MD5 of the byte vector MSG: a fresh 16-byte vector."
  (let* ((m (%md-pad msg nil))
         (h (list #x67452301 #xefcdab89 #x98badcfe #x10325476))
         (x (make-array 16 :element-type '(unsigned-byte 32))))
    (loop for off from 0 below (length m) by 64 do
      (dotimes (i 16)
        (let ((j (+ off (* 4 i))))
          (setf (aref x i) (logior (aref m j) (%shl32 (aref m (+ j 1)) 8)
                                   (%shl32 (aref m (+ j 2)) 16) (%shl32 (aref m (+ j 3)) 24)))))
      (destructuring-bind (a b c d) h
        (dotimes (i 64)
          (multiple-value-bind (f g)
              (cond ((< i 16) (values (logior (logand b c) (logand (logxor b #xffffffff) d)) i))
                    ((< i 32) (values (logior (logand d b) (logand (logxor d #xffffffff) c)) (mod (1+ (* 5 i)) 16)))
                    ((< i 48) (values (logxor b c d) (mod (+ (* 3 i) 5) 16)))
                    (t (values (logxor c (logior b (logxor d #xffffffff))) (mod (* 7 i) 16))))
            (let ((tmp (%add32 a f (aref +md5-k+ i) (aref x g))))
              (setf a d d c c b b (%add32 b (%rol32 tmp (aref +md5-s+ i)))))))
        (setf h (mapcar #'%add32 h (list a b c d)))))
    (let ((out (make-u8v 16)))
      (loop for w in h for i from 0 do
        (dotimes (k 4) (setf (aref out (+ (* 4 i) k)) (ldb (byte 8 (* 8 k)) w))))
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

;;; The sponge, streaming: absorb any number of pieces, then pad with SUFFIX (#x06 for
;;; SHA-3, #x1F for SHAKE) and squeeze.  SHA3-COPY-STATE forks a running hash, which Tor's
;;; relay digests need.
(defstruct (sha3-state (:conc-name %k-) (:constructor %make-sha3-state (rate suffix outlen)))
  (lo (make-array 25 :initial-element 0)) (hi (make-array 25 :initial-element 0))
  (buf (make-u8v 200)) (fill 0 :type fixnum) rate suffix outlen)

(defun %sha3-absorb-block (st buf)
  (let ((lo (%k-lo st)) (hi (%k-hi st)))
    (dotimes (k (floor (%k-rate st) 8))
      (let ((j (* 8 k)))
        (setf (svref lo k) (logxor (svref lo k)
                                   (logior (aref buf j) (%shl32 (aref buf (+ j 1)) 8)
                                           (%shl32 (aref buf (+ j 2)) 16) (%shl32 (aref buf (+ j 3)) 24)))
              (svref hi k) (logxor (svref hi k)
                                   (logior (aref buf (+ j 4)) (%shl32 (aref buf (+ j 5)) 8)
                                           (%shl32 (aref buf (+ j 6)) 16) (%shl32 (aref buf (+ j 7)) 24))))))
    (%keccak-f lo hi)))

(defun make-sha3-256-state () "A fresh streaming SHA3-256." (%make-sha3-state 136 #x06 32))
(defun make-shake256-state () "A fresh streaming SHAKE256." (%make-sha3-state 136 #x1f nil))

(defun sha3-update (st data &optional (start 0) (end (length data)))
  "Absorb DATA[START, END) into the SHA-3 / SHAKE state ST.  Returns ST."
  (let ((buf (%k-buf st)) (rate (%k-rate st)) (fill (%k-fill st)))
    (loop for i from start below end do
      (setf (aref buf fill) (aref data i))
      (when (= (incf fill) rate) (%sha3-absorb-block st buf) (setf fill 0)))
    (setf (%k-fill st) fill))
  st)

(defun sha3-copy-state (st)
  "A new state that continues independently from ST."
  (let ((c (%make-sha3-state (%k-rate st) (%k-suffix st) (%k-outlen st))))
    (setf (%k-lo c) (copy-seq (%k-lo st)) (%k-hi c) (copy-seq (%k-hi st))
          (%k-buf c) (copy-seq (%k-buf st)) (%k-fill c) (%k-fill st))
    c))

(defun sha3-final (st &optional (nbytes (%k-outlen st)))
  "Pad, then squeeze NBYTES (the digest size for SHA3-256; any length for SHAKE).
   ST is used up."
  (let ((buf (%k-buf st)) (rate (%k-rate st)) (fill (%k-fill st)))
    (fill buf 0 :start fill :end rate)
    (setf (aref buf fill) (logxor (aref buf fill) (%k-suffix st)))
    (setf (aref buf (1- rate)) (logxor (aref buf (1- rate)) #x80))
    (%sha3-absorb-block st buf)
    (let ((out (make-u8v nbytes)) (lo (%k-lo st)) (hi (%k-hi st)))
      (loop for done from 0 by rate while (< done nbytes) do
        (when (plusp done) (%keccak-f lo hi))
        (loop for i from 0 below (min rate (- nbytes done)) do
          (let* ((lane (floor i 8)) (b (mod i 8))
                 (w (if (< b 4) (svref lo lane) (svref hi lane))))
            (setf (aref out (+ done i)) (ldb (byte 8 (* 8 (mod b 4))) w)))))
      out)))

(defun sha3-256 (msg)
  "SHA3-256 (FIPS 202) of the byte vector MSG: a fresh 32-byte vector."
  (sha3-final (sha3-update (make-sha3-256-state) msg)))

(defun shake256 (msg nbytes)
  "SHAKE256 (FIPS 202) of MSG: NBYTES of output."
  (sha3-final (sha3-update (make-shake256-state) msg) nbytes))

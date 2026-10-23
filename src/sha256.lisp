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

;;; --- streaming -----------------------------------------------------------
;;; A context is three fixed buffers from the FIXED pool -- the state H, the message
;;; schedule W and the block buffer -- so hashing a secret leaves nothing on the moving
;;; heap: the message is read in place (never copied for padding), and the buffers are
;;; wiped when WITH-SHA256 exits, however it exits.

(defstruct (sha256-ctx (:constructor %make-sha256-ctx (h w buf)))
  (h nil :type (simple-array fixnum (8)))
  (w nil :type (simple-array fixnum (64)))
  (buf nil :type (simple-array (unsigned-byte 8) (64)))
  (buflen 0 :type fixnum)
  (total 0 :type integer))

(defun sha256-init (ctx)
  (replace (sha256-ctx-h ctx) '(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
                                #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19))
  (setf (sha256-ctx-buflen ctx) 0 (sha256-ctx-total ctx) 0)
  ctx)

(defmacro with-sha256 ((ctx) &body body)
  "Bind CTX to an initialised SHA-256 context over fixed scratch for BODY."
  (let ((h (gensym "H")) (w (gensym "W")) (b (gensym "B")))
    `(gossamer:with-fixed-scratch ((,h :fixnums 8) (,w :fixnums 64) (,b :octets 64))
       (let ((,ctx (sha256-init (%make-sha256-ctx ,h ,w ,b))))
         ,@body))))

(defun %sha256-block (h w data off)
  "Compress the 64-byte block DATA[OFF, OFF+64) into H, using W as the schedule."
  (declare (type (simple-array fixnum (8)) h) (type (simple-array fixnum (64)) w)
           (type (simple-array (unsigned-byte 8) (*)) data) (type fixnum off))
  (dotimes (i 16)
    (let ((j (+ off (* i 4))))
      (setf (aref w i) (logior (ash (aref data j) 24) (ash (aref data (+ j 1)) 16)
                               (ash (aref data (+ j 2)) 8) (aref data (+ j 3))))))
  (loop for i from 16 below 64 do
    (let ((s0 (logxor (ror32 (aref w (- i 15)) 7) (ror32 (aref w (- i 15)) 18) (shr32 (aref w (- i 15)) 3)))
          (s1 (logxor (ror32 (aref w (- i 2)) 17) (ror32 (aref w (- i 2)) 19) (shr32 (aref w (- i 2)) 10))))
      (setf (aref w i) (logand #xffffffff (+ (aref w (- i 16)) s0 (aref w (- i 7)) s1)))))
  (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
        (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
    (declare (type u32 a b c d e f g hh))
    (dotimes (i 64)
      (let* ((bs1 (logxor (ror32 e 6) (ror32 e 11) (ror32 e 25)))
             (ch (logxor (logand e f) (logand (logxor e #xffffffff) g)))
             (t1 (logand #xffffffff (+ hh bs1 ch (aref +sha256-k+ i) (aref w i))))
             (bs0 (logxor (ror32 a 2) (ror32 a 13) (ror32 a 22)))
             (maj (logxor (logand a b) (logand a c) (logand b c)))
             (t2 (logand #xffffffff (+ bs0 maj))))
        (setf hh g  g f  f e  e (logand #xffffffff (+ d t1))
              d c  c b  b a  a (logand #xffffffff (+ t1 t2)))))
    (setf (aref h 0) (logand #xffffffff (+ (aref h 0) a))
          (aref h 1) (logand #xffffffff (+ (aref h 1) b))
          (aref h 2) (logand #xffffffff (+ (aref h 2) c))
          (aref h 3) (logand #xffffffff (+ (aref h 3) d))
          (aref h 4) (logand #xffffffff (+ (aref h 4) e))
          (aref h 5) (logand #xffffffff (+ (aref h 5) f))
          (aref h 6) (logand #xffffffff (+ (aref h 6) g))
          (aref h 7) (logand #xffffffff (+ (aref h 7) hh))))
  nil)

(defun sha256-update (ctx data &key (start 0) end)
  "Hash DATA[START,END) into CTX.  DATA is read in place."
  (let* ((end (or end (length data)))
         (buf (sha256-ctx-buf ctx)) (h (sha256-ctx-h ctx)) (w (sha256-ctx-w ctx))
         (simple (typep data '(simple-array (unsigned-byte 8) (*))))
         (i start))
    (incf (sha256-ctx-total ctx) (- end start))
    (loop while (< i end) do
      (cond ((and simple (zerop (sha256-ctx-buflen ctx)) (<= (+ i 64) end))
             (%sha256-block h w data i) (incf i 64))
            (t (setf (aref buf (sha256-ctx-buflen ctx)) (aref data i))
               (incf i)
               (when (= (incf (sha256-ctx-buflen ctx)) 64)
                 (%sha256-block h w buf 0)
                 (setf (sha256-ctx-buflen ctx) 0)))))
    ctx))

(defun sha256-final-into (ctx out &key (start 0))
  "Finish CTX and write the 32-byte digest into OUT at START.  Returns OUT."
  (let ((buf (sha256-ctx-buf ctx)) (h (sha256-ctx-h ctx)) (w (sha256-ctx-w ctx))
        (bitlen (* 8 (sha256-ctx-total ctx))))
    (setf (aref buf (sha256-ctx-buflen ctx)) #x80)
    (incf (sha256-ctx-buflen ctx))
    (when (> (sha256-ctx-buflen ctx) 56)
      (fill buf 0 :start (sha256-ctx-buflen ctx))
      (%sha256-block h w buf 0)
      (setf (sha256-ctx-buflen ctx) 0))
    (fill buf 0 :start (sha256-ctx-buflen ctx))
    (dotimes (i 8) (setf (aref buf (- 63 i)) (logand #xff (ash bitlen (* -8 i)))))
    (%sha256-block h w buf 0)
    (dotimes (i 8)
      (let ((v (aref h i)) (o (+ start (* i 4))))
        (setf (aref out o) (logand #xff (ash v -24))
              (aref out (+ o 1)) (logand #xff (ash v -16))
              (aref out (+ o 2)) (logand #xff (ash v -8))
              (aref out (+ o 3)) (logand #xff v))))
    (gossamer:wipe buf h w)
    out))

(defun sha256-into (msg out &key (start 0))
  "SHA-256 of MSG written into OUT at START (use a fixed OUT when the digest is secret)."
  (with-sha256 (c) (sha256-update c msg) (sha256-final-into c out :start start)))

(defun sha256 (msg)
  "SHA-256 of byte vector MSG → fresh 32-byte big-endian digest."
  (sha256-into msg (make-array 32 :element-type '(unsigned-byte 8))))

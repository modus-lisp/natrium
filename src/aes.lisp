;;;; aes.lisp — AES-128/192/256 (FIPS 197) with no secret-indexed table.
;;;;
;;;; The usual AES is a table lookup per state byte, and a table indexed by a secret
;;;; byte is a cache-timing channel.  Here SubBytes is COMPUTED, bit-sliced: the 16
;;;; state bytes are transposed into eight 16-bit bit-planes (plane i holds bit i of
;;;; every byte, one byte per lane), the GF(2^8) inverse x^254 is evaluated on the
;;;; planes by an addition chain of bit-sliced multiplications, and the affine map
;;;; is a fixed XOR of planes.  All sixteen bytes go through one evaluation, and no
;;;; step branches on, or indexes by, a secret.  ShiftRows is a fixed permutation and
;;;; MixColumns uses a masked xtime.  Plane words fit in 16 bits, so every value is a
;;;; fixnum on every target, 30-bit ones included.
;;;;
;;;; The key schedule lives in a pooled FIXED buffer owned by an AES-KEY; the state,
;;;; the planes and every intermediate live in fixed scratch.
;;;;
;;;; Modes: single blocks, CBC (SP 800-38A; no padding -- the caller pads), and CTR
;;;; (SP 800-38A, a 128-bit big-endian counter block).

(in-package #:natrium)

;;; ---------------------------------------------------------------------------
;;; Bit-sliced GF(2^8) arithmetic on 8 planes of 16 lanes.
;;; ---------------------------------------------------------------------------

(defconstant +aes-lanes+ #xFFFF "All sixteen lanes set.")

(deftype %octets () '(simple-array (unsigned-byte 8) (*)))

(defun %aes-pack! (planes bytes)
  "PLANES[i] <- bit i of BYTES[j] in lane j, for the 16 bytes of BYTES."
  (declare (type (simple-array fixnum (*)) planes) (type %octets bytes) (optimize speed (safety 0)))
  (dotimes (i 8 planes)
    (let ((w 0))
      (declare (type (unsigned-byte 16) w))
      (dotimes (j 16) (setf w (logior w (the (unsigned-byte 16) (ash (logand (ash (aref bytes j) (- i)) 1) j)))))
      (setf (aref planes i) w))))

(defun %aes-unpack! (bytes planes)
  "BYTES[j] <- the eight bits of lane j of PLANES."
  (declare (type (simple-array fixnum (*)) planes) (type %octets bytes) (optimize speed (safety 0)))
  (dotimes (j 16 bytes)
    (let ((b 0))
      (declare (type (unsigned-byte 8) b))
      (dotimes (i 8) (setf b (logior b (the (unsigned-byte 8) (ash (logand (ash (the (unsigned-byte 16) (aref planes i)) (- j)) 1) i)))))
      (setf (aref bytes j) b))))

(deftype %planes () '(simple-array fixnum (*)))

(defmacro %gf-mul-body (out a b)
  "Straight-line bit-sliced GF(2^8) product: load both operands' planes into locals,
form the 15 partial-product planes, reduce by x^8 = x^4+x^3+x+1, store into OUT."
  (let ((as (loop for i below 8 collect (gensym "A")))
        (bs (loop for i below 8 collect (gensym "B")))
        (cs (loop for k below 15 collect (gensym "C"))))
    `(let (,@(loop for v in as for i from 0 collect `(,v (aref ,a ,i)))
           ,@(loop for v in bs for i from 0 collect `(,v (aref ,b ,i))))
       (declare (type (unsigned-byte 16) ,@as ,@bs))
       (let (,@(loop for k below 15
                     collect `(,(nth k cs)
                               (logxor ,@(loop for i below 8 for j = (- k i)
                                               when (<= 0 j 7) collect `(logand ,(nth i as) ,(nth j bs)))))))
         (declare (type (unsigned-byte 16) ,@cs))
         ,@(loop for k from 14 downto 8
                 collect `(setf ,(nth (- k 4) cs) (logxor ,(nth (- k 4) cs) ,(nth k cs))
                                ,(nth (- k 5) cs) (logxor ,(nth (- k 5) cs) ,(nth k cs))
                                ,(nth (- k 7) cs) (logxor ,(nth (- k 7) cs) ,(nth k cs))
                                ,(nth (- k 8) cs) (logxor ,(nth (- k 8) cs) ,(nth k cs))))
         (setf ,@(loop for i below 8 append `((aref ,out ,i) ,(nth i cs))))
         ,out))))

(defun %aes-gf-mul! (out a b c)
  "OUT <- A * B in GF(2^8) mod x^8+x^4+x^3+x+1, lane-wise on planes.  OUT may be A
or B.  (C is unused: the products live in locals, which are immediate fixnums.)"
  (declare (type %planes out a b) (ignore c) (optimize speed (safety 0)))
  (%gf-mul-body out a b))

(defun %aes-gf-inv! (x w)
  "X <- X^254 (the multiplicative inverse, 0 for 0) lane-wise.  W holds the scratch
planes :X2 :X3 :X12 :T and the 15-word product buffer :C."
  (let ((x2 (aref w 1)) (x3 (aref w 2)) (x12 (aref w 3)) (tt (aref w 4)) (c (aref w 5)))
    (%aes-gf-mul! x2 x x c)                      ; x^2
    (%aes-gf-mul! x3 x2 x c)                     ; x^3
    (%aes-gf-mul! x12 x3 x3 c)                   ; x^6
    (%aes-gf-mul! x12 x12 x12 c)                 ; x^12
    (%aes-gf-mul! tt x12 x3 c)                   ; x^15
    (dotimes (i 4) (%aes-gf-mul! tt tt tt c))    ; x^240
    (%aes-gf-mul! tt tt x12 c)                   ; x^252
    (%aes-gf-mul! x tt x2 c)                     ; x^254
    x))

(defun %aes-sub-bytes! (s w)
  "S (16 octets) <- SubBytes(S)."
  (let ((p (aref w 0)) (q (aref w 4)))
    (%aes-pack! p s)
    (%aes-gf-inv! p w)
    ;; affine: b'_i = b_i ^ b_(i+4) ^ b_(i+5) ^ b_(i+6) ^ b_(i+7) ^ c_i, c = #x63
    (dotimes (i 8)
      (setf (aref q i) (logxor (aref p i) (aref p (mod (+ i 4) 8)) (aref p (mod (+ i 5) 8))
                               (aref p (mod (+ i 6) 8)) (aref p (mod (+ i 7) 8))
                               (if (logbitp i #x63) +aes-lanes+ 0))))
    (%aes-unpack! s q)))

(defun %aes-inv-sub-bytes! (s w)
  "S (16 octets) <- InvSubBytes(S)."
  (let ((p (aref w 0)) (q (aref w 4)))
    (%aes-pack! q s)
    ;; inverse affine: b_i = b'_(i+2) ^ b'_(i+5) ^ b'_(i+7) ^ d_i, d = #x05
    (dotimes (i 8)
      (setf (aref p i) (logxor (aref q (mod (+ i 2) 8)) (aref q (mod (+ i 5) 8))
                               (aref q (mod (+ i 7) 8))
                               (if (logbitp i #x05) +aes-lanes+ 0))))
    (%aes-gf-inv! p w)
    (%aes-unpack! s p)))

;;; ---------------------------------------------------------------------------
;;; The linear layers (bytes in FIPS 197's column-major order: index r + 4c).
;;; ---------------------------------------------------------------------------

(declaim (inline %xtime))
(defun %xtime (b)
  "2 * B in GF(2^8), with a mask instead of a branch."
  (declare (type (unsigned-byte 8) b))
  (logxor (logand (ash b 1) #xFF) (logand #x1B (- (logand (ash b -7) 1)))))

(defun %aes-shift-rows! (s tmp)
  (replace tmp s)
  (dotimes (r 4 s)
    (dotimes (c 4)
      (setf (aref s (+ r (* 4 c))) (aref tmp (+ r (* 4 (mod (+ c r) 4))))))))

(defun %aes-inv-shift-rows! (s tmp)
  (replace tmp s)
  (dotimes (r 4 s)
    (dotimes (c 4)
      (setf (aref s (+ r (* 4 (mod (+ c r) 4)))) (aref tmp (+ r (* 4 c)))))))

(defun %aes-mix-columns! (s)
  (declare (type %octets s) (optimize speed (safety 0)))
  (dotimes (c 4 s)
    (let* ((o (* 4 c))
           (a0 (aref s o)) (a1 (aref s (+ o 1))) (a2 (aref s (+ o 2))) (a3 (aref s (+ o 3)))
           (d0 (%xtime a0)) (d1 (%xtime a1)) (d2 (%xtime a2)) (d3 (%xtime a3)))
      (setf (aref s o)       (logxor d0 d1 a1 a2 a3)
            (aref s (+ o 1)) (logxor a0 d1 d2 a2 a3)
            (aref s (+ o 2)) (logxor a0 a1 d2 d3 a3)
            (aref s (+ o 3)) (logxor d0 a0 a1 a2 d3)))))

(defun %aes-inv-mix-columns! (s)
  (declare (type %octets s) (optimize speed (safety 0)))
  (flet ((m9  (a2 a4 a8 a) (declare (ignore a2 a4)) (logxor a8 a))
         (m11 (a2 a4 a8 a) (declare (ignore a4)) (logxor a8 a2 a))
         (m13 (a2 a4 a8 a) (declare (ignore a2)) (logxor a8 a4 a))
         (m14 (a2 a4 a8 a) (declare (ignore a)) (logxor a8 a4 a2)))
    (dotimes (c 4 s)
      (let ((o (* 4 c)))
        (let* ((a0 (aref s o)) (a1 (aref s (+ o 1))) (a2 (aref s (+ o 2))) (a3 (aref s (+ o 3)))
               (b0 (%xtime a0)) (c0 (%xtime b0)) (e0 (%xtime c0))
               (b1 (%xtime a1)) (c1 (%xtime b1)) (e1 (%xtime c1))
               (b2 (%xtime a2)) (c2 (%xtime b2)) (e2 (%xtime c2))
               (b3 (%xtime a3)) (c3 (%xtime b3)) (e3 (%xtime c3)))
          (setf (aref s o)
                (logxor (m14 b0 c0 e0 a0) (m11 b1 c1 e1 a1) (m13 b2 c2 e2 a2) (m9 b3 c3 e3 a3))
                (aref s (+ o 1))
                (logxor (m9 b0 c0 e0 a0) (m14 b1 c1 e1 a1) (m11 b2 c2 e2 a2) (m13 b3 c3 e3 a3))
                (aref s (+ o 2))
                (logxor (m13 b0 c0 e0 a0) (m9 b1 c1 e1 a1) (m14 b2 c2 e2 a2) (m11 b3 c3 e3 a3))
                (aref s (+ o 3))
                (logxor (m11 b0 c0 e0 a0) (m13 b1 c1 e1 a1) (m9 b2 c2 e2 a2) (m14 b3 c3 e3 a3))))))))

(defun %aes-add-round-key! (s sched round)
  (declare (type %octets s sched) (type (integer 0 14) round) (optimize speed (safety 0)))
  (let ((o (* 16 round)))
    (dotimes (i 16 s) (setf (aref s i) (logxor (aref s i) (aref sched (+ o i)))))))

;;; ---------------------------------------------------------------------------
;;; Scratch: one bundle per operation, every buffer fixed and wiped on exit.
;;; ---------------------------------------------------------------------------

(defmacro %with-aes-scratch ((w s tmp) &body body)
  "Bind W to the plane scratch (a vector of fixed buffers: P X2 X3 X12 T C), S and TMP
to fixed 16-octet blocks."
  `(gossamer:with-fixed-scratch ((p :fixnums 8) (x2 :fixnums 8) (x3 :fixnums 8) (x12 :fixnums 8)
                              (tt :fixnums 8) (c :fixnums 15) (,s :octets 16) (,tmp :octets 16))
     (let ((,w (vector p x2 x3 x12 tt c)))
       ,@body)))

;;; ---------------------------------------------------------------------------
;;; Keys.
;;; ---------------------------------------------------------------------------

(defstruct (aes-key (:constructor %make-aes-key (rounds schedule)))
  rounds      ; 10, 12 or 14
  schedule)   ; pooled fixed octets, 16 * (rounds + 1)

(defun %aes-expand! (key sched nk rounds w s)
  "FIPS 197 KeyExpansion of KEY (NK words) into SCHED, as bytes."
  (replace sched key :end2 (* 4 nk))
  (let ((rcon 1))
    (loop for i from nk below (* 4 (1+ rounds))
          do (let ((o (* 4 i)) (p (* 4 (1- i))))
               (fill s 0)
               (replace s sched :start2 p :end2 (+ p 4))   ; temp = w[i-1]
               (cond ((zerop (mod i nk))
                      (let ((b0 (aref s 0)))                 ; RotWord
                        (replace s s :start1 0 :end1 3 :start2 1 :end2 4)
                        (setf (aref s 3) b0))
                      (%aes-sub-bytes! s w)
                      (setf (aref s 0) (logxor (aref s 0) rcon)
                            rcon (%xtime rcon)))
                     ((and (> nk 6) (= (mod i nk) 4))
                      (%aes-sub-bytes! s w)))
               (dotimes (j 4)
                 (setf (aref sched (+ o j)) (logxor (aref sched (+ o j (* -4 nk))) (aref s j)))))))
  sched)

(defun make-aes-key (key)
  "An AES key schedule for KEY (16, 24 or 32 bytes, in FIXED memory: it is a secret).
The schedule is a pooled fixed buffer owned by the result; AES-KEY-WIPE returns it."
  (gossamer:check-fixed key "AES key")
  (let* ((nk (ecase (length key) (16 4) (24 6) (32 8)))
         (rounds (+ nk 6))
         (sched (gossamer:acquire :octets (* 16 (1+ rounds)))))
    (%with-aes-scratch (w s tmp)
      (declare (ignore tmp))
      (%aes-expand! key sched nk rounds w s))
    (gossamer:own (%make-aes-key rounds sched) sched)))

(defun aes-key-wipe (k)
  "Wipe K's schedule and return it to the pool.  K is unusable afterwards."
  (when (aes-key-schedule k)
    (gossamer:disown k)
    (gossamer:free (aes-key-schedule k))
    (setf (aes-key-schedule k) nil))
  k)

(defmacro with-aes-key ((var key) &body body)
  "Run BODY with VAR an AES-KEY for KEY, wiped on exit."
  `(let ((,var (make-aes-key ,key)))
     (unwind-protect (progn ,@body) (aes-key-wipe ,var))))

(defun %aes-live (k)
  (or (aes-key-schedule k) (error "use of a wiped AES key")))

;;; ---------------------------------------------------------------------------
;;; The cipher.
;;; ---------------------------------------------------------------------------

(defun %aes-encrypt! (k s w tmp)
  "S (16 fixed octets) <- AES_K(S)."
  (let ((sched (%aes-live k)) (nr (aes-key-rounds k)))
    (%aes-add-round-key! s sched 0)
    (loop for round from 1 below nr
          do (%aes-sub-bytes! s w) (%aes-shift-rows! s tmp) (%aes-mix-columns! s)
             (%aes-add-round-key! s sched round))
    (%aes-sub-bytes! s w) (%aes-shift-rows! s tmp)
    (%aes-add-round-key! s sched nr)))

(defun %aes-decrypt! (k s w tmp)
  "S (16 fixed octets) <- AES_K^-1(S)."
  (let ((sched (%aes-live k)) (nr (aes-key-rounds k)))
    (%aes-add-round-key! s sched nr)
    (loop for round from (1- nr) downto 1
          do (%aes-inv-shift-rows! s tmp) (%aes-inv-sub-bytes! s w)
             (%aes-add-round-key! s sched round) (%aes-inv-mix-columns! s))
    (%aes-inv-shift-rows! s tmp) (%aes-inv-sub-bytes! s w)
    (%aes-add-round-key! s sched 0)))

(defun aes-encrypt-block (k in out &key (in-start 0) (out-start 0))
  "Encrypt the 16-byte block IN[IN-START..] under the AES-KEY K into OUT[OUT-START..]."
  (%with-aes-scratch (w s tmp)
    (replace s in :start2 in-start :end2 (+ in-start 16))
    (%aes-encrypt! k s w tmp)
    (replace out s :start1 out-start))
  out)

(defun aes-decrypt-block (k in out &key (in-start 0) (out-start 0))
  "Decrypt the 16-byte block IN[IN-START..] under the AES-KEY K into OUT[OUT-START..]
(OUT should be fixed when the plaintext is secret)."
  (%with-aes-scratch (w s tmp)
    (replace s in :start2 in-start :end2 (+ in-start 16))
    (%aes-decrypt! k s w tmp)
    (replace out s :start1 out-start))
  out)

;;; ---------------------------------------------------------------------------
;;; Modes (SP 800-38A).
;;; ---------------------------------------------------------------------------

(defun %check-blocks (n what)
  (unless (zerop (mod n 16)) (error "~a: length ~d is not a multiple of 16 (pad first)" what n)))

(defun aes-cbc-encrypt (k iv plaintext &optional out)
  "CBC-encrypt PLAINTEXT (a multiple of 16 bytes; may be fixed) under the AES-KEY K
and the 16-byte IV, into OUT (a fresh vector by default: ciphertext is public).
The chaining value, which mixes in plaintext, stays in fixed scratch."
  (let* ((n (length plaintext)) (out (or out (make-u8v n))))
    (%check-blocks n "aes-cbc-encrypt")
    (%with-aes-scratch (w s tmp)
      (gossamer:with-fixed-scratch ((prev :octets 16))
        (replace prev iv :end2 16)
        (loop for o from 0 below n by 16
              do (dotimes (i 16) (setf (aref s i) (logxor (aref plaintext (+ o i)) (aref prev i))))
                 (%aes-encrypt! k s w tmp)
                 (replace prev s)
                 (replace out s :start1 o))))
    out))

(defun aes-cbc-decrypt-into (k iv ciphertext out &key (start 0))
  "CBC-decrypt CIPHERTEXT (a multiple of 16 bytes) under the AES-KEY K and IV into
OUT at START.  OUT should be fixed: it receives the plaintext.  Returns OUT."
  (let ((n (length ciphertext)))
    (%check-blocks n "aes-cbc-decrypt")
    (%with-aes-scratch (w s tmp)
      (loop for o from 0 below n by 16
            do (replace s ciphertext :start2 o :end2 (+ o 16))
               (%aes-decrypt! k s w tmp)
               (dotimes (i 16)
                 (setf (aref out (+ start o i))
                       (logxor (aref s i) (if (zerop o) (aref iv i) (aref ciphertext (+ (- o 16) i)))))))))
  out)

(defun aes-ctr-xor-into (k counter in out &key (start 0) (end (length in)) (out-start 0))
  "XOR IN[START,END) with the AES-CTR keystream under the AES-KEY K, starting from the
16-byte COUNTER block (incremented as a 128-bit big-endian integer per block), into
OUT at OUT-START.  Encryption and decryption are the same operation.  Returns OUT."
  (%with-aes-scratch (w s tmp)
    (gossamer:with-fixed-scratch ((ctr :octets 16))
      (replace ctr counter :end2 16)
      (loop for o from start below end by 16
            do (replace s ctr)
               (%aes-encrypt! k s w tmp)
               (loop for i from 0 below (min 16 (- end o))
                     do (setf (aref out (+ out-start (- o start) i)) (logxor (aref in (+ o i)) (aref s i))))
               (loop for i from 15 downto 0                ; counter + 1 (public)
                     do (setf (aref ctr i) (logand (1+ (aref ctr i)) #xFF))
                        (unless (zerop (aref ctr i)) (return))))))
  out)

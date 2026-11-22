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
;;; Encryption on bit-planes, all the way through.
;;;
;;; The state is packed into eight 16-lane planes once, goes through every round as planes, and is unpacked
;;; once: ShiftRows is a rotation of each row's lanes, MixColumns a rotation of lanes within each column with
;;; xtime a shuffle of planes, AddRoundKey an XOR with the round key's planes (packed when the key is made).
;;; SubBytes is Boyar and Peralta's circuit for the S-box (J. Boyar, R. Peralta, "A depth-16 circuit for the
;;; AES S-box", 2011): 32 ANDs and 83 XORs on the planes -- no table and no branch, as before, and a small
;;; part of the work of the multiplication chain above (which decryption still uses).
;;; ---------------------------------------------------------------------------

(eval-when (:compile-toplevel :load-toplevel :execute)
(defparameter +aes-sbox-gates+
  '((y14 x3 "^" x5)
    (y13 x0 "^" x6)
    (y9 x0 "^" x3)
    (y8 x0 "^" x5)
    (t0 x1 "^" x2)
    (y1 t0 "^" x7)
    (y4 y1 "^" x3)
    (y12 y13 "^" y14)
    (y2 y1 "^" x0)
    (y5 y1 "^" x6)
    (y3 y5 "^" y8)
    (t1 x4 "^" y12)
    (y15 t1 "^" x5)
    (y20 t1 "^" x1)
    (y6 y15 "^" x7)
    (y10 y15 "^" t0)
    (y11 y20 "^" y9)
    (y7 x7 "^" y11)
    (y17 y10 "^" y11)
    (y19 y10 "^" y8)
    (y16 t0 "^" y11)
    (y21 y13 "^" y16)
    (y18 x0 "^" y16)
    (t2 y12 "&" y15)
    (t3 y3 "&" y6)
    (t4 t3 "^" t2)
    (t5 y4 "&" x7)
    (t6 t5 "^" t2)
    (t7 y13 "&" y16)
    (t8 y5 "&" y1)
    (t9 t8 "^" t7)
    (t10 y2 "&" y7)
    (t11 t10 "^" t7)
    (t12 y9 "&" y11)
    (t13 y14 "&" y17)
    (t14 t13 "^" t12)
    (t15 y8 "&" y10)
    (t16 t15 "^" t12)
    (t17 t4 "^" t14)
    (t18 t6 "^" t16)
    (t19 t9 "^" t14)
    (t20 t11 "^" t16)
    (t21 t17 "^" y20)
    (t22 t18 "^" y19)
    (t23 t19 "^" y21)
    (t24 t20 "^" y18)
    (t25 t21 "^" t22)
    (t26 t21 "&" t23)
    (t27 t24 "^" t26)
    (t28 t25 "&" t27)
    (t29 t28 "^" t22)
    (t30 t23 "^" t24)
    (t31 t22 "^" t26)
    (t32 t31 "&" t30)
    (t33 t32 "^" t24)
    (t34 t23 "^" t33)
    (t35 t27 "^" t33)
    (t36 t24 "&" t35)
    (t37 t36 "^" t34)
    (t38 t27 "^" t36)
    (t39 t29 "&" t38)
    (t40 t25 "^" t39)
    (t41 t40 "^" t37)
    (t42 t29 "^" t33)
    (t43 t29 "^" t40)
    (t44 t33 "^" t37)
    (t45 t42 "^" t41)
    (z0 t44 "&" y15)
    (z1 t37 "&" y6)
    (z2 t33 "&" x7)
    (z3 t43 "&" y16)
    (z4 t40 "&" y1)
    (z5 t29 "&" y7)
    (z6 t42 "&" y11)
    (z7 t45 "&" y17)
    (z8 t41 "&" y10)
    (z9 t44 "&" y12)
    (z10 t37 "&" y3)
    (z11 t33 "&" y4)
    (z12 t43 "&" y13)
    (z13 t40 "&" y5)
    (z14 t29 "&" y2)
    (z15 t42 "&" y9)
    (z16 t45 "&" y14)
    (z17 t41 "&" y8)
    (t46 z15 "^" z16)
    (t47 z10 "^" z11)
    (t48 z5 "^" z13)
    (t49 z9 "^" z10)
    (t50 z2 "^" z12)
    (t51 z2 "^" z5)
    (t52 z7 "^" z8)
    (t53 z0 "^" z3)
    (t54 z6 "^" z7)
    (t55 z16 "^" z17)
    (t56 z12 "^" t48)
    (t57 t50 "^" t53)
    (t58 z4 "^" t46)
    (t59 z3 "^" t54)
    (t60 t46 "^" t57)
    (t61 z14 "^" t57)
    (t62 t52 "^" t58)
    (t63 t49 "^" t58)
    (t64 z4 "^" t59)
    (t65 t61 "^" t62)
    (t66 z1 "^" t63)
    (s0 t59 "^" t63)
    (s6 t56 "^~" t62)
    (s7 t48 "^~" t60)
    (t67 t64 "^" t65)
    (s3 t53 "^" t66)
    (s4 t51 "^" t66)
    (s5 t47 "^" t65)
    (s1 t64 "^~" s3)
    (s2 t55 "^~" t67))
  "Boyar-Peralta's S-box: (OUT A OP B), OP ^ (xor), & (and) or ^~ (xor with the complement of B).  The
inputs X0..X7 are a byte's bits from the most significant; the outputs S0..S7 likewise."))

(defmacro %aes-sbox-planes! (b0 b1 b2 b3 b4 b5 b6 b7)
  "SubBytes on the planes B0..B7 (B0 the least significant bit of every byte), in place."
  (let ((vars (append '(x0 x1 x2 x3 x4 x5 x6 x7) (mapcar #'first +aes-sbox-gates+))))
    `(let* ((x0 ,b7) (x1 ,b6) (x2 ,b5) (x3 ,b4) (x4 ,b3) (x5 ,b2) (x6 ,b1) (x7 ,b0)
            ,@(loop for (out a op b) in +aes-sbox-gates+
                    collect `(,out ,(cond ((string= op "^") `(logxor ,a ,b))
                                          ((string= op "&") `(logand ,a ,b))
                                          (t `(logxor ,a (logxor ,b +aes-lanes+)))))))
       (declare (type (unsigned-byte 16) ,@vars) (ignorable ,@vars))
       (setf ,b7 s0 ,b6 s1 ,b5 s2 ,b4 s3 ,b3 s4 ,b2 s5 ,b1 s6 ,b0 s7))))

(declaim (inline %rotr16 %aes-sr-plane %aes-col-rot1 %aes-col-rot2 %aes-col-rot3))
(defun %rotr16 (v k)
  (declare (type (unsigned-byte 16) v) (type (integer 1 15) k))
  (logand #xFFFF (logior (ash v (- k)) (ash v (- 16 k)))))

(defun %aes-sr-plane (x)
  "ShiftRows on one plane: lane r+4c is the byte at row r, column c; row r turns left by r columns."
  (declare (type (unsigned-byte 16) x))
  (logior (logand x #x1111) (%rotr16 (logand x #x2222) 4) (%rotr16 (logand x #x4444) 8)
          (%rotr16 (logand x #x8888) 12)))

;; each lane takes the lane K rows below it in its column, wrapping: row r gets row r+K
(defun %aes-col-rot1 (x)
  (declare (type (unsigned-byte 16) x))
  (logior (logand (ash x -1) #x7777) (logand (ash x 3) #x8888)))
(defun %aes-col-rot2 (x)
  (declare (type (unsigned-byte 16) x))
  (logior (logand (ash x -2) #x3333) (logand (ash x 2) #xCCCC)))
(defun %aes-col-rot3 (x)
  (declare (type (unsigned-byte 16) x))
  (logior (logand (ash x -3) #x1111) (logand (ash x 1) #xEEEE)))

(defun %aes-encrypt-planes! (p rk nr)
  "P (8 planes) <- AES encryption of NR rounds under the round-key planes RK (8 a round)."
  (declare (type (simple-array fixnum (*)) p rk) (type (integer 10 14) nr) (optimize speed (safety 0)))
  (let ((b0 (aref p 0)) (b1 (aref p 1)) (b2 (aref p 2)) (b3 (aref p 3))
        (b4 (aref p 4)) (b5 (aref p 5)) (b6 (aref p 6)) (b7 (aref p 7)))
    (declare (type (unsigned-byte 16) b0 b1 b2 b3 b4 b5 b6 b7))
    (macrolet ((ark (round)
                 `(let ((o (* 8 ,round)))
                    (declare (type fixnum o))
                    ,@(loop for b in '(b0 b1 b2 b3 b4 b5 b6 b7) for i from 0
                            collect `(setf ,b (logxor ,b (the (unsigned-byte 16) (aref rk (+ o ,i))))))))
               (sr () `(setf ,@(loop for b in '(b0 b1 b2 b3 b4 b5 b6 b7) append `(,b (%aes-sr-plane ,b)))))
               (mc ()
                 ;; each byte <- 2a + 3a1 + a2 + a3 (a1 the next row's, and so on) = xtime(a + a1) + a1 + a2 + a3
                 (let ((bs '(b0 b1 b2 b3 b4 b5 b6 b7))
                       (us '(u0 u1 u2 u3 u4 u5 u6 u7))
                       (rs '(r0 r1 r2 r3 r4 r5 r6 r7)))
                   `(let* (,@(loop for b in bs for u in us for r in rs
                                   append `((,r (logxor (%aes-col-rot1 ,b) (%aes-col-rot2 ,b) (%aes-col-rot3 ,b)))
                                            (,u (logxor ,b (%aes-col-rot1 ,b))))))
                      (declare (type (unsigned-byte 16) ,@us ,@rs))
                      ;; xtime on planes: bit i <- bit i-1, and the bit shifted out (u7) folds back as #x1B
                      (setf b0 (logxor u7 r0)
                            b1 (logxor u0 u7 r1)
                            b2 (logxor u1 r2)
                            b3 (logxor u2 u7 r3)
                            b4 (logxor u3 u7 r4)
                            b5 (logxor u4 r5)
                            b6 (logxor u5 r6)
                            b7 (logxor u6 r7))))))
      (ark 0)
      (loop for round of-type fixnum from 1 below nr
            do (%aes-sbox-planes! b0 b1 b2 b3 b4 b5 b6 b7) (sr) (mc) (ark round))
      (%aes-sbox-planes! b0 b1 b2 b3 b4 b5 b6 b7) (sr) (ark nr))
    (setf (aref p 0) b0 (aref p 1) b1 (aref p 2) b2 (aref p 3) b3
          (aref p 4) b4 (aref p 5) b5 (aref p 6) b6 (aref p 7) b7)
    p))

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

(defstruct (aes-key (:constructor %make-aes-key (rounds schedule planes)))
  rounds      ; 10, 12 or 14
  schedule    ; pooled fixed octets, 16 * (rounds + 1)
  planes)     ; the same round keys as bit-planes (encryption's): pooled fixed fixnums, 8 * (rounds + 1)

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
         (sched (gossamer:acquire :octets (* 16 (1+ rounds))))
         (planes (gossamer:acquire :fixnums (* 8 (1+ rounds)))))
    (%with-aes-scratch (w s tmp)
      (declare (ignore tmp))
      (%aes-expand! key sched nk rounds w s)
      (let ((p (aref w 0)))                    ; each round key as planes too
        (dotimes (r (1+ rounds))
          (replace s sched :start2 (* 16 r) :end2 (* 16 (1+ r)))
          (%aes-pack! p s)
          (replace planes p :start1 (* 8 r)))))
    (gossamer:own (%make-aes-key rounds sched planes) sched planes)))

(defun aes-key-wipe (k)
  "Wipe K's schedule and return it to the pool.  K is unusable afterwards."
  (when (aes-key-schedule k)
    (gossamer:disown k)
    (gossamer:free (aes-key-schedule k))
    (gossamer:free (aes-key-planes k))
    (setf (aes-key-schedule k) nil (aes-key-planes k) nil))
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
  "S (16 fixed octets) <- AES_K(S): packed into planes, every round there, unpacked."
  (declare (ignore tmp))
  (%aes-live k)
  (let ((p (aref w 0)))
    (%aes-pack! p s)
    (%aes-encrypt-planes! p (aes-key-planes k) (aes-key-rounds k))
    (%aes-unpack! s p)))

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

;;; ---------------------------------------------------------------------------
;;; Running streams: CTR and CFB-128 whose position carries across calls.
;;; ---------------------------------------------------------------------------
;;; A protocol that encrypts a stream in pieces of any size -- Tor's relay cells (CTR),
;;; frp's connection (CFB, as Go's crypto/cipher does it: full-block feedback, a
;;; partial block continuing on the next call) -- keeps one of these per direction.
;;; The register and the unused keystream are secret, so they are fixed buffers owned
;;; by the stream; AES-STREAM-WIPE returns them (and leaves the key to its owner).

(defstruct (aes-stream (:constructor %make-aes-stream (key mode reg ks)))
  key mode reg ks (pos 16 :type (integer 0 16)))

(defun %make-stream (k mode iv)
  (let ((reg (gossamer:acquire :octets 16)) (ks (gossamer:acquire :octets 16)))
    (replace reg iv :end2 16)
    (let ((st (%make-aes-stream k mode reg ks)))
      (gossamer:own st reg ks)
      st)))

;;; --- AES-CMAC (RFC 4493; NIST SP 800-38B) ----------------------------------
;;; SMB 3.0's message signing (MS-SMB2 3.1.4.1).

(defun %cmac-dbl (b)
  "B (16 bytes) doubled in GF(2^128): shifted left one bit, #x87 folded in on a carry."
  (let ((out (make-u8v 16)) (carry (ldb (byte 1 7) (aref b 0))))
    (dotimes (i 16)
      (setf (aref out i) (logand #xff (logior (ash (aref b i) 1)
                                              (if (< i 15) (ldb (byte 1 7) (aref b (1+ i))) 0)))))
    (when (= carry 1) (setf (aref out 15) (logxor (aref out 15) #x87)))
    out))

(defun aes-cmac (k msg &key (end (length msg)))
  "The 16-byte AES-CMAC of the byte vector MSG (up to END) under the AES-KEY K (MAKE-AES-KEY).  MSG is
   read in place; the cipher's scratch is taken once for the whole message, not per block."
  (let* ((l (make-u8v 16)))
    (aes-encrypt-block k (make-u8v 16) l)
    (let* ((k1 (%cmac-dbl l)) (k2 (%cmac-dbl k1))
           (n end)
           (blocks (max 1 (ceiling n 16)))
           (complete (and (plusp n) (zerop (mod n 16))))
           (x (make-u8v 16)))
      (%with-aes-scratch (w y tmp)
        ;; Y is the running state: X xor the block, encrypted in place
        (dotimes (bi blocks)
          (let ((last (= bi (1- blocks))) (off (* 16 bi)))
            (if (and (not last) (typep msg '(simple-array (unsigned-byte 8) (*))))
                (let ((msg msg))
                  (declare (type (simple-array (unsigned-byte 8) (*)) msg))
                  (dotimes (i 16) (setf (aref y i) (logxor (aref x i) (aref msg (+ off i))))))
                (dotimes (i 16)
                  (let* ((j (+ off i))
                         (m (cond ((< j n) (aref msg j))
                                  ((= j n) #x80)          ; the padding a short last block gets
                                  (t 0))))
                    (setf (aref y i)
                          (logxor (aref x i) m (if last (aref (if complete k1 k2) i) 0))))))
            (%aes-encrypt! k y w tmp)
            (replace x y))))
      x)))

(defun make-aes-ctr-stream (k iv)
  "A CTR stream under the AES-KEY K from the 16-byte initial counter IV (a 128-bit
   big-endian integer, incremented per block)."
  (%make-stream k :ctr iv))

(defun make-aes-cfb-stream (k iv direction)
  "A CFB-128 stream under the AES-KEY K from the 16-byte IV; DIRECTION is :ENCRYPT or
   :DECRYPT."
  (%make-stream k (ecase direction (:encrypt :cfb-enc) (:decrypt :cfb-dec)) iv))

(defun aes-stream-xor (st in &key (start 0) (end (length in)) (out in) (out-start start))
  "Run IN[START, END) through the stream ST into OUT at OUT-START (by default in place),
   continuing from wherever the previous call stopped.  Returns OUT."
  (let ((k (aes-stream-key st)) (reg (aes-stream-reg st)) (ks (aes-stream-ks st))
        (mode (aes-stream-mode st)) (pos (aes-stream-pos st)))
    (%with-aes-scratch (w s tmp)
      (loop for i from start below end
            for o from out-start
            do (when (= pos 16)                      ; next block of keystream
                 (replace s reg) (%aes-encrypt! k s w tmp) (replace ks s) (setf pos 0)
                 (when (eq mode :ctr)
                   (loop for j from 15 downto 0
                         do (setf (aref reg j) (logand (1+ (aref reg j)) #xff))
                            (unless (zerop (aref reg j)) (return)))))
               (let* ((x (aref in i)) (y (logxor x (aref ks pos))))
                 ;; CFB feeds the CIPHERTEXT back: the output when encrypting, the input
                 ;; when decrypting.  Read X before writing, so IN may be OUT.
                 (case mode
                   (:cfb-enc (setf (aref reg pos) y))
                   (:cfb-dec (setf (aref reg pos) x)))
                 (setf (aref out o) y)
                 (incf pos))))
    (setf (aes-stream-pos st) pos)
    out))

(defun aes-stream-wipe (st)
  "Wipe ST's register and keystream and return them to the pool."
  (when (aes-stream-reg st)
    (gossamer:disown st)
    (gossamer:free (aes-stream-reg st)) (gossamer:free (aes-stream-ks st))
    (setf (aes-stream-reg st) nil (aes-stream-ks st) nil))
  st)

;;;; fe25519.lisp — constant-time GF(2^255-19) field in radix-2^51 limbs.
;;;;
;;;; A field element is 5 unsigned limbs h0..h4 with value
;;;;   h0 + h1*2^51 + h2*2^102 + h3*2^153 + h4*2^204.
;;;; Reduced limbs are < 2^51; intermediate limbs stay < 2^54 so a 5-term
;;;; product accumulates below 2^128 (the width of the modus %mul128/%addc
;;;; intrinsic that replaces the portable multiply).  Every operation runs a
;;;; FIXED sequence with no data-dependent branch, index, or iteration count, so
;;;; the control/data flow is constant-time; the portable limb multiply itself is
;;;; ordinary CL `*` (uniform in structure — the intrinsic closes the last
;;;; instruction-level gap).  The big-integer field in x25519.lisp is the
;;;; differential oracle: fe ops are checked against it on random inputs.

(in-package #:natrium)

(defconstant +fe-mask+ #x7ffffffffffff "2^51 - 1.")

;; Portable reference: limbs are CL integers.  Reduced limbs are < 2^51 (u64 in
;; the native backend); intermediate products are ~110-bit (u128 in the native
;; backend), which is why the store type is general here rather than (u-b 64).
(deftype fe () '(simple-array t (5)))

(declaim (inline fe-zero fe-one fe-copy fe->integer))
(defun fe-zero () (make-array 5 :initial-element 0))
(defun fe-one ()
  (let ((h (fe-zero))) (setf (aref h 0) 1) h))
(defun fe-copy (f)
  (let ((h (fe-zero))) (replace h f) h))

;;; --- conversion (also the oracle bridge) ---------------------------------
(defun integer->fe (n)
  "Split a field integer N (0 <= N < 2^255) into radix-2^51 limbs."
  (let ((h (fe-zero)))
    (dotimes (i 5 h)
      (setf (aref h i) (logand (ash n (* -51 i)) +fe-mask+)))))

(defun fe->integer (f)
  "Reconstruct the (canonical after fe-freeze) integer value of F."
  (+ (aref f 0) (ash (aref f 1) 51) (ash (aref f 2) 102)
     (ash (aref f 3) 153) (ash (aref f 4) 204)))

(defun fe25519-frombytes (bytes)
  "Load 32 little-endian BYTES into a field element (masking bit 255)."
  (declare (type u8v bytes))
  (integer->fe (logand (le->uint bytes 0 32) (1- (ash 1 255)))))

;;; --- add / sub -----------------------------------------------------------
(defun fe25519-add (f g)
  "Limb-wise add (result limbs < 2^52; caller keeps inputs reduced)."
  (let ((h (fe-zero)))
    (dotimes (i 5 h) (setf (aref h i) (+ (aref f i) (aref g i))))))

;; 2*p in limb form: [2^52-38, 2^52-2, 2^52-2, 2^52-2, 2^52-2].  Adding this
;; before subtracting keeps every limb positive without a branch.
(defun fe25519-sub (f g)
  "Constant-time F - G mod p (inputs must be reduced, < 2^51)."
  (let ((h (fe-zero)))
    (setf (aref h 0) (- (+ (aref f 0) #xfffffffffffda) (aref g 0)))
    (loop for i from 1 below 5 do
      (setf (aref h i) (- (+ (aref f i) #xffffffffffffe) (aref g i))))
    (fe25519-carry h)))

;;; --- carry propagation ---------------------------------------------------
(defun fe25519-carry (h)
  "Reduce H's limbs to < 2^51 (one full carry chain + a short second pass),
   folding the 2^255 = 19 wrap.  Returns H (mutated)."
  (macrolet ((step1 (i j) `(let ((c (ash (aref h ,i) -51)))
                             (setf (aref h ,i) (logand (aref h ,i) +fe-mask+))
                             (incf (aref h ,j) c))))
    (step1 0 1) (step1 1 2) (step1 2 3) (step1 3 4)
    (let ((c (ash (aref h 4) -51)))
      (setf (aref h 4) (logand (aref h 4) +fe-mask+))
      (incf (aref h 0) (* 19 c)))
    (step1 0 1)
    h))

;;; --- multiply / square ---------------------------------------------------
(defun fe25519-mul (f g)
  "Constant-time F * G mod p."
  (let ((f0 (aref f 0)) (f1 (aref f 1)) (f2 (aref f 2)) (f3 (aref f 3)) (f4 (aref f 4))
        (g0 (aref g 0)) (g1 (aref g 1)) (g2 (aref g 2)) (g3 (aref g 3)) (g4 (aref g 4)))
    (let* ((g1_19 (* 19 g1)) (g2_19 (* 19 g2)) (g3_19 (* 19 g3)) (g4_19 (* 19 g4))
           (h (fe-zero)))
      (setf (aref h 0) (+ (* f0 g0) (* f1 g4_19) (* f2 g3_19) (* f3 g2_19) (* f4 g1_19))
            (aref h 1) (+ (* f0 g1) (* f1 g0)    (* f2 g4_19) (* f3 g3_19) (* f4 g2_19))
            (aref h 2) (+ (* f0 g2) (* f1 g1)    (* f2 g0)    (* f3 g4_19) (* f4 g3_19))
            (aref h 3) (+ (* f0 g3) (* f1 g2)    (* f2 g1)    (* f3 g0)    (* f4 g4_19))
            (aref h 4) (+ (* f0 g4) (* f1 g3)    (* f2 g2)    (* f3 g1)    (* f4 g0)))
      (fe25519-carry h))))

(defun fe25519-sq (f) (fe25519-mul f f))

(defun fe25519-mul121666 (f)
  "F * 121665 mod p (the Montgomery-ladder constant a24)."
  (let ((h (fe-zero)))
    (dotimes (i 5) (setf (aref h i) (* 121665 (aref f i))))
    (fe25519-carry h)))

;;; --- exponentiation / inversion ------------------------------------------
;;; The exponent E is a fixed public constant, so square-and-multiply over its
;;; bits runs the same operation sequence every call — constant-time in Z.
(defun fe25519-pow (z e)
  "Z^E mod p by square-and-multiply over the fixed public exponent E."
  (let ((result (fe-one)) (base (fe-copy z)))
    (dotimes (i (integer-length e) result)
      (when (logbitp i e) (setf result (fe25519-mul result base)))
      (setf base (fe25519-sq base)))))

(defun fe25519-invert (z)
  "Multiplicative inverse of Z (= Z^(p-2))."
  (fe25519-pow z (- *p25519* 2)))

(defun fe25519-cmov (bit f g)
  "If BIT (0/1) is 1, copy G's limbs into F; branch-free.  Mutates F."
  (let ((mask (- (logand bit 1))))              ; 0 or all-ones
    (dotimes (i 5)
      (setf (aref f i) (logxor (aref f i) (logand mask (logxor (aref f i) (aref g i))))))))

;;; --- constant-time swap + freeze/serialize -------------------------------
(defun fe25519-cswap (swap f g)
  "If SWAP (0/1) is 1, exchange the limbs of F and G; branch-free.  Mutates."
  (let ((mask (- (logand swap 1))))            ; 0 or all-ones
    (dotimes (i 5)
      (let ((tmp (logand mask (logxor (aref f i) (aref g i)))))
        (setf (aref f i) (logxor (aref f i) tmp)
              (aref g i) (logxor (aref g i) tmp))))))

(defun fe25519-tobytes (f)
  "Freeze F to its canonical residue in [0,p) and serialize to 32 LE bytes.
   After fe25519-carry the value is < 2^255 = p+19, so it is in [0, p+18] and a
   fixed pair of conditional subtractions canonicalizes it (same shape as the
   Barrett/Poly1305 finalize).  NOTE: fe25519-carry must NOT be reused for the
   subtract — its 2^255->19 fold is a *reduction*, not a freeze, and turns a
   non-canonical p (a low-order-point zero) into 19 rather than 0."
  (let ((h (fe-copy f)))
    (fe25519-carry h)
    (let ((v (fe->integer h)) (p *p25519*))
      (when (>= v p) (decf v p))
      (when (>= v p) (decf v p))
      (uint->le v 32))))

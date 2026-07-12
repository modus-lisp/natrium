;;;; x25519-ct.lisp — constant-time X25519 over the fe25519 limb field.
;;;;
;;;; The Montgomery ladder (RFC 7748 5) with a fixed 255-iteration count and a
;;;; branchless fe25519-cswap: no branch, index, or loop bound depends on the
;;;; secret scalar, and every field operation is the fixed-shape fe25519 routine.
;;;; This is the public X25519; x25519-reference (x25519.lisp) is the big-integer
;;;; oracle it is differentially checked against.

(in-package #:natrium)

(defun x25519 (scalar u-bytes)
  "X25519(SCALAR, U): 32-byte little-endian SCALAR and U → the 32-byte
   little-endian u-coordinate of SCALAR*U.  Constant-time in SCALAR."
  (declare (type u8v scalar u-bytes))
  (let* ((k (let ((c (copy-seq scalar)))              ; clamp (does not mutate input)
              (setf (aref c 0)  (logand (aref c 0) 248)
                    (aref c 31) (logior (logand (aref c 31) 127) 64))
              (le->uint c 0 32)))
         (x1 (fe25519-frombytes u-bytes))
         (x2 (fe-one)) (z2 (fe-zero))
         (x3 (fe-copy x1)) (z3 (fe-one))
         (swap 0))
    (loop for tt from 254 downto 0 do
      (let ((kt (logand (ash k (- tt)) 1)))
        (setf swap (logxor swap kt))
        (fe25519-cswap swap x2 x3)
        (fe25519-cswap swap z2 z3)
        (setf swap kt)
        (let* ((a  (fe25519-add x2 z2)) (aa (fe25519-sq a))
               (b  (fe25519-sub x2 z2)) (bb (fe25519-sq b))
               (e  (fe25519-sub aa bb))
               (c  (fe25519-add x3 z3)) (d  (fe25519-sub x3 z3))
               (da (fe25519-mul d a))  (cb (fe25519-mul c b)))
          (setf x3 (fe25519-sq (fe25519-add da cb))
                z3 (fe25519-mul x1 (fe25519-sq (fe25519-sub da cb)))
                x2 (fe25519-mul aa bb)
                z2 (fe25519-mul e (fe25519-add aa (fe25519-mul121666 e)))))))
    (fe25519-cswap swap x2 x3)
    (fe25519-cswap swap z2 z3)
    (fe25519-tobytes (fe25519-mul x2 (fe25519-invert z2)))))

(defun x25519-base (scalar)
  "SCALAR * basepoint (u = 9): the public key / DH share of a private SCALAR."
  (let ((nine (make-u8v 32)))
    (setf (aref nine 0) 9)
    (x25519 scalar nine)))

(defun x25519-keypair ()
  "Fresh X25519 keypair from the CSPRNG.  Returns (values PRIVATE-32 PUBLIC-32)."
  (let ((sk (random-bytes 32)))
    (values sk (x25519-base sk))))

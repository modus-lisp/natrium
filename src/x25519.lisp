;;;; x25519.lisp — X25519 Diffie-Hellman on Curve25519 (RFC 7748).
;;;;
;;;; Portable big-integer reference: field elements are CL integers reduced mod
;;;; p = 2^255-19.  Exact and gated against the RFC 7748 vectors (which are
;;;; ground truth), and the differential oracle for a future constant-time
;;;; 5x51-bit-limb backend.  The Montgomery ladder already uses a branchless
;;;; cswap and a fixed 255-iteration count, so its control flow is constant-time;
;;;; what is NOT yet constant-time is the big-integer field arithmetic itself
;;;; (variable-time multiply/reduce).  The scalar is secret, so the limb backend
;;;; is required before this guards real keys — see the roadmap.

(in-package #:natrium)

(defparameter *p25519* (- (ash 1 255) 19)
  "The Curve25519 field prime, 2^255 - 19.")

(defun fe-pow (base e)
  "BASE^E mod *p25519* by square-and-multiply (E public: only used for the fixed
   inversion exponent p-2)."
  (let ((p *p25519*) (result 1) (b (mod base *p25519*)))
    (loop while (> e 0) do
      (when (oddp e) (setf result (mod (* result b) p)))
      (setf b (mod (* b b) p) e (ash e -1)))
    result))

(defun fe-inv (z)
  "Multiplicative inverse of Z mod p = Z^(p-2)."
  (fe-pow z (- *p25519* 2)))

(defun x25519 (scalar u-bytes)
  "X25519(SCALAR, U): the Montgomery ladder (RFC 7748 5).  SCALAR and U-BYTES are
   32-byte little-endian vectors; returns the 32-byte little-endian u-coordinate
   of SCALAR*U.  SCALAR is clamped and U's high bit masked per the spec."
  (declare (type u8v scalar u-bytes))
  (let* ((p *p25519*)
         (k (let ((c (copy-seq scalar)))            ; clamp (does not mutate input)
              (setf (aref c 0)  (logand (aref c 0) 248)
                    (aref c 31) (logior (logand (aref c 31) 127) 64))
              (le->uint c 0 32)))
         (x1 (mod (logand (le->uint u-bytes 0 32) (1- (ash 1 255))) p)) ; mask bit 255
         (x2 1) (z2 0) (x3 x1) (z3 1) (swap 0))
    (macrolet ((f+ (a b) `(mod (+ ,a ,b) p))
               (f- (a b) `(mod (- ,a ,b) p))
               (f* (a b) `(mod (* ,a ,b) p))
               (fsq (a) `(let ((v ,a)) (mod (* v v) p)))
               (cswap (bit u w)                      ; branchless conditional swap
                 `(let ((dummy (logand (- ,bit) (logxor ,u ,w))))
                    (setf ,u (logxor ,u dummy) ,w (logxor ,w dummy)))))
      (loop for tt from 254 downto 0 do
        (let ((kt (logand (ash k (- tt)) 1)))
          (setf swap (logxor swap kt))
          (cswap swap x2 x3)
          (cswap swap z2 z3)
          (setf swap kt)
          (let* ((a  (f+ x2 z2)) (aa (fsq a))
                 (b  (f- x2 z2)) (bb (fsq b))
                 (e  (f- aa bb))
                 (c  (f+ x3 z3)) (d  (f- x3 z3))
                 (da (f* d a))   (cb (f* c b)))
            (setf x3 (fsq (f+ da cb))
                  z3 (f* x1 (fsq (f- da cb)))
                  x2 (f* aa bb)
                  z2 (f* e (f+ aa (f* 121665 e)))))))
      (cswap swap x2 x3)
      (cswap swap z2 z3)
      (uint->le (f* x2 (fe-inv z2)) 32))))

(defun x25519-base (scalar)
  "SCALAR * basepoint (u = 9): the public key / DH share of a private SCALAR."
  (let ((nine (make-u8v 32)))
    (setf (aref nine 0) 9)
    (x25519 scalar nine)))

(defun x25519-keypair ()
  "Fresh X25519 keypair from the CSPRNG.  Returns (values PRIVATE-32 PUBLIC-32)."
  (let ((sk (random-bytes 32)))
    (values sk (x25519-base sk))))

;;;; ed25519.lisp — Ed25519 signatures (RFC 8032), pure Common Lisp.
;;;;
;;;; Edwards-curve signatures over edwards25519 (-x^2 + y^2 = 1 + d x^2 y^2 mod
;;;; 2^255-19), with SHA-512 as the hash.  Signing is DETERMINISTIC — the per-
;;;; message nonce r = SHA-512(prefix ‖ M) is derived from the key and message,
;;;; never from an RNG — so the catastrophic ECDSA nonce-reuse failure class
;;;; cannot occur here by construction.
;;;;
;;;; Portable big-integer reference (field elements are CL integers, points in
;;;; extended twisted-Edwards coordinates via the unified addition law).  Field
;;;; arithmetic is variable-time; scalar multiplication is a plain double-and-add
;;;; and thus secret-dependent — this is the differential oracle for a future
;;;; constant-time limb backend, not yet a side-channel-hardened signer.  It
;;;; reuses fe-inv / fe-pow / *p25519* from x25519.lisp.

(in-package #:natrium)

(declaim (inline fadd fsub fmul))
(defun fadd (a b) (mod (+ a b) *p25519*))
(defun fsub (a b) (mod (- a b) *p25519*))
(defun fmul (a b) (mod (* a b) *p25519*))

(defparameter *l25519*
  (+ (ash 1 252) 27742317777372353535851937790883648493)
  "Order of the edwards25519 base-point group.")
(defparameter *d25519* (fmul -121665 (fe-inv 121666))
  "Edwards curve constant d = -121665/121666 mod p.")
(defparameter *sqrtm1* (fe-pow 2 (/ (1- *p25519*) 4))
  "A square root of -1 mod p (= 2^((p-1)/4)).")

;;; Points in extended coordinates (X,Y,Z,T): x = X/Z, y = Y/Z, xy = T/Z.
(defstruct (ept (:constructor ept (x y z w)) (:conc-name ept-))
  x y z w)

(defun ed-identity () (ept 0 1 1 0))

(defun ed-add (p1 p2)
  "Unified twisted-Edwards addition (a = -1); correct for P1 = P2 too."
  (let* ((a (fmul (fsub (ept-y p1) (ept-x p1)) (fsub (ept-y p2) (ept-x p2))))
         (b (fmul (fadd (ept-y p1) (ept-x p1)) (fadd (ept-y p2) (ept-x p2))))
         (c (fmul (fmul (ept-w p1) (fmul 2 *d25519*)) (ept-w p2)))
         (d (fmul (fmul (ept-z p1) 2) (ept-z p2)))
         (e (fsub b a)) (f (fsub d c)) (g (fadd d c)) (h (fadd b a)))
    ;; X3=E*F  Y3=G*H  Z3=F*G  T3=E*H
    (ept (fmul e f) (fmul g h) (fmul f g) (fmul e h))))

(defun ed-mul (n p)
  "Scalar multiple [N]P by double-and-add (variable-time; N may be secret)."
  (let ((r (ed-identity)))
    (loop for i from 255 downto 0 do
      (setf r (ed-add r r))
      (when (logbitp i n) (setf r (ed-add r p))))
    r))

(defun ed-point-equal (p q)
  "Projective equality: cross-multiply the affine coordinates."
  (and (= (fmul (ept-x p) (ept-z q)) (fmul (ept-x q) (ept-z p)))
       (= (fmul (ept-y p) (ept-z q)) (fmul (ept-y q) (ept-z p)))))

(defun ed-recover-x (y sign)
  "Recover x for the curve point with the given Y and SIGN bit (0/1); NIL if Y is
   not a valid x-coordinate's partner."
  (let* ((p *p25519*)
         (y2 (fmul y y))
         (u (fsub y2 1))                       ; y^2 - 1
         (v (fadd (fmul *d25519* y2) 1))       ; d y^2 + 1
         (v3 (fmul (fmul v v) v))
         (v7 (fmul (fmul v3 v3) v))
         (x (fmul (fmul u v3) (fe-pow (fmul u v7) (/ (- p 5) 8)))))
    (let ((vx2 (fmul v (fmul x x))))
      (cond ((= vx2 (mod u p)))                          ; x^2 = u/v: done
            ((= vx2 (mod (- u) p)) (setf x (fmul x *sqrtm1*)))  ; times sqrt(-1)
            (t (return-from ed-recover-x nil))))
    (when (and (zerop x) (= sign 1)) (return-from ed-recover-x nil))
    (unless (= (logand x 1) sign) (setf x (fsub 0 x)))
    x))

(defparameter *ed-base*
  (let* ((by (fmul 4 (fe-inv 5)))              ; base-point y = 4/5
         (bx (ed-recover-x by 0)))
    (ept bx by 1 (fmul bx by)))
  "The edwards25519 base point in extended coordinates.")

(defun ed-encode (p)
  "Encode point P as 32 little-endian bytes: y with x's low bit in the MSB."
  (let* ((zinv (fe-inv (ept-z p)))
         (x (fmul (ept-x p) zinv))
         (y (fmul (ept-y p) zinv))
         (out (uint->le y 32)))
    (setf (aref out 31) (logior (aref out 31) (ash (logand x 1) 7)))
    out))

(defun ed-decode (bytes)
  "Decode 32 bytes to a point, or NIL if invalid."
  (declare (type u8v bytes))
  (let ((sign (ldb (byte 1 7) (aref bytes 31)))
        (y (logand (le->uint bytes 0 32) (1- (ash 1 255)))))
    (when (>= y *p25519*) (return-from ed-decode nil))
    (let ((x (ed-recover-x y sign)))
      (when (null x) (return-from ed-decode nil))
      (ept x y 1 (fmul x y)))))

(defun ed-clamp-scalar (h32)
  "Clamp the low half of the SHA-512 key hash into the private scalar integer."
  (let ((c (copy-seq h32)))
    (setf (aref c 0)  (logand (aref c 0) 248)
          (aref c 31) (logior (logand (aref c 31) 127) 64))
    (le->uint c 0 32)))

(defun ed25519-public-key (sk)
  "32-byte Ed25519 public key for a 32-byte secret key SK."
  (declare (type u8v sk))
  (let* ((h (sha512 sk))
         (a (ed-clamp-scalar (subseq h 0 32))))
    (ed-encode (ed-mul a *ed-base*))))

(defun ed25519-sign (sk message)
  "Deterministic Ed25519 signature (64 bytes) of MESSAGE under secret key SK."
  (declare (type u8v sk message))
  (let* ((h (sha512 sk))
         (a (ed-clamp-scalar (subseq h 0 32)))
         (prefix (subseq h 32 64))
         (pk (ed-encode (ed-mul a *ed-base*)))
         (r (mod (le->uint (sha512 (u8cat prefix message)) 0 64) *l25519*))
         (rp (ed-encode (ed-mul r *ed-base*)))
         (k (mod (le->uint (sha512 (u8cat rp pk message)) 0 64) *l25519*))
         (s (mod (+ r (* k a)) *l25519*)))
    (u8cat rp (uint->le s 32))))

(defun ed25519-verify (pk message sig)
  "Verify a 64-byte Ed25519 SIG on MESSAGE under 32-byte public key PK.  Returns
   T or NIL.  Cofactorless check [S]B = R + [k]A (accepts RFC 8032 vectors)."
  (declare (type u8v pk message sig))
  (when (/= (length sig) 64) (return-from ed25519-verify nil))
  (let ((rraw (subseq sig 0 32))
        (s (le->uint sig 32 32)))
    (when (>= s *l25519*) (return-from ed25519-verify nil))
    (let ((a-pt (ed-decode pk))
          (r-pt (ed-decode rraw)))
      (when (or (null a-pt) (null r-pt)) (return-from ed25519-verify nil))
      (let* ((k (mod (le->uint (sha512 (u8cat rraw pk message)) 0 64) *l25519*))
             (sb (ed-mul s *ed-base*))
             (rka (ed-add r-pt (ed-mul k a-pt))))
        (ed-point-equal sb rka)))))

(defun ed25519-keypair ()
  "Fresh Ed25519 keypair from the CSPRNG.  Returns (values SECRET-32 PUBLIC-32)."
  (let ((sk (random-bytes 32)))
    (values sk (ed25519-public-key sk))))

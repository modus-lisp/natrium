;;;; ed25519-ct.lisp — constant-time Ed25519 over the fe25519 limb field.
;;;;
;;;; The signing path is the one that touches secrets (the private scalar a and
;;;; the nonce r), so it must not branch on them.  Point arithmetic runs over the
;;;; constant-time fe25519 field; scalar multiplication is double-and-add-ALWAYS
;;;; with a branch-free point cmov (fixed 256 iterations, an addition every step
;;;; whether or not the bit is set); scalar reduction mod L is Barrett with
;;;; fixed-size operands and a fixed number of conditional subtractions.  As with
;;;; fe25519, the structure is constant-time and the native %mul128/%addc backend
;;;; closes the last instruction-level gap.  The big-integer *-reference functions
;;;; (ed25519.lisp) are the differential oracle.
;;;;
;;;; Points reuse the EPT struct with fe25519 limb arrays in the slots (the
;;;; reference uses the same struct with integer slots; the two never mix).

(in-package #:natrium)

;;; --- curve constants as field elements -----------------------------------
(defparameter *fe-2d* (integer->fe (mod (* 2 *d25519*) *p25519*))
  "2*d as a field element (the edc-add curve constant).")
(defparameter *edc-base*
  (let* ((by (fmul 4 (fe-inv 5)))
         (bx (ed-recover-x by 0)))
    (ept (integer->fe bx) (integer->fe by) (fe-one)
         (integer->fe (fmul bx by))))
  "The edwards25519 base point with fe25519 coordinates.")

(defun edc-identity ()
  (ept (fe-zero) (fe-one) (fe-one) (fe-zero)))

(defun edc-copy (p)
  (ept (fe-copy (ept-x p)) (fe-copy (ept-y p)) (fe-copy (ept-z p)) (fe-copy (ept-w p))))

(defun edc-add (p1 p2)
  "Unified twisted-Edwards addition (a = -1) over fe25519; correct for P1 = P2."
  (let* ((a (fe25519-mul (fe25519-sub (ept-y p1) (ept-x p1)) (fe25519-sub (ept-y p2) (ept-x p2))))
         (b (fe25519-mul (fe25519-add (ept-y p1) (ept-x p1)) (fe25519-add (ept-y p2) (ept-x p2))))
         (c (fe25519-mul (fe25519-mul *fe-2d* (ept-w p1)) (ept-w p2)))
         (d (fe25519-mul (fe25519-add (ept-z p1) (ept-z p1)) (ept-z p2)))
         (e (fe25519-sub b a)) (f (fe25519-sub d c)) (g (fe25519-add d c)) (h (fe25519-add b a)))
    (ept (fe25519-mul e f) (fe25519-mul g h) (fe25519-mul f g) (fe25519-mul e h))))

(defun edc-cmov (bit r src)
  "If BIT is 1, copy SRC's coordinates into R; branch-free.  Mutates R."
  (fe25519-cmov bit (ept-x r) (ept-x src))
  (fe25519-cmov bit (ept-y r) (ept-y src))
  (fe25519-cmov bit (ept-z r) (ept-z src))
  (fe25519-cmov bit (ept-w r) (ept-w src)))

(defun edc-mul (n p)
  "[N]P by double-and-add-ALWAYS: 256 fixed iterations, an addition and a
   branch-free cmov every step, so timing is independent of N's bits."
  (let ((r (edc-identity)))
    (loop for i from 255 downto 0 do
      (setf r (edc-add r r))                       ; double
      (let ((s (edc-add r p))                      ; always compute r+p
            (bit (logand (ash n (- i)) 1)))
        (edc-cmov bit r s)))                        ; take it iff bit set
    r))

(defun edc-encode (p)
  "Encode point P (fe coords) as 32 bytes: y with x's low bit in the MSB."
  (let* ((zinv (fe25519-invert (ept-z p)))
         (y (fe25519-mul (ept-y p) zinv))
         (xbytes (fe25519-tobytes (fe25519-mul (ept-x p) zinv)))
         (out (fe25519-tobytes y)))
    (setf (aref out 31) (logior (aref out 31) (ash (logand (aref xbytes 0) 1) 7)))
    out))

(defun edc-decode (bytes)
  "Decode 32 bytes to an fe-coordinate point, or NIL.  Verify-only (public data),
   so x-recovery borrows the big-integer reference."
  (declare (type u8v bytes))
  (let ((sign (ldb (byte 1 7) (aref bytes 31)))
        (yint (logand (le->uint bytes 0 32) (1- (ash 1 255)))))
    (when (>= yint *p25519*) (return-from edc-decode nil))
    (let ((x (ed-recover-x yint sign)))
      (when (null x) (return-from edc-decode nil))
      (ept (integer->fe x) (integer->fe yint) (fe-one)
           (integer->fe (mod (* x yint) *p25519*))))))

(defun edc-point-equal (p q)
  "Projective equality via cross-multiplied, frozen coordinates."
  (and (bytes= (fe25519-tobytes (fe25519-mul (ept-x p) (ept-z q)))
               (fe25519-tobytes (fe25519-mul (ept-x q) (ept-z p))))
       (bytes= (fe25519-tobytes (fe25519-mul (ept-y p) (ept-z q)))
               (fe25519-tobytes (fe25519-mul (ept-y q) (ept-z p))))))

;;; --- scalar arithmetic mod L (Barrett) -----------------------------------
(defparameter *l-mu* (floor (ash 1 512) *l25519*)
  "Barrett parameter floor(2^512 / L).")

(defun sc-reduce (x)
  "X mod L for 0 <= X < 2^512, via Barrett with a fixed operation shape: two
   fixed-size multiplies and a fixed number (2) of conditional subtractions."
  (let* ((l *l25519*)
         (q (ash (* x *l-mu*) -512))
         (r (- x (* q l))))
    (when (>= r l) (decf r l))
    (when (>= r l) (decf r l))
    r))

(defun sc-muladd (a b c)
  "(A*B + C) mod L.  A*B+C < 2^506 < 2^512, so one sc-reduce suffices."
  (sc-reduce (+ (* a b) c)))

;;; --- public API (constant-time; overrides the reference names) -----------
(defun ed25519-public-key (sk)
  "32-byte Ed25519 public key for a 32-byte secret key SK."
  (declare (type u8v sk))
  (let ((a (ed-clamp-scalar (subseq (sha512 sk) 0 32))))
    (edc-encode (edc-mul a *edc-base*))))

(defun ed25519-sign (sk message)
  "Deterministic Ed25519 signature (64 bytes) of MESSAGE under secret key SK."
  (declare (type u8v sk message))
  (let* ((h (sha512 sk))
         (a (ed-clamp-scalar (subseq h 0 32)))
         (prefix (subseq h 32 64))
         (pk (edc-encode (edc-mul a *edc-base*)))
         (r (sc-reduce (le->uint (sha512 (u8cat prefix message)) 0 64)))
         (rp (edc-encode (edc-mul r *edc-base*)))
         (k (sc-reduce (le->uint (sha512 (u8cat rp pk message)) 0 64)))
         (s (sc-muladd k a r)))
    (u8cat rp (uint->le s 32))))

(defun ed25519-verify (pk message sig)
  "Verify a 64-byte Ed25519 SIG on MESSAGE under 32-byte public key PK → T/NIL.
   Cofactorless check [S]B = R + [k]A."
  (declare (type u8v pk message sig))
  (when (/= (length sig) 64) (return-from ed25519-verify nil))
  (let ((rraw (subseq sig 0 32))
        (s (le->uint sig 32 32)))
    (when (>= s *l25519*) (return-from ed25519-verify nil))
    (let ((a-pt (edc-decode pk))
          (r-pt (edc-decode rraw)))
      (when (or (null a-pt) (null r-pt)) (return-from ed25519-verify nil))
      (let* ((k (sc-reduce (le->uint (sha512 (u8cat rraw pk message)) 0 64)))
             (sb (edc-mul s *edc-base*))
             (rka (edc-add r-pt (edc-mul k a-pt))))
        (edc-point-equal sb rka)))))

(defun ed25519-keypair ()
  "Fresh Ed25519 keypair from the CSPRNG.  Returns (values SECRET-32 PUBLIC-32)."
  (let ((sk (random-bytes 32)))
    (values sk (ed25519-public-key sk))))

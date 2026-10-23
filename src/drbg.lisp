;;;; drbg.lisp — HMAC-DRBG (NIST SP 800-90A), the userland CSPRNG.
;;;;
;;;; The OS entropy source (entropy.lisp) is conditioned through an HMAC-DRBG so
;;;; that (a) a coarse or slow source is stretched, and (b) we don't hammer the
;;;; kernel per call.  Generic over the underlying HMAC / output length; the
;;;; process default uses HMAC-SHA512 (outlen 64), while the test suite also
;;;; instantiates a SHA-256 DRBG to check against a real NIST CAVP known-answer.
;;;;
;;;; Not reentrant: the process-global instance behind RANDOM-BYTES must not be
;;;; shared across threads without external locking.  Under modus each actor has
;;;; its own heap, so one DRBG per actor is the natural (lock-free) shape.

(in-package #:natrium)

(defstruct (drbg (:constructor %make-drbg))
  (hmac   nil :type function)        ; (key msg) -> outlen-byte digest
  (outlen 64  :type fixnum)
  (k      nil :type u8v)
  (v      nil :type u8v)
  (reseed-counter 1 :type integer))

;;; K and V are the DRBG's whole secret state, so they live in fixed buffers (one pair
;;; per DRBG, allocated once) and are updated in place by HMAC-INTO; seed material is
;;; passed as HMAC parts, never concatenated.  A DRBG whose HMAC is not one of the
;;; three SHA-2 HMACs keeps the old consing path (tests only).

;;; HMAC_DRBG_Update (SP 800-90A 10.1.2.2).  PROVIDED is the provided_data: a byte
;;; vector, a list of byte vectors (concatenated), or NIL.  NIL, a zero-length vector
;;; or a list of zero-length vectors is the spec's Null (skip the second HMAC pair) --
;;; treating empty as Null keeps a caller who passes (make-u8v 0) to mean "no
;;; additional input" on the CAVP-conformant path.
(defun %provided-parts (provided)
  (let ((parts (cond ((null provided) nil) ((listp provided) provided) (t (list provided)))))
    (and (some (lambda (p) (plusp (length p))) parts) parts)))

(defun drbg-update (d provided)
  (let ((kind (%hmac-kind (drbg-hmac d))) (parts (%provided-parts provided))
        (k (drbg-k d)) (v (drbg-v d)))
    (if kind
        (gossamer:with-fixed-scratch ((sep :octets 1))
          (setf (aref sep 0) 0)
          (hmac-into kind k (list* v sep parts) k)
          (hmac-into kind k v v)
          (when parts
            (setf (aref sep 0) 1)
            (hmac-into kind k (list* v sep parts) k)
            (hmac-into kind k v v)))
        (let ((hm (drbg-hmac d)) (data (apply #'u8cat parts)))
          (setf k (funcall hm k (u8cat v (make-u8v 1 0) data)))
          (setf v (funcall hm k v))
          (when parts
            (setf k (funcall hm k (u8cat v (make-u8v 1 1) data)))
            (setf v (funcall hm k v)))
          (setf (drbg-k d) k (drbg-v d) v)))
    d))

(defun drbg-instantiate (entropy nonce &key personalization
                                             (hmac #'hmac-sha512) (outlen 64))
  "Instantiate an HMAC-DRBG (SP 800-90A 10.1.2.3).  ENTROPY, NONCE and the
   optional PERSONALIZATION are byte vectors; their concatenation is the seed
   material.  K starts all-zero, V all-0x01."
  (let* ((fixedp (%hmac-kind hmac))
         (k (if fixedp (gossamer:make-fixed-octets outlen) (make-u8v outlen 0)))
         (v (if fixedp (gossamer:make-fixed-octets outlen) (make-u8v outlen 1))))
    (fill v 1)
    (let ((d (%make-drbg :hmac hmac :outlen outlen :k k :v v)))
      (drbg-update d (remove nil (list entropy nonce personalization)))
      (setf (drbg-reseed-counter d) 1)
      d)))

(defun drbg-reseed (d entropy &optional additional)
  "Reseed (SP 800-90A 10.1.2.4) with fresh ENTROPY (+ optional ADDITIONAL)."
  (drbg-update d (remove nil (list entropy additional)))
  (setf (drbg-reseed-counter d) 1))

(defparameter *drbg-reseed-max* (expt 2 48)
  "SP 800-90A reseed_interval upper bound: generate fails closed past this.")

(defun drbg-generate (d n &optional additional)
  "Generate N bytes (SP 800-90A 10.1.2.5).  ADDITIONAL is optional additional
   input (u8v) or NIL (a zero-length vector is treated as NIL).  Signals an error
   once the reseed interval is exceeded (the spec's 'reseed required').  The output
   is a fresh heap vector; DRBG-GENERATE-INTO writes into a caller's buffer."
  (drbg-generate-into d (make-u8v n) additional))

(defun drbg-generate-into (d out &optional additional &key (start 0) (end (length out)))
  "Like DRBG-GENERATE, filling OUT[START,END) (fixed, when the output is a key)."
  (when (> (drbg-reseed-counter d) *drbg-reseed-max*)
    (error "natrium DRBG: reseed required (reseed interval exceeded)"))
  (let ((kind (%hmac-kind (drbg-hmac d))) (outlen (drbg-outlen d))
        (add (and additional (plusp (length additional)) additional)))
    (when add (drbg-update d add))
    (let ((pos start))
      (loop while (< pos end) do
        (if kind
            (hmac-into kind (drbg-k d) (drbg-v d) (drbg-v d))
            (setf (drbg-v d) (funcall (drbg-hmac d) (drbg-k d) (drbg-v d))))
        (let ((take (min outlen (- end pos))))
          (replace out (drbg-v d) :start1 pos :end2 take)
          (incf pos take))))
    (drbg-update d add)                         ; ADD is NIL when Null (= spec)
    (incf (drbg-reseed-counter d))
    out))

;;; ---- process-global CSPRNG ------------------------------------------------

(defparameter *default-drbg* nil)
(defparameter *drbg-reseed-interval* (expt 2 20)
  "Generate calls between automatic reseeds of the process-global DRBG.")

;;; On modus, threads and actors share no state, so the process-global DRBG
;;; is per COMPUTATION there: each thread and actor gets its own, seeded from
;;; the OS, when it first asks.  (Filling a shared global from a worker would
;;; be a shared-state write, which modus refuses.)
#+modus
(let ((reg (find-symbol "REGISTER-PER-COMPUTATION-SPECIAL" "COMMON-LISP-USER")))
  (when (and reg (fboundp reg)) (funcall reg '*default-drbg*)))

(defun ensure-default-drbg ()
  (or *default-drbg*
      (setf *default-drbg*
            (drbg-instantiate (os-entropy 32) (os-entropy 16)))))

(defun random-bytes (n)
  "N cryptographically-random bytes from the process-global CSPRNG (HMAC-SHA512
   DRBG, seeded and periodically reseeded from *OS-ENTROPY*).  Not reentrant —
   see the file header; per-thread/per-actor callers should use their own
   DRBG-INSTANTIATE."
  (let ((d (ensure-default-drbg)))
    (when (> (drbg-reseed-counter d) *drbg-reseed-interval*)
      (drbg-reseed d (os-entropy 32)))
    (drbg-generate d n)))

(defun random-bytes-into (out &key (start 0) (end (length out)))
  "Fill OUT[START,END) from the process-global CSPRNG -- the form for key material:
generate straight into a fixed buffer, so the secret never exists on the heap."
  (let ((d (ensure-default-drbg)))
    (when (> (drbg-reseed-counter d) *drbg-reseed-interval*)
      (drbg-reseed d (os-entropy 32)))
    (drbg-generate-into d out nil :start start :end end)))

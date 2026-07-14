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

;;; HMAC_DRBG_Update (SP 800-90A 10.1.2.2).  PROVIDED is the provided_data byte
;;; vector; NIL *or a zero-length vector* is the spec's Null (skip the second
;;; HMAC pair) — treating empty as Null keeps a caller who passes (make-u8v 0)
;;; to mean "no additional input" on the CAVP-conformant path.
(defun drbg-update (d provided)
  (let ((hm (drbg-hmac d)) (k (drbg-k d)) (v (drbg-v d)))
    (setf k (funcall hm k (u8cat v (make-u8v 1 0) (or provided (make-u8v 0)))))
    (setf v (funcall hm k v))
    (when (and provided (plusp (length provided)))
      (setf k (funcall hm k (u8cat v (make-u8v 1 1) provided)))
      (setf v (funcall hm k v)))
    (setf (drbg-k d) k (drbg-v d) v)))

(defun drbg-instantiate (entropy nonce &key personalization
                                             (hmac #'hmac-sha512) (outlen 64))
  "Instantiate an HMAC-DRBG (SP 800-90A 10.1.2.3).  ENTROPY, NONCE and the
   optional PERSONALIZATION are byte vectors; their concatenation is the seed
   material.  K starts all-zero, V all-0x01."
  (let ((d (%make-drbg :hmac hmac :outlen outlen
                       :k (make-u8v outlen 0) :v (make-u8v outlen 1))))
    (drbg-update d (u8cat entropy nonce (or personalization (make-u8v 0))))
    (setf (drbg-reseed-counter d) 1)
    d))

(defun drbg-reseed (d entropy &optional additional)
  "Reseed (SP 800-90A 10.1.2.4) with fresh ENTROPY (+ optional ADDITIONAL)."
  (drbg-update d (u8cat entropy (or additional (make-u8v 0))))
  (setf (drbg-reseed-counter d) 1))

(defparameter *drbg-reseed-max* (expt 2 48)
  "SP 800-90A reseed_interval upper bound: generate fails closed past this.")

(defun drbg-generate (d n &optional additional)
  "Generate N bytes (SP 800-90A 10.1.2.5).  ADDITIONAL is optional additional
   input (u8v) or NIL (a zero-length vector is treated as NIL).  Signals an error
   once the reseed interval is exceeded (the spec's 'reseed required')."
  (when (> (drbg-reseed-counter d) *drbg-reseed-max*)
    (error "natrium DRBG: reseed required (reseed interval exceeded)"))
  (let ((hm (drbg-hmac d)) (outlen (drbg-outlen d))
        (add (and additional (plusp (length additional)) additional)))
    (when add (drbg-update d add))
    (let ((out (make-u8v n)) (pos 0))
      (loop while (< pos n) do
        (let ((v (funcall hm (drbg-k d) (drbg-v d))))
          (setf (drbg-v d) v)
          (let ((take (min outlen (- n pos))))
            (replace out v :start1 pos :end2 take)
            (incf pos take))))
      (drbg-update d add)                         ; ADD is NIL when Null (= spec)
      (incf (drbg-reseed-counter d))
      out)))

;;; ---- process-global CSPRNG ------------------------------------------------

(defparameter *default-drbg* nil)
(defparameter *drbg-reseed-interval* (expt 2 20)
  "Generate calls between automatic reseeds of the process-global DRBG.")

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

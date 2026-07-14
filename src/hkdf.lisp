;;;; hkdf.lisp — HKDF (RFC 5869), the extract-then-expand KDF over HMAC.
;;;;
;;;; The standard way to turn a Diffie-Hellman shared secret (or any high-entropy
;;;; but non-uniform input) into one or more uniformly-random keys.  Generic over
;;;; the HMAC; hkdf-sha256 / hkdf-sha512 are the usual instantiations.

(in-package #:natrium)

(defun hkdf-extract (hmac-fn hashlen salt ikm)
  "HKDF-Extract: PRK = HMAC(salt, IKM).  An empty SALT is treated as HASHLEN
   zero bytes (RFC 5869 2.2)."
  (declare (type u8v salt ikm))
  (funcall hmac-fn (if (zerop (length salt)) (make-u8v hashlen) salt) ikm))

(defun hkdf-expand (hmac-fn hashlen prk info len)
  "HKDF-Expand: LEN bytes of output keying material from PRK and context INFO
   (RFC 5869 2.3).  LEN <= 255*HASHLEN."
  (declare (type u8v prk info))
  (when (> len (* 255 hashlen))
    (error "hkdf-expand: requested length ~d exceeds 255*hashlen" len))
  (let ((out (make-u8v len)) (tprev (make-u8v 0)) (pos 0) (i 0))
    (loop while (< pos len) do
      (incf i)
      (setf tprev (funcall hmac-fn prk (u8cat tprev info (make-u8v 1 i))))
      (let ((take (min hashlen (- len pos))))
        (replace out tprev :start1 pos :end2 take)
        (incf pos take)))
    out))

(defun hkdf (hmac-fn hashlen salt ikm info len)
  "Full HKDF: extract then expand to LEN bytes."
  (hkdf-expand hmac-fn hashlen (hkdf-extract hmac-fn hashlen salt ikm) info len))

(defun hkdf-sha256 (salt ikm info len)
  "HKDF-SHA256 (RFC 5869): derive LEN bytes from IKM with SALT and context INFO."
  (hkdf #'hmac-sha256 32 salt ikm info len))

(defun hkdf-sha384 (salt ikm info len)
  "HKDF-SHA384: derive LEN bytes from IKM with SALT and context INFO."
  (hkdf #'hmac-sha384 48 salt ikm info len))

(defun hkdf-sha512 (salt ikm info len)
  "HKDF-SHA512: derive LEN bytes from IKM with SALT and context INFO."
  (hkdf #'hmac-sha512 64 salt ikm info len))

;;;; hkdf.lisp — HKDF (RFC 5869), extract-then-expand over HMAC.
;;;;
;;;; The PRK and every T(i) block are secret, so they live in fixed scratch and are
;;;; hashed as HMAC parts (T(i-1), info, i) without concatenation.  HKDF-INTO writes
;;;; the output keying material into a caller's (fixed) buffer.

(in-package #:natrium)

(defun %hmac-kind (hmac-fn)
  (cond ((eq hmac-fn #'hmac-sha256) :sha256)
        ((eq hmac-fn #'hmac-sha512) :sha512)
        ((eq hmac-fn #'hmac-sha384) :sha384)))

(defun %hkdf-expand-into (kind prk info out start len)
  (multiple-value-bind (bs hashlen) (%hash-spec kind)
    (declare (ignore bs))
    (when (> len (* 255 hashlen)) (error "hkdf: requested length ~d exceeds 255*hashlen" len))
    (gossamer:with-fixed-scratch ((tblk :octets hashlen) (ctr :octets 1))
      (let ((pos 0) (i 0))
        (loop while (< pos len) do
          (incf i)
          (setf (aref ctr 0) i)
          (hmac-into kind prk (if (= i 1) (list info ctr) (list tblk info ctr)) tblk)
          (let ((take (min hashlen (- len pos))))
            (replace out tblk :start1 (+ start pos) :end2 take)
            (incf pos take)))))
    out))

(defun hkdf-expand-into (kind prk info out &key (start 0) (len (- (length out) start)))
  "HKDF-Expand only (RFC 5869 2.3): LEN bytes from PRK and INFO into OUT at START."
  (%hkdf-expand-into kind prk info out start len))

(defun hkdf-into (kind salt ikm info out &key (start 0) (len (- (length out) start)))
  "HKDF with KIND (:sha256 :sha384 :sha512): LEN bytes of OKM from IKM, SALT and INFO,
written into OUT at START.  Returns OUT."
  (multiple-value-bind (bs hashlen) (%hash-spec kind)
    (declare (ignore bs))
    (gossamer:with-fixed-scratch ((prk :octets hashlen) (zsalt :octets hashlen))
      (hmac-into kind (if (zerop (length salt)) zsalt salt) ikm prk)
      (%hkdf-expand-into kind prk info out start len))))

(defun hkdf-extract (hmac-fn hashlen salt ikm)
  "HKDF-Extract: PRK = HMAC(salt, IKM).  An empty SALT is treated as HASHLEN zero
bytes (RFC 5869 2.2).  Returns a fresh PRK on the heap -- use HKDF-INTO when the
PRK must stay secret."
  (declare (type u8v salt ikm))
  (funcall hmac-fn (if (zerop (length salt)) (make-u8v hashlen) salt) ikm))

(defun hkdf-expand (hmac-fn hashlen prk info len)
  "HKDF-Expand: LEN bytes of OKM from PRK and INFO (RFC 5869 2.3)."
  (declare (type u8v prk info))
  (let ((kind (%hmac-kind hmac-fn)))
    (if kind
        (%hkdf-expand-into kind prk info (make-u8v len) 0 len)
        (progn
          (when (> len (* 255 hashlen)) (error "hkdf-expand: requested length ~d exceeds 255*hashlen" len))
          (let ((out (make-u8v len)) (tprev (make-u8v 0)) (pos 0) (i 0))
            (loop while (< pos len) do
              (incf i)
              (setf tprev (funcall hmac-fn prk (u8cat tprev info (make-u8v 1 i))))
              (let ((take (min hashlen (- len pos))))
                (replace out tprev :start1 pos :end2 take) (incf pos take)))
            out)))))

(defun hkdf (hmac-fn hashlen salt ikm info len)
  "Full HKDF: extract then expand to LEN bytes (fresh output)."
  (let ((kind (%hmac-kind hmac-fn)))
    (if kind
        (hkdf-into kind salt ikm info (make-u8v len))
        (hkdf-expand hmac-fn hashlen (hkdf-extract hmac-fn hashlen salt ikm) info len))))

(defun hkdf-sha256 (salt ikm info len)
  "HKDF-SHA256 (RFC 5869): derive LEN bytes from IKM with SALT and context INFO."
  (hkdf-into :sha256 salt ikm info (make-u8v len)))

(defun hkdf-sha384 (salt ikm info len)
  "HKDF-SHA384: derive LEN bytes from IKM with SALT and context INFO."
  (hkdf-into :sha384 salt ikm info (make-u8v len)))

(defun hkdf-sha512 (salt ikm info len)
  "HKDF-SHA512: derive LEN bytes from IKM with SALT and context INFO."
  (hkdf-into :sha512 salt ikm info (make-u8v len)))

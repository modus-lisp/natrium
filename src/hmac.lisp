;;;; hmac.lisp — HMAC (RFC 2104) over the streaming SHA-2 contexts.
;;;;
;;;; The key block, the pads and the inner digest are fixed scratch, wiped on exit,
;;;; and the message is hashed in place as a sequence of PARTS -- callers never
;;;; concatenate secret material to call HMAC (BIP-32's 0x00||key||index, HKDF's
;;;; T(i-1)||info||i).  The -INTO functions write the MAC into a caller's buffer, which
;;;; should be fixed whenever the MAC is itself a key (HKDF PRKs, BIP-32 children, the
;;;; DRBG's K and V).

(in-package #:natrium)

(defun %hash-spec (kind)
  "(values block-size digest-size) for KIND."
  (ecase kind (:sha256 (values 64 32)) (:sha384 (values 128 48)) (:sha512 (values 128 64))))

(defmacro %with-hash ((ctx kind) &body body)
  "Bind CTX to a fresh context for KIND (:sha256 :sha384 :sha512) and run BODY."
  (let ((k (gensym "KIND")) (f (gensym "BODY")))
    `(let ((,k ,kind))
       (flet ((,f (,ctx) ,@body))
         (ecase ,k
           (:sha256 (with-sha256 (c) (,f c)))
           (:sha384 (with-sha384 (c) (,f c)))
           (:sha512 (with-sha512 (c) (,f c))))))))

(defun %hash-update (ctx data &optional end)
  (if (sha256-ctx-p ctx) (sha256-update ctx data :end end) (sha512-update ctx data :end end)))

(defun %hash-final-into (ctx out start)
  (if (sha256-ctx-p ctx) (sha256-final-into ctx out :start start) (sha512-final-into ctx out :start start)))

(defun %parts (parts) (if (listp parts) parts (list parts)))

(defun hmac-into (kind key parts out &key (start 0))
  "HMAC of the concatenation of PARTS (a byte vector or a list of them) under KEY,
written into OUT at START.  KIND is :sha256, :sha384 or :sha512.  Returns OUT.
OUT may be KEY or one of PARTS: key and message are fully consumed before OUT is
written."
  (multiple-value-bind (bs dl) (%hash-spec kind)
    (gossamer:with-fixed-scratch ((k0 :octets 128) (pad :octets 128) (inner :octets 64))
      (if (> (length key) bs)
          (%with-hash (c kind) (%hash-update c key) (%hash-final-into c k0 0))
          (replace k0 key))
      (dotimes (i bs) (setf (aref pad i) (logxor (aref k0 i) #x36)))
      (%with-hash (c kind)
        (%hash-update c pad bs)
        (dolist (p (%parts parts)) (%hash-update c p))
        (%hash-final-into c inner 0))
      (dotimes (i bs) (setf (aref pad i) (logxor (aref k0 i) #x5c)))
      (%with-hash (c kind)
        (%hash-update c pad bs)
        (%hash-update c inner dl)
        (%hash-final-into c out start))))
  out)

(defun hmac-sha256-into (key parts out &key (start 0)) (hmac-into :sha256 key parts out :start start))
(defun hmac-sha384-into (key parts out &key (start 0)) (hmac-into :sha384 key parts out :start start))
(defun hmac-sha512-into (key parts out &key (start 0)) (hmac-into :sha512 key parts out :start start))

(defun hmac-sha256 (key msg)
  "HMAC-SHA256 of MSG under KEY → fresh 32-byte digest."
  (hmac-into :sha256 key msg (make-u8v 32)))

(defun hmac-sha384 (key msg)
  "HMAC-SHA384 of MSG under KEY → fresh 48-byte digest."
  (hmac-into :sha384 key msg (make-u8v 48)))

(defun hmac-sha512 (key msg)
  "HMAC-SHA512 of MSG under KEY → fresh 64-byte digest."
  (hmac-into :sha512 key msg (make-u8v 64)))

(defun hmac (hash-fn block-size key msg)
  "HMAC of MSG under KEY using HASH-FN with BLOCK-SIZE (64 for SHA-256, 128 for
SHA-512/384).  The three SHA-2 functions take the streaming fixed-scratch path; any
other HASH-FN gets the generic construction, which conses its pads -- do not use it
with a secret key."
  (cond ((eq hash-fn #'sha256) (hmac-sha256 key msg))
        ((eq hash-fn #'sha512) (hmac-sha512 key msg))
        ((eq hash-fn #'sha384) (hmac-sha384 key msg))
        (t (let* ((k (if (> (length key) block-size) (funcall hash-fn key) key))
                  (k0 (make-u8v block-size)) (ipad (make-u8v block-size)) (opad (make-u8v block-size)))
             (replace k0 k)
             (dotimes (i block-size)
               (setf (aref ipad i) (logxor (aref k0 i) #x36) (aref opad i) (logxor (aref k0 i) #x5c)))
             (funcall hash-fn (u8cat opad (funcall hash-fn (u8cat ipad msg))))))))

;;;; hmac.lisp — HMAC (RFC 2104), generic over the underlying hash.

(in-package #:natrium)

(defun hmac (hash-fn block-size key msg)
  "HMAC of MSG under KEY (both byte vectors) using HASH-FN with the given
   BLOCK-SIZE (64 for SHA-256, 128 for SHA-512).  Returns a fresh digest of
   HASH-FN's output length."
  (declare (type u8v key msg))
  (let* ((k (if (> (length key) block-size) (funcall hash-fn key) key))
         (k0 (make-u8v block-size))
         (ipad (make-u8v block-size))
         (opad (make-u8v block-size)))
    (replace k0 k)
    (dotimes (i block-size)
      (setf (aref ipad i) (logxor (aref k0 i) #x36)
            (aref opad i) (logxor (aref k0 i) #x5c)))
    (funcall hash-fn
             (concatenate '(simple-array (unsigned-byte 8) (*))
                          opad
                          (funcall hash-fn
                                   (concatenate '(simple-array (unsigned-byte 8) (*))
                                                ipad msg))))))

(defun hmac-sha256 (key msg)
  "HMAC-SHA256 of MSG under KEY → fresh 32-byte digest."
  (hmac #'sha256 64 key msg))

(defun hmac-sha512 (key msg)
  "HMAC-SHA512 of MSG under KEY → fresh 64-byte digest."
  (hmac #'sha512 128 key msg))

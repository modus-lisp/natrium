;;;; util.lisp — shared byte-vector helpers.

(in-package #:natrium)

(deftype u8v () '(simple-array (unsigned-byte 8) (*)))

;;; A constant a saved image carries (a bignum, a field element) is not trustworthy after a
;;; restore at another address: on the phone the saved *p25519* came back unprintable.  So each
;;; such constant has a refresh that builds it again, registered here to run after a restore, in
;;; load order (a later constant may use an earlier one).
(defun %on-restore-refresh (fn)
  ;; FIND-PACKAGE first: FIND-SYMBOL signals when the package does not exist, as on SBCL.
  (let* ((pkg (find-package "MODUS"))
         (add (and pkg (find-symbol "ADD-RESTORE-HOOK" pkg))))
    (when (and add (fboundp add)) (funcall add fn))))

(declaim (ftype (function (fixnum &optional (unsigned-byte 8)) u8v) make-u8v))
(defun make-u8v (n &optional (init 0))
  "Fresh (unsigned-byte 8) simple-array of length N."
  (make-array n :element-type '(unsigned-byte 8) :initial-element init))

(defun ascii->bytes (string)
  "ASCII STRING → fresh (unsigned-byte 8) vector."
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))

(defun u8cat (&rest parts)
  "Concatenate byte sequences into a fresh u8v."
  ;; MAKE-U8V + REPLACE rather than CONCATENATE: CONCATENATE with an array type
  ;; specifier works the type out on every call, which on modus was most of
  ;; the time of an HMAC over a short message.
  (let ((out (make-u8v (loop for p in parts sum (length p))))
        (at 0))
    (dolist (p parts out)
      (replace out p :start1 at)
      (incf at (length p)))))

(defun le->uint (bytes off len)
  "Decode LEN little-endian bytes of BYTES at OFF into a non-negative integer."
  (let ((n 0))
    (dotimes (i len n)
      (setf n (logior n (ash (aref bytes (+ off i)) (* 8 i)))))))

(defun uint->le (n len)
  "Encode non-negative integer N as LEN little-endian bytes (fresh u8v)."
  (let ((out (make-u8v len)))
    (dotimes (i len out)
      (setf (aref out i) (logand #xff (ash n (* -8 i)))))))

(defun bytes= (a b)
  "Constant-time equality of two byte vectors: the running time depends only on
   the (public) length, never on where the first differing byte is.  Length
   mismatch is reported directly (lengths are not secret in our uses — MAC tags
   are fixed-width)."
  (declare (type u8v a b))
  (if (/= (length a) (length b))
      nil
      (let ((acc 0))
        (declare (type (unsigned-byte 8) acc))
        (dotimes (i (length a))
          (setf acc (logior acc (logxor (aref a i) (aref b i)))))
        (zerop acc))))

;;; ---- base64 (RFC 4648 section 4: the standard alphabet, padded) ---------------------------
;;; The org's canonical copy (AGENTS.md: hex, base64 and UTF-8 are moving here).  Public data
;;; only: the table lookups are not constant-time, so do not run a secret through these.

(defparameter +base64-chars+
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defun base64-encode (bytes &key (start 0) (end (length bytes)))
  "The octets of BYTES from START to END as a padded base64 string (RFC 4648)."
  (let* ((n (- end start))
         (out (make-string (* 4 (ceiling n 3))))
         (o 0))
    (flet ((put (k) (setf (char out o) (char +base64-chars+ k)) (incf o)))
      (loop for i from start below end by 3
            do (let* ((left (- end i))
                      (w (logior (ash (aref bytes i) 16)
                                 (if (> left 1) (ash (aref bytes (+ i 1)) 8) 0)
                                 (if (> left 2) (aref bytes (+ i 2)) 0))))
                 (put (ldb (byte 6 18) w))
                 (put (ldb (byte 6 12) w))
                 (if (> left 1) (put (ldb (byte 6 6) w)) (progn (setf (char out o) #\=) (incf o)))
                 (if (> left 2) (put (ldb (byte 6 0) w)) (progn (setf (char out o) #\=) (incf o))))))
    out))

(defun base64-decode (string)
  "The octets a padded or unpadded base64 STRING (RFC 4648) encodes, as a fresh u8v.
   Whitespace is skipped; any other character outside the alphabet signals an error."
  (let ((out (make-u8v (* 3 (ceiling (length string) 4))))
        (o 0) (acc 0) (bits 0))
    (loop for c across string
          do (let ((k (position c +base64-chars+)))
               (cond (k (setf acc (logior (ash (logand acc #xffff) 6) k))
                        (incf bits 6)
                        (when (>= bits 8)
                          (decf bits 8)
                          (setf (aref out o) (ldb (byte 8 bits) acc))
                          (incf o)))
                     ((char= c #\=) (loop-finish))
                     ((member c '(#\Space #\Tab #\Newline #\Return)))
                     (t (error "natrium: ~s is not a base64 character" c)))))
    (subseq out 0 o)))

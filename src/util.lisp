;;;; util.lisp — shared byte-vector helpers.

(in-package #:natrium)

(deftype u8v () '(simple-array (unsigned-byte 8) (*)))

(declaim (ftype (function (fixnum &optional (unsigned-byte 8)) u8v) make-u8v))
(defun make-u8v (n &optional (init 0))
  "Fresh (unsigned-byte 8) simple-array of length N."
  (make-array n :element-type '(unsigned-byte 8) :initial-element init))

(defun ascii->bytes (string)
  "ASCII STRING → fresh (unsigned-byte 8) vector."
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))

(defun u8cat (&rest parts)
  "Concatenate byte sequences into a fresh u8v."
  (apply #'concatenate '(simple-array (unsigned-byte 8) (*)) parts))

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

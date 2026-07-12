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

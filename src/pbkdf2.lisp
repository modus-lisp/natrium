;;;; pbkdf2.lisp — PBKDF2 (RFC 8018 5.2) over natrium's HMAC, into fixed memory.
;;;;
;;;; The password, every U_i and the running T live in fixed buffers; the block
;;;; counter is an HMAC part, so nothing is concatenated onto the heap.

(in-package #:natrium)

(defun pbkdf2-into (kind password salt iterations out &key (start 0) (len (- (length out) start)))
  "PBKDF2-HMAC-KIND (:sha256 :sha384 :sha512): LEN bytes derived from PASSWORD (the
HMAC key -- pass it in fixed memory) and SALT with ITERATIONS rounds, written into
OUT (fixed) at START.  Returns OUT."
  (check-type iterations (integer 1))
  (multiple-value-bind (bs hashlen) (%hash-spec kind)
    (declare (ignore bs))
    (gossamer:with-fixed-scratch ((u :octets hashlen) (tacc :octets hashlen) (ctr :octets 4))
      (loop for i from 1 to (ceiling len hashlen)
            do (setf (aref ctr 0) (ldb (byte 8 24) i) (aref ctr 1) (ldb (byte 8 16) i)
                     (aref ctr 2) (ldb (byte 8 8) i) (aref ctr 3) (ldb (byte 8 0) i))
               (hmac-into kind password (list salt ctr) u)
               (replace tacc u)
               (loop repeat (1- iterations)
                     do (hmac-into kind password u u)
                        (dotimes (j hashlen) (setf (aref tacc j) (logxor (aref tacc j) (aref u j)))))
               (let ((o (* hashlen (1- i))))
                 (replace out tacc :start1 (+ start o) :end2 (min hashlen (- len o))))))
    out))

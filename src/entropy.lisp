;;;; entropy.lisp — the one OS-coupled seam.
;;;;
;;;; Every other file in natrium is pure computation.  Random bytes are the sole
;;;; thing that must come from outside — and on a Lisp OS that source is the
;;;; kernel's hardware/jitter entropy, not a Unix device.  So the raw source is a
;;;; single indirection, *OS-ENTROPY*, that modus overrides.  The default reads
;;;; /dev/urandom (Unix), which is enough to develop and test on SBCL/CCL/ECL.

(in-package #:natrium)

(defun read-dev-urandom (n)
  "Read N bytes from /dev/urandom.  The portable default OS entropy source."
  (with-open-file (s "/dev/urandom" :element-type '(unsigned-byte 8))
    (let* ((buf (make-u8v n))
           (got (read-sequence buf s)))
      (unless (= got n)
        (error "natrium: short read from /dev/urandom (~d of ~d bytes)" got n))
      buf)))

(defparameter *os-entropy* #'read-dev-urandom
  "Function of one argument (N) returning a fresh N-byte u8v of OS entropy.
   THE seam a Lisp OS reimplements: modus binds this to its hardware entropy
   source.  Must return full-entropy bytes; the DRBG conditions them but cannot
   create entropy that isn't there.")

(defun os-entropy (n)
  "N bytes from the current OS entropy source (see *OS-ENTROPY*)."
  (funcall *os-entropy* n))

;;;; tests.lisp -- fixed

(defpackage #:gossamer.tests (:use #:cl) (:export #:run))
(in-package #:gossamer.tests)

(defvar *pass* 0) (defvar *fail* '())
(defmacro check (name form)
  `(if (ignore-errors ,form) (incf *pass*) (progn (push ,name *fail*) (format t "~&FAIL: ~a~%" ,name))))

(declaim (notinline abandon-an-owner))
(defun abandon-an-owner ()
  (let ((b (gossamer:acquire :octets 48)))
    (fill b 3)
    (gossamer:own (list :owner) b)
    nil))

(defun run ()
  (setf *pass* 0 *fail* '())
  (let ((f (gossamer:make-fixed-octets 32)) (h (make-array 32 :element-type '(unsigned-byte 8))))
    (check "fixed octets are fixed" (gossamer:fixed-p f))
    (check "heap octets are not" (not (gossamer:fixed-p h)))
    (check "fixnum buffers are fixed" (gossamer:fixed-p (gossamer:make-fixed-fixnums 5)))
    #-modus (check "ub64 buffers are fixed" (gossamer:fixed-p (gossamer:make-fixed-ub64 4)))
    #+modus (check "ub64 buffers are refused (a bignum element would dangle in the arena)"
                   (handler-case (progn (gossamer:make-fixed-ub64 4) nil) (error () t)))
    (check "check-fixed passes a fixed buffer" (eq (gossamer:check-fixed f) f))
    (check "check-fixed rejects a heap copy"
           (handler-case (progn (gossamer:check-fixed (subseq f 0 16) "key") nil) (gossamer:not-fixed () t)))
    (check "check-fixed rejects an integer" (handler-case (progn (gossamer:check-fixed 12345) nil) (gossamer:not-fixed () t)))
    (check "*allow-unfixed* lets it through" (let ((gossamer:*allow-unfixed* t)) (gossamer:check-fixed h)))
    (check "fixed-copy is fixed and equal"
           (let ((c (gossamer:fixed-copy (coerce #(1 2 3 4) '(vector (unsigned-byte 8))))))
             (and (gossamer:fixed-p c) (equalp c #(1 2 3 4)))))
    (fill f 7) (gossamer:wipe f)
    (check "wipe zeroes" (every #'zerop f)))
  ;; scratch: zeroed on entry, wiped on exit (including non-local exit), reused
  (let (seen)
    (gossamer:with-fixed-scratch ((a :octets 32) (b :fixnums 5))
      (check "scratch is fixed" (and (gossamer:fixed-p a) (gossamer:fixed-p b)))
      (check "scratch starts zeroed" (and (every #'zerop a) (every #'zerop b)))
      (fill a 9) (fill b 9) (setf seen a))
    (check "scratch wiped on exit" (every #'zerop seen))
    (ignore-errors (gossamer:with-fixed-scratch ((a :octets 32)) (fill a 5) (setf seen a) (error "boom")))
    (check "scratch wiped on error exit" (every #'zerop seen))
    (gossamer:with-fixed-scratch ((a :octets 32))
      (check "pool reuses buffers" (eq a seen))))
  ;; OWN: a dropped owner's buffers come back to the pool, wiped (SBCL: finalizers)
  ;; OWN is a SAFETY NET, not the contract (explicit wipe/free is): SBCL never
  ;; promises to finalize a given object, and on arm64 it keeps a dead one alive
  ;; far more often (2 of 11 finalized there, measured, against 11 of 11 on
  ;; x86-64).  So abandon twenty owners, made in a not-inlined function so no
  ;; stack slot here holds them, and require that the net catches SOME.
  #+sbcl
  (let ((before (nth-value 1 (gossamer:pool-stats))))
    (dotimes (i 20) (abandon-an-owner))
    ;; newer SBCLs run finalizers on their own thread: give it up to 5 seconds
    (loop repeat 50
          until (> (nth-value 1 (gossamer:pool-stats)) before)
          do (sb-ext:gc :full t)
             (let ((run (find-symbol "RUN-PENDING-FINALIZERS" "SB-IMPL")))
               (when (and run (fboundp run)) (funcall run)))
             (sleep 0.1))
    (check "abandoned owners' buffers return to the pool"
           (> (nth-value 1 (gossamer:pool-stats)) before)))
  (let* ((o (list :owner)) (b (gossamer:acquire :octets 40))
         (free0 (nth-value 1 (gossamer:pool-stats))))
    (gossamer:own o b) (gossamer:disown o) (gossamer:free b)
    (check "disown then free: the buffer is back in the pool, once"
           (= (1+ free0) (nth-value 1 (gossamer:pool-stats))))
    (check "and the next acquire of that size is that buffer, zeroed"
           (let ((c (gossamer:acquire :octets 40))) (prog1 (and (eq c b) (every #'zerop c)) (gossamer:free c)))))
  ;; the backend keeps buffers still: contents and identity survive heavy allocation
  (let ((a (gossamer:acquire :octets 64)) (f (gossamer:acquire :fixnums 8)))
    (dotimes (i 64) (setf (aref a i) (mod (* 13 i) 256)))
    (dotimes (i 8) (setf (aref f i) (* i 1000003)))
    (let ((junk nil)) (dotimes (i 400000) (setf junk (make-list 20)) (make-string 64)) (length junk))
    #+sbcl (sb-ext:gc :full t)
    (check "a buffer is still fixed after collections" (and (gossamer:fixed-p a) (gossamer:fixed-p f)))
    (check "and still holds what was written"
           (and (loop for i below 64 always (= (aref a i) (mod (* 13 i) 256)))
                (loop for i below 8 always (= (aref f i) (* i 1000003)))))
    (gossamer:free a) (gossamer:free f))
  (check "the backend is real here" (not (eq (gossamer:fixed-backend) :none)))
  (format t "~&gossamer: ~d passed, ~d failed~%" *pass* (length *fail*))
  (null *fail*))

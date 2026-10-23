;;;; gossamer.lisp -- memory the collector never moves, for secrets
;;;;
;;;; Backends:
;;;;   SBCL   static vectors (sb-int:make-static-vector): outside the moving dynamic
;;;;          space, so a collection never copies them.  FIXED-P asks whether an object
;;;;          lies outside dynamic space.  SBCL 2.2 cannot free a static vector, so
;;;;          short-lived buffers come from a pool (WITH-FIXED-SCRATCH) and are wiped
;;;;          and reused, never abandoned.
;;;;   modus  (hosted Linux) a SECRET ARENA: private anonymous mmap chunks, mlock'd, kept
;;;;          out of core dumps (MADV_DONTDUMP) and zeroed in a forked child
;;;;          (MADV_WIPEONFORK).  Buffers are ordinary Lisp vectors whose headers are
;;;;          written into the arena -- every modus collector forwards only words that
;;;;          point into the region it is collecting, so an object outside every region
;;;;          is never moved, copied or scanned.  FIXED-P is an address-range test.
;;;;          :OCTETS are u8 vectors; :FIXNUMS are general vectors holding only fixnums
;;;;          (immediates: the collector never needs to see them).  :UB64 is refused --
;;;;          on modus a value past the fixnum range is a heap bignum, and a pointer
;;;;          stored in the arena would dangle.  Bare metal has no backend yet:
;;;;          FIXED-BACKEND is :NONE there and CHECK-FIXED signals unless
;;;;          *ALLOW-UNFIXED* -- secret code fails loudly rather than pretending.
;;;;
;;;; SBCL'S STATIC SPACE IS SMALL AND NEVER RECLAIMED: 1 MB on a stock build, about
;;;; 21,800 32-byte vectors, and a static vector that becomes garbage is still there.
;;;; So MAKE-FIXED-* and FIXED-COPY are for the few long-lived secrets (an identity key,
;;;; a DRBG's state); anything per-operation -- a derived key, an ephemeral key, a
;;;; conversation key -- comes from the pool (ACQUIRE / POOLED-COPY / WITH-FIXED-SCRATCH)
;;;; and goes back (RELEASE / FREE).  A pool only grows to the peak number in use.
;;;;
;;;; What this does not do: it cannot see secrets held as immediate values (fixnums in
;;;; registers or stack slots).  Code on the secret path keeps them in fixed limb
;;;; buffers, and a stack scrub is a separate, platform-level job.

(defpackage #:gossamer
  (:use #:cl)
  (:export #:fixed-backend #:fixed-p #:check-fixed #:not-fixed #:*allow-unfixed*
           #:make-fixed-octets #:make-fixed-ub64 #:make-fixed-fixnums
           #:wipe #:with-fixed-scratch #:fixed-copy #:pool-stats #:acquire #:release
           #:pooled-copy #:free #:static-bytes-used #:own #:disown))

(in-package #:gossamer)

(defvar *allow-unfixed* nil
  "When true, CHECK-FIXED accepts objects it cannot verify (on a platform with no
fixed memory, or for tests).  Never true in production on the secret path.")

(define-condition not-fixed (error)
  ((object :initarg :object :reader not-fixed-object)
   (what :initarg :what :reader not-fixed-what))
  (:report (lambda (c s)
             (format s "~a is not in fixed memory~@[ (~a)~]: a secret was copied onto the moving heap"
                     (let ((o (not-fixed-object c)))
                       (if (typep o 'array) (format nil "a ~a of length ~a" (type-of o) (length o)) (type-of o)))
                     (not-fixed-what c)))))

(defun fixed-backend ()
  #+sbcl :sbcl-static
  #+modus (if (%arena-available-p) :modus-arena :none)
  #-(or sbcl modus) :none)

;;; ---------------------------------------------------------------------------
;;; The modus secret arena.
;;; ---------------------------------------------------------------------------

;;; MODUS THREADS SHARE NO HEAP STATE: a thread may not store a pointer to one of its
;;; own objects into a structure another thread can reach (the collector of the
;;; thread that owns the object would not update it).  So on modus NOTHING of the
;;; pool or the arena lives on the heap: chunk ranges, free-list heads and counters
;;; are raw words in an arena CONTROL PAGE, a free buffer is linked through the
;;; 8-byte padding word after its header, and a spinlock word in the control page
;;; (XCHG-MEM, as modus's own atomics) guards them.  Every store is a raw integer
;;; into arena memory -- no thread ever publishes a heap pointer.
;;;
;;; Control page:  +0 lock   +8 bump pointer   +16 bump end   +24 buffers allocated
;;;   +32 buffers free   +40 range count   +48 ranges (start, end) x 64
;;;   +1088 bucket count   +1096 buckets (kind-code, length, free-list head) x 256

#+modus
(progn
  (defconstant +arena-chunk+ (* 1024 1024))
  (defconstant +ctl-size+ 8192)
  (defvar *ctl* 0 "Raw address of the arena's control page; 0 when there is no arena.")

  (defun %baked (name)
    "A function baked into the modus image, or NIL.  Syscalls are issued through one:
an intrinsic SYSCALL in runtime-compiled code does not return the kernel's answer."
    (let ((s (intern name "COMMON-LISP-USER")))
      (and (fboundp s) (symbol-function s))))

  (defun %syscall (n a b c d)
    (funcall (or (%baked "%GC-SAFE-BLOCK-6") (error "gossamer: this modus image has no syscall path"))
             n a b c d))

  (defun %arena-numbers ()
    "(mmap mlock madvise) for this architecture, or NIL."
    (and (member :linux *features*)
         (let ((m (string-downcase (or (ignore-errors (machine-type)) ""))))
           (cond ((search "x86_64" m) '(9 149 28))
                 ((or (search "aarch64" m) (search "arm64" m)) '(222 228 233))))))

  (defun %arena-available-p () (/= *ctl* 0))

  (defmacro %ctl (off) `(mem-ref (+ *ctl* ,off) :u64))

  (defun %mmap-secret (size)
    "SIZE bytes of private, zeroed, locked memory, kept out of core dumps and wiped in
a forked child.  Returns the raw address."
    (destructuring-bind (mmap mlock madvise) (%arena-numbers)
      ;; PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS (Linux ignores the fd of an
      ;; anonymous map, so the 0 the syscall path passes is fine)
      (let ((raw (%syscall mmap 0 size 3 #x22)))
        (when (or (not (integerp raw)) (< raw 4096))
          (error "gossamer: mmap for the secret arena failed (~a)" raw))
        (%syscall mlock raw size 0 0)            ; may fail under RLIMIT_MEMLOCK: best effort
        (%syscall madvise raw size 16 0)         ; MADV_DONTDUMP
        (%syscall madvise raw size 18 0)         ; MADV_WIPEONFORK
        raw)))

  (defun %arena-init ()
    (when (and (zerop *ctl*) (%arena-numbers) (%baked "%GC-SAFE-BLOCK-6"))
      (setf *ctl* (%mmap-secret +ctl-size+))))

  (defun %arena-lock ()
    (let ((a *ctl*))
      (loop (if (zerop (xchg-mem a 1))
                (return)
                (loop (if (zerop (mem-ref a :u8)) (return) (pause)))))))

  (defun %arena-unlock () (mfence) (setf (%ctl 0) 0))

  (defmacro %with-arena-lock (&body body)
    `(progn (%arena-lock) (unwind-protect (progn ,@body) (%arena-unlock))))

  (defun %arena-grow (bytes)
    "Map another chunk and make it the bump region.  Lock held."
    (let* ((size (* +arena-chunk+ (ceiling bytes +arena-chunk+)))
           (raw (%mmap-secret size))
           (i (%ctl 40)))
      (when (>= i 64) (error "gossamer: the secret arena has run out of range slots"))
      (setf (%ctl (+ 48 (* 16 i))) raw
            (%ctl (+ 56 (* 16 i))) (+ raw size)
            (%ctl 40) (1+ i)
            (%ctl 8) raw
            (%ctl 16) (+ raw size))))

  (defun %arena-bump (bytes)
    "Raw address of BYTES (rounded to 16) of fresh arena.  Lock held."
    (let ((bytes (* 16 (ceiling bytes 16))))
      (when (> (+ (%ctl 8) bytes) (%ctl 16)) (%arena-grow bytes))
      (let ((raw (%ctl 8)))
        (setf (%ctl 8) (+ raw bytes))
        raw)))

  (defun %kind-code (kind) (ecase kind (:octets 1) (:fixnums 2) (:ub64 3)))

  (defun %arena-new (kind n)
    "A fresh zeroed vector: header (N << 8) | SUBTAG, 8 bytes of padding (the free-list
link), then the elements.  Lock held."
    (multiple-value-bind (subtag bytes)
        (ecase kind
          (:octets (values #x11 (+ 16 n)))
          (:fixnums (values #x32 (+ 16 (* 8 n))))
          (:ub64 (error "gossamer: no (unsigned-byte 64) buffers on modus (a value past the ~
                         fixnum range would be a heap bignum the arena cannot hold)")))
      (let ((raw (%arena-bump bytes)))
        (setf (mem-ref raw :u32) (logior (ash (logand n #xFFFFFF) 8) subtag)
              (mem-ref (+ raw 4) :u32) (ash n -24))
        (setf (%ctl 24) (1+ (%ctl 24)))
        (%word->val (logior raw 9)))))

  (defun %bucket (kind n)
    "Address of the free-list entry for (KIND, N), made if new.  Lock held."
    (let ((code (%kind-code kind)) (nb (%ctl 1088)))
      (dotimes (j nb)
        (let ((e (+ *ctl* 1096 (* 24 j))))
          (when (and (= (mem-ref e :u64) code) (= (mem-ref (+ e 8) :u64) n))
            (return-from %bucket e))))
      (when (>= nb 256) (error "gossamer: too many distinct buffer sizes"))
      (let ((e (+ *ctl* 1096 (* 24 nb))))
        (setf (mem-ref e :u64) code (mem-ref (+ e 8) :u64) n (mem-ref (+ e 16) :u64) 0
              (%ctl 1088) (1+ nb))
        e)))

  (defun %arena-acquire (kind n)
    (%with-arena-lock
      (let* ((e (%bucket kind n)) (head (mem-ref (+ e 16) :u64)))
        (if (zerop head)
            (%arena-new kind n)
            (progn (setf (mem-ref (+ e 16) :u64) (mem-ref (+ head 8) :u64)
                         (mem-ref (+ head 8) :u64) 0
                         (%ctl 32) (1- (%ctl 32)))
                   (%word->val (logior head 9)))))))

  (defun %arena-release (kind n buffer)
    (fill buffer 0)
    (let ((raw (- (%val->word buffer) 9)))
      (%with-arena-lock
        (let ((e (%bucket kind n)))
          (setf (mem-ref (+ raw 8) :u64) (mem-ref (+ e 16) :u64)
                (mem-ref (+ e 16) :u64) raw
                (%ctl 32) (1+ (%ctl 32)))))))

  (defun %in-arena-p (object)
    (let ((w (%val->word object)))
      (and (= (logand w 15) 9) (/= *ctl* 0)
           (dotimes (i (%ctl 40) nil)
             (when (and (<= (%ctl (+ 48 (* 16 i))) w) (< w (%ctl (+ 56 (* 16 i)))))
               (return t))))))

  (%arena-init))

;;; ---------------------------------------------------------------------------
;;; Allocation (long-lived: keys, pool slabs).
;;; ---------------------------------------------------------------------------

(defvar *static-bytes* 0 "Bytes of fixed memory ever allocated (never reclaimed on SBCL).")

(defun static-bytes-used () *static-bytes*)

(defun %alloc (n element-type)
  (incf *static-bytes* (* n (if (equal element-type '(unsigned-byte 8)) 1 8)))
  #+sbcl (sb-int:make-static-vector n :element-type element-type :initial-element 0)
  #+modus (if (%arena-available-p)
              (%with-arena-lock
                (%arena-new (cond ((equal element-type '(unsigned-byte 8)) :octets)
                                  ((eq element-type 'fixnum) :fixnums)
                                  (t :ub64))
                            n))
              (make-array n :element-type element-type :initial-element 0))
  #-(or sbcl modus) (make-array n :element-type element-type :initial-element 0))

(defun make-fixed-octets (n) "A zeroed fixed (unsigned-byte 8) vector of length N." (%alloc n '(unsigned-byte 8)))
(defun make-fixed-ub64 (n) "A zeroed fixed (unsigned-byte 64) vector of length N." (%alloc n '(unsigned-byte 64)))
(defun make-fixed-fixnums (n) "A zeroed fixed FIXNUM vector of length N." (%alloc n 'fixnum))

(defun fixed-p (object)
  "True when OBJECT lives in memory the collector never moves."
  #+sbcl (and (typep object '(simple-array * (*)))
              (not (sb-kernel::dynamic-space-obj-p object)))
  #+modus (and (vectorp object) (%in-arena-p object))
  #-(or sbcl modus) (declare (ignore object))
  #-(or sbcl modus) nil)

(defun check-fixed (object &optional what)
  "Assert that OBJECT is in fixed memory; signal NOT-FIXED otherwise.  Returns OBJECT.
Put this where a secret enters a function: it is the line that says \"this is a
secret\" in the source and enforces it at run time."
  (unless (or (fixed-p object) *allow-unfixed*)
    (error 'not-fixed :object object :what what))
  object)

(defun wipe (&rest buffers)
  "Zero each buffer in place (NILs are skipped).  Returns NIL."
  (dolist (b buffers) (when b (fill b 0)))
  nil)

(defun fixed-copy (source &key (start 0) end)
  "A new fixed octet vector holding SOURCE[START,END).  For bringing a secret that
arrived on the heap (from a file, a socket) into fixed memory once, at the edge."
  (let* ((end (or end (length source)))
         (out (make-fixed-octets (- end start))))
    (replace out source :start2 start :end2 end)
    out))

;;; ---------------------------------------------------------------------------
;;; Scratch pool.  Buffers are keyed by (element-type . length).  A buffer is wiped
;;; when it is released, so whatever is in the pool is zero.
;;; ---------------------------------------------------------------------------

(defvar *pool* (make-hash-table :test 'equal))
(defvar *pool-lock* #+sb-thread (sb-thread:make-mutex :name "fixed pool") #-sb-thread nil)
(defvar *pool-allocated* 0)

(defmacro %with-pool-lock (&body body)
  #+sb-thread `(sb-thread:with-mutex (*pool-lock*) ,@body)
  #-sb-thread `(progn ,@body))

(defun %element-type (kind)
  (ecase kind (:octets '(unsigned-byte 8)) (:ub64 '(unsigned-byte 64)) (:fixnums 'fixnum)))

(defun %acquire (kind n)
  #+modus (when (%arena-available-p) (return-from %acquire (%arena-acquire kind n)))
  (let ((key (cons kind n)))
    (or (%with-pool-lock (pop (gethash key *pool*)))
        (progn (%with-pool-lock (incf *pool-allocated*))
               (%alloc n (%element-type kind))))))

(defun %release (kind n buffer)
  #+modus (when (%arena-available-p) (return-from %release (%arena-release kind n buffer)))
  (fill buffer 0)
  (%with-pool-lock (push buffer (gethash (cons kind n) *pool*))))

(defun acquire (kind n)
  "A zeroed fixed buffer of KIND (:octets :ub64 :fixnums) and length N from the pool.
Pair every ACQUIRE with a RELEASE in an UNWIND-PROTECT cleanup; WITH-FIXED-SCRATCH
does this for you when the set of buffers is known lexically."
  (%acquire kind n))

(defun release (kind n buffer)
  "Wipe BUFFER and return it to the pool."
  (%release kind n buffer))

(defun %kind-of (buffer)
  ;; on modus a fixnum or u64 array is a general vector, and both type specifiers
  ;; match it: there, anything that is not octets is :FIXNUMS
  #+modus (if (typep buffer '(simple-array (unsigned-byte 8) (*))) :octets :fixnums)
  #-modus
  (etypecase buffer
    ((simple-array (unsigned-byte 8) (*)) :octets)
    ((simple-array (unsigned-byte 64) (*)) :ub64)
    ((simple-array fixnum (*)) :fixnums)))

(defun pooled-copy (source &key (start 0) end)
  "A pooled fixed octet buffer holding SOURCE[START,END); FREE it when done.  The
form for bringing a transient secret into fixed memory."
  (let* ((end (or end (length source)))
         (out (%acquire :octets (- end start))))
    (replace out source :start2 start :end2 end)
    out))

(defun free (buffer)
  "Wipe BUFFER and return it to the pool (it must have come from ACQUIRE or
POOLED-COPY).  NIL is ignored."
  (when buffer (%release (%kind-of buffer) (length buffer) buffer))
  nil)

(defun own (owner &rest buffers)
  "Tie pooled BUFFERS to OWNER: when OWNER becomes garbage, the buffers are wiped and
returned to the pool.  For secrets held by an object that can be dropped without an
explicit wipe (an abandoned handshake, a forgotten keypair) -- on SBCL a pooled
buffer that is never returned is lost for good.  The finalizer closes over the
buffers, never OWNER.  Call DISOWN before freeing the buffers yourself.  Returns OWNER."
  #+sbcl (when buffers
           (sb-ext:finalize owner (lambda () (mapc #'free buffers)) :dont-save t))
  #-sbcl (declare (ignore buffers))
  owner)

(defun disown (owner)
  "Cancel OWN's finalizer for OWNER (before an explicit FREE of its buffers)."
  #+sbcl (sb-ext:cancel-finalization owner)
  #-sbcl (declare (ignore owner))
  owner)

(defun pool-stats ()
  "(values buffers-ever-allocated buffers-currently-free)"
  #+modus (when (%arena-available-p)
            (return-from pool-stats (values (%ctl 24) (%ctl 32))))
  (%with-pool-lock
    (values *pool-allocated*
            (loop for v being the hash-values of *pool* sum (length v)))))

(defmacro with-fixed-scratch ((&rest specs) &body body)
  "SPECS are (VAR KIND LENGTH), KIND one of :OCTETS :UB64 :FIXNUMS.  Each VAR is bound
to a zeroed fixed buffer from the pool for BODY's extent, and wiped and returned to
the pool on every exit, normal or not."
  (let ((cleanups '()))
    (dolist (s specs) (destructuring-bind (var kind n) s (push `(%release ,kind ,n ,var) cleanups)))
    `(let ,(loop for (var kind n) in specs collect `(,var (%acquire ,kind ,n)))
       (unwind-protect (progn ,@body)
         ,@cleanups))))

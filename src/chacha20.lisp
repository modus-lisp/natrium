;;;; chacha20.lisp — ChaCha20 stream cipher, pure Common Lisp.
;;;;
;;;; Two nonce/counter layouts share one round core:
;;;;   - the RFC 8439 variant (96-bit nonce, 32-bit counter) — chacha20-block /
;;;;     chacha20, used by ChaCha20-Poly1305 (TLS, the AEAD);
;;;;   - the original DJB variant (64-bit nonce, 64-bit counter) —
;;;;     chacha20-original-block / chacha20-original, used by SSH's
;;;;     chacha20-poly1305@openssh.com.
;;;; 256-bit key, 20 rounds.  Constant-time by construction — only 32-bit add /
;;;; xor / rotate, no tables, no secret-dependent branches.  Little-endian.

(in-package #:natrium)

(declaim (inline rotl32 u32le))
(defun rotl32 (x n)
  (declare (type (unsigned-byte 32) x) (type (integer 0 31) n))
  (logand #xffffffff (logior (ash x n) (ash x (- n 32)))))

(defun u32le (bytes off)
  "Read 4 little-endian bytes of BYTES at OFF as a u32."
  (logior (aref bytes off)
          (ash (aref bytes (+ off 1)) 8)
          (ash (aref bytes (+ off 2)) 16)
          (ash (aref bytes (+ off 3)) 24)))

(defmacro %qr (st a b c d)
  "ChaCha quarter-round on state array ST at indices A B C D."
  `(let ((va (aref ,st ,a)) (vb (aref ,st ,b)) (vc (aref ,st ,c)) (vd (aref ,st ,d)))
     (declare (type (unsigned-byte 32) va vb vc vd))
     (setf va (logand #xffffffff (+ va vb))  vd (rotl32 (logxor vd va) 16))
     (setf vc (logand #xffffffff (+ vc vd))  vb (rotl32 (logxor vb vc) 12))
     (setf va (logand #xffffffff (+ va vb))  vd (rotl32 (logxor vd va) 8))
     (setf vc (logand #xffffffff (+ vc vd))  vb (rotl32 (logxor vb vc) 7))
     (setf (aref ,st ,a) va (aref ,st ,b) vb (aref ,st ,c) vc (aref ,st ,d) vd)))

(defun %chacha20-serialize (st)
  "20 rounds over initial state ST (16 u32 words), add the original state, and
   serialize little-endian to a fresh 64-byte block."
  (let ((w (copy-seq st)))
    (dotimes (i 10)                                        ; 20 rounds = 10x2
      (%qr w 0 4  8 12) (%qr w 1 5  9 13) (%qr w 2 6 10 14) (%qr w 3 7 11 15)
      (%qr w 0 5 10 15) (%qr w 1 6 11 12) (%qr w 2 7  8 13) (%qr w 3 4  9 14))
    (let ((out (make-u8v 64)))
      (dotimes (i 16 out)
        (let ((v (logand #xffffffff (+ (aref w i) (aref st i)))) (o (* 4 i)))
          (setf (aref out o)       (logand #xff v)
                (aref out (+ o 1)) (logand #xff (ash v -8))
                (aref out (+ o 2)) (logand #xff (ash v -16))
                (aref out (+ o 3)) (logand #xff (ash v -24))))))))

(defun %chacha20-state (key)
  "Fresh 16-word state with the constants and 256-bit KEY filled in (words
   12-15 left zero for the caller to set per variant)."
  (declare (type u8v key))
  (let ((st (make-array 16 :element-type '(unsigned-byte 32) :initial-element 0)))
    (setf (aref st 0) #x61707865 (aref st 1) #x3320646e   ; "expand 32-byte k"
          (aref st 2) #x79622d32 (aref st 3) #x6b206574)
    (dotimes (i 8 st) (setf (aref st (+ 4 i)) (u32le key (* 4 i))))))

;;; --- RFC 8439 variant (96-bit nonce, 32-bit counter) ---------------------
(defun chacha20-block (key counter nonce)
  "One 64-byte ChaCha20 keystream block (RFC 8439 2.3).  KEY 32 bytes, NONCE
   12 bytes, COUNTER a u32."
  (declare (type u8v key nonce))
  (let ((st (%chacha20-state key)))
    (setf (aref st 12) (logand #xffffffff counter))
    (dotimes (i 3) (setf (aref st (+ 13 i)) (u32le nonce (* 4 i))))
    (%chacha20-serialize st)))

(defun chacha20 (key nonce data &key (counter 1))
  "ChaCha20 keystream XOR (RFC 8439 2.4).  KEY 32 bytes, NONCE 12 bytes, DATA a
   byte vector.  Returns fresh DATA XOR keystream; the same call decrypts.
   COUNTER is the initial block counter (RFC's AEAD uses 1; raw ChaCha20 test
   vectors sometimes start at 0)."
  (declare (type u8v key nonce data))
  (let* ((len (length data))
         (out (make-u8v len)))
    ;; fail closed rather than silently wrap the 32-bit block counter (which
    ;; would reuse keystream) on an absurdly long (>256 GiB) message
    (when (>= (+ counter (ceiling len 64)) (ash 1 32))
      (error "chacha20: 32-bit block counter would wrap (message too long)"))
    (loop for blk from 0
          for base from 0 below len by 64 do
      (let ((ks (chacha20-block key (+ counter blk) nonce)))
        (loop for i from base below (min len (+ base 64)) do
          (setf (aref out i) (logxor (aref data i) (aref ks (- i base)))))))
    out))

;;; --- original DJB variant (64-bit nonce, 64-bit counter) -----------------
;;; Words 12-13 are the 64-bit block counter (little-endian), words 14-15 the
;;; 64-bit nonce (two little-endian words from the 8-byte NONCE).  This is what
;;; SSH's chacha20-poly1305@openssh.com uses; conch builds the OpenSSH AEAD on it.
(defun chacha20-original-block (key counter nonce)
  "One 64-byte keystream block of the original ChaCha20.  KEY 32 bytes, NONCE
   8 bytes, COUNTER a 64-bit block counter."
  (declare (type u8v key nonce))
  (let ((st (%chacha20-state key)))
    (setf (aref st 12) (logand #xffffffff counter)
          (aref st 13) (logand #xffffffff (ash counter -32))
          (aref st 14) (u32le nonce 0)
          (aref st 15) (u32le nonce 4))
    (%chacha20-serialize st)))

(defun chacha20-original (key nonce data &key (counter 0))
  "Original-ChaCha20 keystream XOR.  KEY 32 bytes, NONCE 8 bytes.  Returns fresh
   DATA XOR keystream from block COUNTER onward."
  (declare (type u8v key nonce data))
  (let* ((len (length data))
         (out (make-u8v len)))
    (loop for blk from 0
          for base from 0 below len by 64 do
      (let ((ks (chacha20-original-block key (+ counter blk) nonce)))
        (loop for i from base below (min len (+ base 64)) do
          (setf (aref out i) (logxor (aref data i) (aref ks (- i base)))))))
    out))

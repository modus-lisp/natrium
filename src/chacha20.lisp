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

(defun %chacha20-keystream (st w ks)
  "20 rounds over initial state ST (16 u32 words) in the scratch array W, add
   the original state, and serialize little-endian into the 64-byte KS.
   Returns KS.  The callers keep W and KS across the blocks of a message."
  (dotimes (i 16) (setf (aref w i) (aref st i)))
  (dotimes (i 10)                                        ; 20 rounds = 10x2
    (%qr w 0 4  8 12) (%qr w 1 5  9 13) (%qr w 2 6 10 14) (%qr w 3 7 11 15)
    (%qr w 0 5 10 15) (%qr w 1 6 11 12) (%qr w 2 7  8 13) (%qr w 3 4  9 14))
  (dotimes (i 16 ks)
    (let ((v (logand #xffffffff (+ (aref w i) (aref st i)))) (o (* 4 i)))
      (setf (aref ks o)       (logand #xff v)
            (aref ks (+ o 1)) (logand #xff (ash v -8))
            (aref ks (+ o 2)) (logand #xff (ash v -16))
            (aref ks (+ o 3)) (logand #xff (ash v -24))))))

(defun %chacha20-scratch ()
  ;; A simple-vector, not (unsigned-byte 32): the words are fixnums on every
  ;; 64-bit Lisp, and on modus a store into a specialized array is a call.
  (make-array 16 :initial-element 0))

(defun %chacha20-serialize (st)
  "The keystream block of state ST as a fresh 64-byte vector."
  (%chacha20-keystream st (%chacha20-scratch) (make-u8v 64)))

(defun %chacha20-state (key)
  "Fresh 16-word state with the constants and 256-bit KEY filled in (words
   12-15 left zero for the caller to set per variant)."
  (declare (type u8v key))
  (let ((st (%chacha20-scratch)))
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

(defmacro %qr-locals (a b c d)
  "ChaCha quarter-round on four local variables."
  `(setf ,a (logand #xffffffff (+ ,a ,b))  ,d (rotl32 (logxor ,d ,a) 16)
         ,c (logand #xffffffff (+ ,c ,d))  ,b (rotl32 (logxor ,b ,c) 12)
         ,a (logand #xffffffff (+ ,a ,b))  ,d (rotl32 (logxor ,d ,a) 8)
         ,c (logand #xffffffff (+ ,c ,d))  ,b (rotl32 (logxor ,b ,c) 7)))

(defun %chacha20-xor (key data start end out ostart counter original na nb nc)
  "DATA[START,END) XOR the keystream into OUT from OSTART (OUT may be DATA itself, at the same place): blocks
   from COUNTER on, the nonce words NA NB (NC) laid out as ORIGINAL says -- the original DJB variant, words
   12-13 a 64-bit counter and 14-15 the nonce, or RFC 8439's, word 12 the counter and 13-15 the nonce.  The
   sixteen state words are LOCALS and the rounds unrolled, and each keystream word is XORed straight into
   OUT: on modus, where an array slot costs a call or a check and a local does not, this is 3.4x the round
   core over a scratch vector (16.8 -> 57 MB/s)."
  (declare (type u8v key data out) (type fixnum start end ostart))
  (let ((k0 (u32le key 0)) (k1 (u32le key 4)) (k2 (u32le key 8)) (k3 (u32le key 12))
        (k4 (u32le key 16)) (k5 (u32le key 20)) (k6 (u32le key 24)) (k7 (u32le key 28))
        (len (- end start)))
    (loop for base from 0 below len by 64
          for ctr from counter
          do (let* ((i12 (logand #xffffffff ctr))
                    (i13 (if original (logand #xffffffff (ash ctr -32)) na))
                    (i14 (if original na nb))
                    (i15 (if original nb nc))
                    (x0 #x61707865) (x1 #x3320646e) (x2 #x79622d32) (x3 #x6b206574)
                    (x4 k0) (x5 k1) (x6 k2) (x7 k3) (x8 k4) (x9 k5) (x10 k6) (x11 k7)
                    (x12 i12) (x13 i13) (x14 i14) (x15 i15))
               (dotimes (r 10)                               ; 20 rounds = 10x (column, diagonal)
                 (%qr-locals x0 x4 x8 x12) (%qr-locals x1 x5 x9 x13)
                 (%qr-locals x2 x6 x10 x14) (%qr-locals x3 x7 x11 x15)
                 (%qr-locals x0 x5 x10 x15) (%qr-locals x1 x6 x11 x12)
                 (%qr-locals x2 x7 x8 x13) (%qr-locals x3 x4 x9 x14))
               (macrolet ((word (i x init)
                            ;; keystream word I (the round's X plus the block's initial word), little-endian,
                            ;; XORed over its four bytes -- fewer at the message's end
                            `(let ((v (logand #xffffffff (+ ,x ,init)))
                                   (o (+ base ,(* 4 i))))
                               (if (<= (+ o 4) len)
                                   (let ((d (+ start o)) (e (+ ostart o)))
                                     (setf (aref out e) (logxor (aref data d) (logand v #xff))
                                           (aref out (+ e 1)) (logxor (aref data (+ d 1)) (logand (ash v -8) #xff))
                                           (aref out (+ e 2)) (logxor (aref data (+ d 2)) (logand (ash v -16) #xff))
                                           (aref out (+ e 3)) (logxor (aref data (+ d 3)) (ash v -24))))
                                   (loop for j from 0 below (- len o)
                                         do (setf (aref out (+ ostart o j))
                                                  (logxor (aref data (+ start o j)) (logand (ash v (* -8 j)) #xff))))))))
                 (word 0 x0 #x61707865) (word 1 x1 #x3320646e) (word 2 x2 #x79622d32) (word 3 x3 #x6b206574)
                 (word 4 x4 k0) (word 5 x5 k1) (word 6 x6 k2) (word 7 x7 k3)
                 (word 8 x8 k4) (word 9 x9 k5) (word 10 x10 k6) (word 11 x11 k7)
                 (word 12 x12 i12) (word 13 x13 i13) (word 14 x14 i14) (word 15 x15 i15))))
    out))

(defun chacha20 (key nonce data &key (counter 1))
  "ChaCha20 keystream XOR (RFC 8439 2.4).  KEY 32 bytes, NONCE 12 bytes, DATA a
   byte vector.  Returns fresh DATA XOR keystream; the same call decrypts.
   COUNTER is the initial block counter (RFC's AEAD uses 1; raw ChaCha20 test
   vectors sometimes start at 0)."
  (declare (type u8v key nonce data))
  (let ((len (length data)))
    ;; fail closed rather than silently wrap the 32-bit block counter (which
    ;; would reuse keystream) on an absurdly long (>256 GiB) message
    (when (>= (+ counter (ceiling len 64)) (ash 1 32))
      (error "chacha20: 32-bit block counter would wrap (message too long)"))
    (%chacha20-xor key data 0 len (make-u8v len) 0 counter nil
                   (u32le nonce 0) (u32le nonce 4) (u32le nonce 8))))

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
  (let ((len (length data)))
    (%chacha20-xor key data 0 len (make-u8v len) 0 counter t (u32le nonce 0) (u32le nonce 4) 0)))

(defun chacha20-original-xor (key nonce buf &key (counter 0) (start 0) (end (length buf)))
  "Original-ChaCha20 keystream XOR over BUF[START,END) IN PLACE, from block COUNTER onward; returns BUF.  What
   a packet cipher wants: the body encrypted where it sits, no fresh vector and no copy."
  (declare (type u8v key nonce buf))
  (%chacha20-xor key buf start end buf start counter t (u32le nonce 0) (u32le nonce 4) 0))

;;;; noise.lisp -- the Noise IK and XK handshakes and transport, generic over the DH group.
;;;;
;;;; The handshake state machine, the symmetric state, the cipher state and the
;;;; session split are protocol logic, not curve logic.  They live here, and take
;;;; the curve as a NOISE-SUITE: key generation, public-key encoding and decoding,
;;;; the DH, and the pre-message normalisation.  natrium itself stays free of any
;;;; curve dependency; the suite is supplied by the caller.
;;;;
;;;; The first user is FIPS (jmcorgan/fips @ 57bc510, src/noise/{mod,handshake,
;;;; session}.rs), whose suite is secp256k1 and whose binding lives in cl-fips.
;;;; Read against upstream:
;;;;
;;;;   SymmetricState::initialize  name <= 32 bytes is zero-padded, else hashed;
;;;;                               ck = h = that value.  No prologue is mixed.
;;;;   mix_hash                    h = SHA-256(h || data)
;;;;   mix_key                     HKDF-SHA256(salt = ck, ikm, info = "") -> 64;
;;;;                               ck = out[0..32], k = out[32..64], n = 0
;;;;   encrypt_and_hash            ct = AEAD(k, n++, aad = EMPTY, pt); mix_hash(ct)
;;;;                               (FIPS deviation: Noise uses aad = h)
;;;;   split                       HKDF-SHA256(salt = ck, ikm = "", info = "")
;;;;                               -> c1 = out[0..32], c2 = out[32..64]
;;;;   into_session                initiator sends c1 / receives c2;
;;;;                               responder sends c2 / receives c1
;;;;   CipherState nonce           12 bytes: 4 zero bytes || counter u64 LE
;;;;
;;;; IK pattern:   <- s   ...   -> e, es, s, ss, epoch   <- e, ee, se, epoch
;;;; msg1 = e || enc(s) || enc(epoch)     msg2 = e || enc(epoch)
;;;; with e, s the suite's public-key size, enc() adding a 16-byte tag, and the
;;;; epoch 8 bytes.  For secp256k1 (33-byte keys) that is 106 and 57 bytes.
;;;;
;;;; XK pattern (handshake.rs new_xk_* / write_xk_* / read_xk_*):
;;;;   <- s   ...   -> e, es   <- e, ee, epoch   -> s, se, epoch
;;;; msg1 = e        msg2 = e || enc(epoch)      msg3 = enc(s) || enc(epoch)
;;;; The pre-message is the same normalised responder key as IK, under the XK
;;;; protocol name.  No framing inside the Noise bytes: for secp256k1 that is
;;;; 33, 57 and 73 bytes.  "se" in msg3 is DH(initiator s, responder e).
;;;;
;;;; Transport (mod.rs CipherState, session.rs NoiseSession): the send side
;;;; refuses nonce 2^64-1; the receive side checks an explicit counter against a
;;;; 2048-wide sliding replay window (replay.rs) and accepts it into the window
;;;; only after the AEAD opens.  The *-with-aad variants are FMP's established
;;;; path, whose AAD is the 16-byte outer header.

(in-package #:natrium.noise)

(defconstant +aead-tag-size+ 16 "Poly1305 tag.")
(defconstant +epoch-size+ 8 "Startup epoch, for restart detection.")

(define-condition noise-error (error)
  ((reason :initarg :reason :reader noise-error-reason))
  (:report (lambda (c s) (format s "Noise error: ~a" (noise-error-reason c)))))

(defun noise-fail (reason) (error 'noise-error :reason reason))

;;; --- The suite: everything curve-specific ----------------------------------

(defstruct noise-suite
  "The DH group a Noise handshake runs over.  Keys are opaque to this module:
   GENERATE returns a key pair, PUBLIC-BYTES its wire form, DECODE a point
   from wire bytes (or NIL if invalid), DH (key point) a 32-byte shared
   secret, and PREMESSAGE the byte form of a static key mixed in as a
   pre-message.  IK-NAME and XK-NAME are the full protocol names."
  name
  ik-name
  xk-name
  pubkey-size
  generate        ; () -> key
  public-bytes    ; key -> wire bytes
  decode          ; wire bytes -> point, or NIL
  dh              ; (key point) -> 32 bytes
  premessage)     ; wire bytes -> pre-message bytes

(defun ik-msg1-size (suite)
  (+ (* 2 (noise-suite-pubkey-size suite)) +aead-tag-size+ (+ +epoch-size+ +aead-tag-size+)))

(defun ik-msg2-size (suite)
  (+ (noise-suite-pubkey-size suite) (+ +epoch-size+ +aead-tag-size+)))

(defun xk-msg1-size (suite) (noise-suite-pubkey-size suite))

(defun xk-msg2-size (suite)
  (+ (noise-suite-pubkey-size suite) (+ +epoch-size+ +aead-tag-size+)))

(defun xk-msg3-size (suite)
  (+ (noise-suite-pubkey-size suite) +aead-tag-size+ (+ +epoch-size+ +aead-tag-size+)))

;;; --- Byte helpers -----------------------------------------------------------

(defun u8 (n) (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

(defun u8-concat (&rest vs)
  (let* ((out (u8 (reduce #'+ vs :key #'length))) (pos 0))
    (dolist (v vs out)
      (replace out v :start1 pos)
      (incf pos (length v)))))

(defun u8-subseq (v start &optional end)
  (let ((out (u8 (- (or end (length v)) start))))
    (replace out v :start2 start :end2 end)
    out))

(defun ascii-bytes (string)
  (let ((v (u8 (length string))))
    (dotimes (i (length string) v) (setf (aref v i) (char-code (char string i))))))

(defun encode-u64le (value)
  "8-byte little-endian encoding of VALUE (the nonce counter)."
  (let ((out (u8 8)))
    (dotimes (i 8 out)
      (setf (aref out i) (ldb (byte 8 (* 8 i)) value)))))

;;; --- CipherState (mod.rs) ---------------------------------------------------

(defstruct (cipher-state (:constructor make-cipher-state (&optional key)))
  key            ; 32-byte key, or NIL before the first mix_key
  (nonce 0))

(defun counter-nonce (counter)
  "mod.rs counter_to_nonce: 4 zero bytes then the 64-bit counter little-endian."
  (u8-concat (u8 4) (encode-u64le counter)))

(defconstant +max-nonce+ (1- (expt 2 64))
  "mod.rs advance_nonce refuses this value: it is never used as a nonce.")

(defconstant +max-message-size+ 65535 "mod.rs MAX_MESSAGE_SIZE.")

(defun as-u8v (v) (coerce v '(simple-array (unsigned-byte 8) (*))))

(defun cipher-advance-nonce (cs)
  (let ((n (cipher-state-nonce cs)))
    (when (>= n +max-nonce+) (noise-fail "nonce overflow"))
    (setf (cipher-state-nonce cs) (1+ n))
    n))

(defun cipher-encrypt (cs plaintext &optional (aad (u8 0)))
  "ChaCha20-Poly1305 at the next nonce; returns ct || tag.  AAD is empty for
   the handshake and plain transport (FIPS deviation), the outer header for FMP."
  (unless (cipher-state-key cs) (noise-fail "cipher has no key"))
  (when (> (length plaintext) (- +max-message-size+ +aead-tag-size+))
    (noise-fail "message too large"))
  (let ((n (cipher-advance-nonce cs)))
    (multiple-value-bind (ct tag)
        (n:chacha20-poly1305-encrypt (cipher-state-key cs) (counter-nonce n)
                                     (as-u8v plaintext) (as-u8v aad))
      (u8-concat ct tag))))

(defun cipher-decrypt-with-counter (cs counter ciphertext &optional (aad (u8 0)))
  (unless (cipher-state-key cs) (noise-fail "cipher has no key"))
  (when (< (length ciphertext) +aead-tag-size+) (noise-fail "ciphertext shorter than tag"))
  (let* ((split (- (length ciphertext) +aead-tag-size+))
         (pt (n:chacha20-poly1305-decrypt (cipher-state-key cs) (counter-nonce counter)
                                          (u8-subseq ciphertext 0 split)
                                          (u8-subseq ciphertext split)
                                          (as-u8v aad))))
    (or pt (noise-fail "decryption failed"))))

(defun cipher-decrypt (cs ciphertext)
  "Decrypt at the internal counter.  As in mod.rs `decrypt`, the counter
   advances before authentication, so a failed decrypt still consumes it."
  (cipher-decrypt-with-counter cs (cipher-advance-nonce cs) ciphertext))

;;; --- SymmetricState (handshake.rs) ------------------------------------------

(defstruct (symmetric-state (:conc-name ss-))
  ck h (cipher (make-cipher-state)))

(defun symmetric-initialize (protocol-name)
  (let* ((name (ascii-bytes protocol-name))
         (h (if (<= (length name) 32)
                (let ((v (u8 32))) (replace v name) v)
                (n:sha256 name))))
    (make-symmetric-state :ck (copy-seq h) :h h)))

(defun mix-hash (ss data)
  (setf (ss-h ss) (n:sha256 (u8-concat (ss-h ss) data))))

(defun hkdf2 (ck ikm)
  "HKDF-SHA256(salt = CK, IKM, info = empty) -> two 32-byte outputs."
  (let ((out (n:hkdf-sha256 ck ikm (u8 0) 64)))
    (values (u8-subseq out 0 32) (u8-subseq out 32 64))))

(defun mix-key (ss ikm)
  (multiple-value-bind (ck k) (hkdf2 (ss-ck ss) ikm)
    (setf (ss-ck ss) ck
          (ss-cipher ss) (make-cipher-state k))))

(defun encrypt-and-hash (ss plaintext)
  (let ((ct (cipher-encrypt (ss-cipher ss) plaintext)))
    (mix-hash ss ct)
    ct))

(defun decrypt-and-hash (ss ciphertext)
  (let ((pt (cipher-decrypt (ss-cipher ss) ciphertext)))
    (mix-hash ss ciphertext)
    pt))

(defun symmetric-split (ss)
  (multiple-value-bind (k1 k2) (hkdf2 (ss-ck ss) (u8 0))
    (values (make-cipher-state k1) (make-cipher-state k2))))

;;; --- HandshakeState ----------------------------------------------------------

(defstruct (handshake (:conc-name hs-))
  suite
  role                 ; :initiator or :responder
  pattern              ; :ik or :xk
  (progress :initial)  ; :initial :message1-done :message2-done (XK) :complete
  symmetric
  static               ; our key pair
  ephemeral            ; our ephemeral key pair
  remote-static        ; the peer's point
  remote-ephemeral     ; the peer's point
  local-epoch          ; 8 bytes
  remote-epoch)

(defun hs-pubkey-size (hs) (noise-suite-pubkey-size (hs-suite hs)))

(defun hs-public-bytes (hs key)
  (funcall (noise-suite-public-bytes (hs-suite hs)) key))

(defun hs-decode (hs bytes)
  (or (funcall (noise-suite-decode (hs-suite hs)) bytes)
      (noise-fail "invalid public key")))

(defun hs-dh (hs key point)
  (funcall (noise-suite-dh (hs-suite hs)) key point))

(defun hs-generate (hs)
  (funcall (noise-suite-generate (hs-suite hs))))

(defun %make-initiator (suite pattern protocol-name static remote-static-bytes local-epoch)
  "Both patterns know the responder's static key up front: <- s is mixed as a
   pre-message under the pattern's protocol name."
  (let* ((rs (or (funcall (noise-suite-decode suite) remote-static-bytes)
                 (noise-fail "invalid public key")))
         (sym (symmetric-initialize protocol-name)))
    (mix-hash sym (funcall (noise-suite-premessage suite) remote-static-bytes))
    (make-handshake :suite suite :pattern pattern :role :initiator :symmetric sym
                    :static static :remote-static rs :local-epoch local-epoch)))

(defun %make-responder (suite pattern protocol-name static local-epoch)
  (let ((sym (symmetric-initialize protocol-name)))
    (mix-hash sym (funcall (noise-suite-premessage suite)
                           (funcall (noise-suite-public-bytes suite) static)))
    (make-handshake :suite suite :pattern pattern :role :responder :symmetric sym
                    :static static :local-epoch local-epoch)))

(defun make-ik-initiator (suite static remote-static-bytes local-epoch)
  "handshake.rs new_initiator.  REMOTE-STATIC-BYTES is the responder's public key."
  (%make-initiator suite :ik (noise-suite-ik-name suite) static remote-static-bytes local-epoch))

(defun make-ik-responder (suite static local-epoch)
  "handshake.rs new_responder."
  (%make-responder suite :ik (noise-suite-ik-name suite) static local-epoch))

(defun make-xk-initiator (suite static remote-static-bytes local-epoch)
  "handshake.rs new_xk_initiator.  REMOTE-STATIC-BYTES is the responder's public key."
  (%make-initiator suite :xk (noise-suite-xk-name suite) static remote-static-bytes local-epoch))

(defun make-xk-responder (suite static local-epoch)
  "handshake.rs new_xk_responder.  The initiator's static key arrives in msg3."
  (%make-responder suite :xk (noise-suite-xk-name suite) static local-epoch))

(defun check-state (hs role progress &optional (pattern (hs-pattern hs)))
  (unless (eq (hs-pattern hs) pattern)
    (noise-fail (format nil "expected a ~a handshake, got ~a" pattern (hs-pattern hs))))
  (unless (eq (hs-role hs) role) (noise-fail (format nil "expected ~(~a~)" role)))
  (unless (eq (hs-progress hs) progress)
    (noise-fail (format nil "expected state ~(~a~), got ~(~a~)" progress (hs-progress hs)))))

(defun ik-write-message-1 (hs &key ephemeral)
  "Initiator: -> e, es, s, ss, epoch.  EPHEMERAL (a key pair) is for tests;
   normally a fresh one is generated."
  (check-state hs :initiator :initial :ik)
  (let* ((sym (hs-symmetric hs))
         (e (setf (hs-ephemeral hs) (or ephemeral (hs-generate hs))))
         (e-pub (hs-public-bytes hs e)))
    (mix-hash sym e-pub)                                              ; -> e
    (mix-key sym (hs-dh hs e (hs-remote-static hs)))                  ; -> es
    (let ((enc-s (encrypt-and-hash sym (hs-public-bytes hs (hs-static hs))))) ; -> s
      (mix-key sym (hs-dh hs (hs-static hs) (hs-remote-static hs)))   ; -> ss
      (let ((enc-epoch (encrypt-and-hash sym (hs-local-epoch hs))))   ; -> epoch
        (setf (hs-progress hs) :message1-done)
        (u8-concat e-pub enc-s enc-epoch)))))

(defun ik-read-message-1 (hs msg)
  "Responder: process msg1, learning the initiator's static key and epoch."
  (check-state hs :responder :initial :ik)
  (unless (= (length msg) (ik-msg1-size (hs-suite hs))) (noise-fail "msg1 has wrong length"))
  (let* ((sym (hs-symmetric hs))
         (pk (hs-pubkey-size hs))
         (e-bytes (u8-subseq msg 0 pk))
         (re (hs-decode hs e-bytes))
         (s-end (+ pk pk +aead-tag-size+)))
    (setf (hs-remote-ephemeral hs) re)
    (mix-hash sym e-bytes)                                            ; -> e
    (mix-key sym (hs-dh hs (hs-static hs) re))                        ; -> es
    (let* ((s-bytes (decrypt-and-hash sym (u8-subseq msg pk s-end)))  ; -> s
           (rs (hs-decode hs s-bytes)))
      (setf (hs-remote-static hs) rs)
      (mix-key sym (hs-dh hs (hs-static hs) rs))                      ; -> ss
      (setf (hs-remote-epoch hs) (decrypt-and-hash sym (u8-subseq msg s-end))) ; -> epoch
      (setf (hs-progress hs) :message1-done)
      hs)))

(defun ik-write-message-2 (hs &key ephemeral)
  "Responder: <- e, ee, se, epoch.  Returns msg2."
  (check-state hs :responder :message1-done :ik)
  (let* ((sym (hs-symmetric hs))
         (re (hs-remote-ephemeral hs))
         (e (setf (hs-ephemeral hs) (or ephemeral (hs-generate hs))))
         (e-pub (hs-public-bytes hs e)))
    (mix-hash sym e-pub)                                              ; <- e
    (mix-key sym (hs-dh hs e re))                                     ; <- ee
    (mix-key sym (hs-dh hs (hs-static hs) re))                        ; <- se
    (let ((enc-epoch (encrypt-and-hash sym (hs-local-epoch hs))))     ; <- epoch
      (setf (hs-progress hs) :complete)
      (u8-concat e-pub enc-epoch))))

(defun ik-read-message-2 (hs msg)
  "Initiator: process msg2 and complete the handshake."
  (check-state hs :initiator :message1-done :ik)
  (unless (= (length msg) (ik-msg2-size (hs-suite hs))) (noise-fail "msg2 has wrong length"))
  (let* ((sym (hs-symmetric hs))
         (pk (hs-pubkey-size hs))
         (e-bytes (u8-subseq msg 0 pk))
         (re (hs-decode hs e-bytes)))
    (setf (hs-remote-ephemeral hs) re)
    (mix-hash sym e-bytes)                                            ; <- e
    (mix-key sym (hs-dh hs (hs-ephemeral hs) re))                     ; <- ee
    (mix-key sym (hs-dh hs (hs-ephemeral hs) (hs-remote-static hs)))  ; <- se
    (setf (hs-remote-epoch hs) (decrypt-and-hash sym (u8-subseq msg pk))) ; <- epoch
    (setf (hs-progress hs) :complete)
    hs))

;;; --- XK (handshake.rs, "XK Pattern Methods") ---------------------------------

(defun xk-write-message-1 (hs &key ephemeral)
  "Initiator: -> e, es.  Returns msg1 (the ephemeral key only)."
  (check-state hs :initiator :initial :xk)
  (let* ((sym (hs-symmetric hs))
         (e (setf (hs-ephemeral hs) (or ephemeral (hs-generate hs))))
         (e-pub (hs-public-bytes hs e)))
    (mix-hash sym e-pub)                                              ; -> e
    (mix-key sym (hs-dh hs e (hs-remote-static hs)))                  ; -> es
    (setf (hs-progress hs) :message1-done)
    e-pub))

(defun xk-read-message-1 (hs msg)
  "Responder: process msg1.  The initiator's identity is NOT learned here."
  (check-state hs :responder :initial :xk)
  (unless (= (length msg) (xk-msg1-size (hs-suite hs))) (noise-fail "msg1 has wrong length"))
  (let* ((sym (hs-symmetric hs))
         (e-bytes (u8-subseq msg 0 (hs-pubkey-size hs)))
         (re (hs-decode hs e-bytes)))
    (setf (hs-remote-ephemeral hs) re)
    (mix-hash sym e-bytes)                                            ; -> e
    (mix-key sym (hs-dh hs (hs-static hs) re))                        ; -> es
    (setf (hs-progress hs) :message1-done)
    hs))

(defun xk-write-message-2 (hs &key ephemeral)
  "Responder: <- e, ee, epoch.  Returns msg2."
  (check-state hs :responder :message1-done :xk)
  (let* ((sym (hs-symmetric hs))
         (re (hs-remote-ephemeral hs))
         (e (setf (hs-ephemeral hs) (or ephemeral (hs-generate hs))))
         (e-pub (hs-public-bytes hs e)))
    (mix-hash sym e-pub)                                              ; <- e
    (mix-key sym (hs-dh hs e re))                                     ; <- ee
    (let ((enc-epoch (encrypt-and-hash sym (hs-local-epoch hs))))     ; <- epoch
      (setf (hs-progress hs) :message2-done)
      (u8-concat e-pub enc-epoch))))

(defun xk-read-message-2 (hs msg)
  "Initiator: process msg2, learning the responder's epoch.  msg3 still to go."
  (check-state hs :initiator :message1-done :xk)
  (unless (= (length msg) (xk-msg2-size (hs-suite hs))) (noise-fail "msg2 has wrong length"))
  (let* ((sym (hs-symmetric hs))
         (pk (hs-pubkey-size hs))
         (e-bytes (u8-subseq msg 0 pk))
         (re (hs-decode hs e-bytes)))
    (setf (hs-remote-ephemeral hs) re)
    (mix-hash sym e-bytes)                                            ; <- e
    (mix-key sym (hs-dh hs (hs-ephemeral hs) re))                     ; <- ee
    (setf (hs-remote-epoch hs) (decrypt-and-hash sym (u8-subseq msg pk))) ; <- epoch
    (setf (hs-progress hs) :message2-done)
    hs))

(defun xk-write-message-3 (hs)
  "Initiator: -> s, se, epoch.  Returns msg3 and completes the handshake."
  (check-state hs :initiator :message2-done :xk)
  (let* ((sym (hs-symmetric hs))
         (enc-s (encrypt-and-hash sym (hs-public-bytes hs (hs-static hs))))) ; -> s
    (mix-key sym (hs-dh hs (hs-static hs) (hs-remote-ephemeral hs)))  ; -> se
    (let ((enc-epoch (encrypt-and-hash sym (hs-local-epoch hs))))      ; -> epoch
      (setf (hs-progress hs) :complete)
      (u8-concat enc-s enc-epoch))))

(defun xk-read-message-3 (hs msg)
  "Responder: process msg3, learning the initiator's static key and epoch."
  (check-state hs :responder :message2-done :xk)
  (unless (= (length msg) (xk-msg3-size (hs-suite hs))) (noise-fail "msg3 has wrong length"))
  (let* ((sym (hs-symmetric hs))
         (s-end (+ (hs-pubkey-size hs) +aead-tag-size+))
         (s-bytes (decrypt-and-hash sym (u8-subseq msg 0 s-end)))     ; -> s
         (rs (hs-decode hs s-bytes)))
    (setf (hs-remote-static hs) rs)
    (mix-key sym (hs-dh hs (hs-ephemeral hs) rs))                     ; -> se
    (setf (hs-remote-epoch hs) (decrypt-and-hash sym (u8-subseq msg s-end))) ; -> epoch
    (setf (hs-progress hs) :complete)
    hs))

;;; --- Rolling-back reads (handshake.rs try_read_message_2, try_read_xk_message_2,
;;; try_read_xk_message_3) -------------------------------------------------------
;;;
;;; The plain readers mix the sender's ephemeral (and DH results) into the
;;; symmetric state, and advance the cipher nonce, BEFORE the AEAD that
;;; authenticates the message, so a message that fails partway leaves a
;;; handshake the genuine message can no longer complete.  Upstream's try_read_*
;;; snapshot exactly the fields the plain reader writes and put them back on
;;; failure; these do the same.  The saved sets are upstream's, field for field:
;;;
;;;   try_read_message_2      symmetric, remote_ephemeral, remote_epoch, progress
;;;   try_read_xk_message_2   symmetric, remote_ephemeral, remote_epoch, progress
;;;   try_read_xk_message_3   symmetric, remote_static,    remote_epoch, progress
;;;
;;; As upstream warns, the mirror is manual: a new write in a plain reader must
;;; be added to its saved set here.  The symmetric state is copied deeply
;;; (the cipher state's nonce is mutated in place by CIPHER-ADVANCE-NONCE).

(defun copy-symmetric (ss)
  (make-symmetric-state :ck (copy-seq (ss-ck ss)) :h (copy-seq (ss-h ss))
                        :cipher (copy-cipher-state (ss-cipher ss))))

(defmacro %with-rollback ((hs &rest accessors) &body body)
  "Run BODY; if it exits abnormally (any error), restore the symmetric state
   and the slots named by ACCESSORS (hs-* accessors) to their values on entry."
  (let ((saved-sym (gensym "SYM")) (ok (gensym "OK"))
        (saved (loop for a in accessors collect (gensym (symbol-name a)))))
    `(let ((,saved-sym (copy-symmetric (hs-symmetric ,hs)))
           ,@(loop for s in saved for a in accessors collect `(,s (,a ,hs)))
           (,ok nil))
       (unwind-protect (multiple-value-prog1 (progn ,@body) (setf ,ok t))
         (unless ,ok
           (setf (hs-symmetric ,hs) ,saved-sym)
           ,@(loop for s in saved for a in accessors collect `(setf (,a ,hs) ,s)))))))

(defun ik-try-read-message-2 (hs msg)
  "handshake.rs try_read_message_2: IK-READ-MESSAGE-2, leaving HS as it was if
   MSG does not authenticate (the error is still signalled)."
  (%with-rollback (hs hs-remote-ephemeral hs-remote-epoch hs-progress)
    (ik-read-message-2 hs msg)))

(defun xk-try-read-message-2 (hs msg)
  "handshake.rs try_read_xk_message_2."
  (%with-rollback (hs hs-remote-ephemeral hs-remote-epoch hs-progress)
    (xk-read-message-2 hs msg)))

(defun xk-try-read-message-3 (hs msg)
  "handshake.rs try_read_xk_message_3."
  (%with-rollback (hs hs-remote-static hs-remote-epoch hs-progress)
    (xk-read-message-3 hs msg)))

(defun handshake-hash (hs) (ss-h (hs-symmetric hs)))

;;; --- Session (session.rs) ----------------------------------------------------

;;; --- Replay window (replay.rs) ------------------------------------------------
;;;
;;; Upstream keeps HIGHEST and a 2048-bit bitmap in which bit i means "counter
;;; HIGHEST - i was seen", shifting it on every advance.  This keeps the same
;;; set as a ring indexed by COUNTER mod 2048 (one bit per counter, 256 bytes):
;;; advancing from H to C clears the slots of the counters H+1 .. C, which is
;;; exactly the zero bits the upstream shift introduces, and a counter that has
;;; fallen out of the window is never consulted because CHECK rejects
;;; HIGHEST - C >= 2048 first.  Byte arithmetic only, so no bignum shifts.

(defconstant +replay-window-size+ 2048 "mod.rs REPLAY_WINDOW_SIZE.")

(defstruct (replay-window (:constructor make-replay-window ()))
  (highest 0)
  (bits (u8 (floor +replay-window-size+ 8))))

(defun %rw-slot (counter)
  (let ((i (mod counter +replay-window-size+)))
    (values (floor i 8) (mod i 8))))

(defun %rw-seen-p (rw counter)
  (multiple-value-bind (byte bit) (%rw-slot counter)
    (logbitp bit (aref (replay-window-bits rw) byte))))

(defun %rw-mark (rw counter)
  (multiple-value-bind (byte bit) (%rw-slot counter)
    (setf (aref (replay-window-bits rw) byte)
          (logior (aref (replay-window-bits rw) byte) (ash 1 bit)))))

(defun %rw-clear (rw counter)
  (multiple-value-bind (byte bit) (%rw-slot counter)
    (setf (aref (replay-window-bits rw) byte)
          (logandc2 (aref (replay-window-bits rw) byte) (ash 1 bit)))))

(defun replay-check (rw counter)
  "replay.rs check: T if COUNTER is acceptable.  Does not update the window.
   2^64-1 is always refused (no conforming peer sends it, and accepting it
   would pin HIGHEST at the ceiling)."
  (cond ((not (and (integerp counter) (<= 0 counter) (< counter +max-nonce+))) nil)
        ((> counter (replay-window-highest rw)) t)
        ((>= (- (replay-window-highest rw) counter) +replay-window-size+) nil)
        (t (not (%rw-seen-p rw counter)))))

(defun replay-accept (rw counter)
  "replay.rs accept: record COUNTER.  Call only after a successful decrypt."
  (let ((highest (replay-window-highest rw)))
    (when (> counter highest)
      (if (>= (- counter highest) +replay-window-size+)
          (fill (replay-window-bits rw) 0)
          (loop for c from (1+ highest) to counter do (%rw-clear rw c)))
      (setf (replay-window-highest rw) counter))
    (%rw-mark rw counter)
    rw))

(defun replay-reset (rw)
  (setf (replay-window-highest rw) 0)
  (fill (replay-window-bits rw) 0)
  rw)

;;; --- Session (session.rs) ----------------------------------------------------

(defstruct (noise-session (:conc-name session-))
  role send recv handshake-hash remote-static
  (replay (make-replay-window)))

(defun handshake-into-session (hs)
  "handshake.rs into_session: split, then initiator sends c1 / responder c2."
  (unless (eq (hs-progress hs) :complete) (noise-fail "handshake not complete"))
  (multiple-value-bind (c1 c2) (symmetric-split (hs-symmetric hs))
    (multiple-value-bind (send recv)
        (if (eq (hs-role hs) :initiator) (values c1 c2) (values c2 c1))
      (make-noise-session :role (hs-role hs) :send send :recv recv
                          :handshake-hash (handshake-hash hs)
                          :remote-static (hs-remote-static hs)))))

(defun session-encrypt (session plaintext)
  (cipher-encrypt (session-send session) plaintext))

(defun session-decrypt (session ciphertext)
  (cipher-decrypt (session-recv session) ciphertext))

(defun session-decrypt-with-counter (session counter ciphertext)
  (cipher-decrypt-with-counter (session-recv session) counter ciphertext))

(defun session-current-send-counter (session)
  "session.rs current_send_counter: the counter the next encrypt will use."
  (cipher-state-nonce (session-send session)))

(defun session-encrypt-with-aad (session plaintext aad)
  "session.rs encrypt_with_aad."
  (cipher-encrypt (session-send session) plaintext aad))

(defun session-check-replay (session counter)
  (replay-check (session-replay session) counter))

(defun session-decrypt-with-replay-check (session counter ciphertext &optional (aad (u8 0)))
  "session.rs decrypt_with_replay_check[_and_aad]: refuse a replayed or stale
   COUNTER before decrypting, and accept it into the window only once the AEAD
   has opened (so forgeries cannot advance the window)."
  (unless (session-check-replay session counter)
    (noise-fail (format nil "replay detected: counter ~d" counter)))
  (let ((pt (cipher-decrypt-with-counter (session-recv session) counter ciphertext aad)))
    (replay-accept (session-replay session) counter)
    pt))

(defun session-reset-replay-window (session)
  (replay-reset (session-replay session)))

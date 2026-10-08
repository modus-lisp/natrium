;;;; noise.lisp -- the Noise IK handshake and transport, generic over the DH group.
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
   pre-message.  IK-NAME is the full protocol name."
  name
  ik-name
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

(defun cipher-encrypt (cs plaintext)
  "ChaCha20-Poly1305 with empty AAD at the next nonce; returns ct || tag."
  (unless (cipher-state-key cs) (noise-fail "cipher has no key"))
  (let ((n (cipher-state-nonce cs)))
    (setf (cipher-state-nonce cs) (1+ n))
    (multiple-value-bind (ct tag)
        (n:chacha20-poly1305-encrypt (cipher-state-key cs) (counter-nonce n)
                                     (coerce plaintext '(simple-array (unsigned-byte 8) (*))))
      (u8-concat ct tag))))

(defun cipher-decrypt-with-counter (cs counter ciphertext)
  (unless (cipher-state-key cs) (noise-fail "cipher has no key"))
  (when (< (length ciphertext) +aead-tag-size+) (noise-fail "ciphertext shorter than tag"))
  (let* ((split (- (length ciphertext) +aead-tag-size+))
         (pt (n:chacha20-poly1305-decrypt (cipher-state-key cs) (counter-nonce counter)
                                          (u8-subseq ciphertext 0 split)
                                          (u8-subseq ciphertext split))))
    (or pt (noise-fail "decryption failed"))))

(defun cipher-decrypt (cs ciphertext)
  "Decrypt at the internal counter.  As in mod.rs `decrypt`, the counter
   advances before authentication, so a failed decrypt still consumes it."
  (let ((n (cipher-state-nonce cs)))
    (setf (cipher-state-nonce cs) (1+ n))
    (cipher-decrypt-with-counter cs n ciphertext)))

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
  (progress :initial)  ; :initial :message1-done :complete
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

(defun make-ik-initiator (suite static remote-static-bytes local-epoch)
  "handshake.rs new_initiator.  REMOTE-STATIC-BYTES is the responder's public key."
  (let* ((rs (or (funcall (noise-suite-decode suite) remote-static-bytes)
                 (noise-fail "invalid public key")))
         (sym (symmetric-initialize (noise-suite-ik-name suite))))
    (mix-hash sym (funcall (noise-suite-premessage suite) remote-static-bytes))
    (make-handshake :suite suite :role :initiator :symmetric sym :static static
                    :remote-static rs :local-epoch local-epoch)))

(defun make-ik-responder (suite static local-epoch)
  "handshake.rs new_responder."
  (let ((sym (symmetric-initialize (noise-suite-ik-name suite))))
    (mix-hash sym (funcall (noise-suite-premessage suite)
                           (funcall (noise-suite-public-bytes suite) static)))
    (make-handshake :suite suite :role :responder :symmetric sym :static static
                    :local-epoch local-epoch)))

(defun check-state (hs role progress)
  (unless (eq (hs-role hs) role) (noise-fail (format nil "expected ~(~a~)" role)))
  (unless (eq (hs-progress hs) progress)
    (noise-fail (format nil "expected state ~(~a~), got ~(~a~)" progress (hs-progress hs)))))

(defun ik-write-message-1 (hs &key ephemeral)
  "Initiator: -> e, es, s, ss, epoch.  EPHEMERAL (a key pair) is for tests;
   normally a fresh one is generated."
  (check-state hs :initiator :initial)
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
  (check-state hs :responder :initial)
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
  (check-state hs :responder :message1-done)
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
  (check-state hs :initiator :message1-done)
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

(defun handshake-hash (hs) (ss-h (hs-symmetric hs)))

;;; --- Session (session.rs) ----------------------------------------------------

(defstruct (noise-session (:conc-name session-))
  role send recv handshake-hash remote-static)

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

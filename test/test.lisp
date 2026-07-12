;;;; test.lisp — vectors from FIPS 180-4 (SHA-256/512) and RFC 4231 (HMAC).

(defpackage #:natrium.test
  (:use #:cl)
  (:local-nicknames (#:n #:natrium))
  (:export #:run-all))

(in-package #:natrium.test)

(defun hex->bytes (hex)
  (let* ((hex (remove #\Space hex))
         (n (/ (length hex) 2))
         (out (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n out)
      (setf (aref out i) (parse-integer hex :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun bytes->hex (bytes)
  (string-downcase
   (with-output-to-string (s)
     (loop for b across bytes do (format s "~2,'0x" b)))))

(defun rep-byte (byte count)
  (make-array count :element-type '(unsigned-byte 8) :initial-element byte))

(defvar *fails* 0)
(defvar *count* 0)

(defun check (name got want-hex)
  (incf *count*)
  (let ((got-hex (bytes->hex got)))
    (cond ((string-equal got-hex want-hex)
           (format t "  ok    ~a~%" name))
          (t (incf *fails*)
             (format t "  FAIL  ~a~%        got  ~a~%        want ~a~%" name got-hex want-hex)))))

(defun rfc7748-iterate (n)
  "RFC 7748 5.2 iterated test: k=u=basepoint(9); repeat (k,u)=(x25519(k,u),k)
   N times; return the final k as a byte vector."
  (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
        (u (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref k 0) 9 (aref u 0) 9)
    (dotimes (i n k)
      (let ((newk (n:x25519 k u)))
        (setf u k k newk)))))

(defun run-all ()
  (let ((*fails* 0) (*count* 0))
    (format t "~&natrium test vectors~%")

    ;; ---- SHA-256 (FIPS 180-4) ----
    (check "sha256 empty"  (n:sha256 (n:ascii->bytes ""))
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    (check "sha256 abc"    (n:sha256 (n:ascii->bytes "abc"))
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    (check "sha256 448bit" (n:sha256 (n:ascii->bytes
                                      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
           "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")

    ;; ---- SHA-512 (FIPS 180-4) ----
    (check "sha512 empty"  (n:sha512 (n:ascii->bytes ""))
           "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
    (check "sha512 abc"    (n:sha512 (n:ascii->bytes "abc"))
           "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
    (check "sha512 896bit" (n:sha512 (n:ascii->bytes
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))
           "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")

    ;; ---- HMAC-SHA256 (RFC 4231) ----
    (check "hmac-sha256 rfc4231-1"
           (n:hmac-sha256 (rep-byte #x0b 20) (n:ascii->bytes "Hi There"))
           "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    (check "hmac-sha256 rfc4231-2"
           (n:hmac-sha256 (n:ascii->bytes "Jefe") (n:ascii->bytes "what do ya want for nothing?"))
           "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    (check "hmac-sha256 rfc4231-4"
           (n:hmac-sha256 (hex->bytes "0102030405060708090a0b0c0d0e0f10111213141516171819")
                          (rep-byte #xcd 50))
           "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")

    ;; ---- HMAC-SHA512 (RFC 4231) ----
    (check "hmac-sha512 rfc4231-1"
           (n:hmac-sha512 (rep-byte #x0b 20) (n:ascii->bytes "Hi There"))
           "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
    (check "hmac-sha512 rfc4231-2"
           (n:hmac-sha512 (n:ascii->bytes "Jefe") (n:ascii->bytes "what do ya want for nothing?"))
           "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")
    (check "hmac-sha512 rfc4231-4"
           (n:hmac-sha512 (hex->bytes "0102030405060708090a0b0c0d0e0f10111213141516171819")
                          (rep-byte #xcd 50))
           "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd")

    ;; ---- ChaCha20 (RFC 8439) ----
    (let ((key (hex->bytes "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")))
      (check "chacha20 block KAT (rfc8439 2.3.2)"
             (n:chacha20-block key 1 (hex->bytes "000000090000004a00000000"))
             "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
      (check "chacha20 encrypt sunscreen (rfc8439 2.4.2)"
             (n:chacha20 key (hex->bytes "000000000000004a00000000")
                         (n:ascii->bytes
                          "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
                         :counter 1)
             "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"))

    ;; ---- HMAC-DRBG (SP 800-90A) ----
    ;; Real NIST CAVP known-answer: HMAC_DRBG SHA-256, no reseed, no PR, Count 0
    ;; (instantiate, generate 128 bytes and discard, generate 128 = ReturnedBits).
    (let ((d (n:drbg-instantiate
              (hex->bytes "ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488")
              (hex->bytes "659ba96c601dc69fc902940805ec0ca8")
              :hmac #'n:hmac-sha256 :outlen 32)))
      (n:drbg-generate d 128)
      (check "hmac-drbg sha256 NIST CAVP count0"
             (n:drbg-generate d 128)
             "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc107694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8"))
    ;; SHA-512 DRBG (natrium's default hash), cross-checked against an independent
    ;; SP 800-90A reference implementation (test/oracle.py).
    (let ((d (n:drbg-instantiate
              (hex->bytes "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
              (hex->bytes "202122232425262728292a2b2c2d2e2f"))))
      (check "hmac-drbg sha512 vector"
             (n:drbg-generate d 64)
             "5a947e2ec811344b506f321e3f1fbde3fde96845301a7c1793e72b2071e1d984846eda8ee0e97301da2e6d07c4937b7a50c729a1ad16e594ab3dd96561709270"))

    ;; ---- Poly1305 (RFC 8439 2.5.2) ----
    (check "poly1305 mac (rfc8439 2.5.2)"
           (n:poly1305-mac
            (hex->bytes "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            (n:ascii->bytes "Cryptographic Forum Research Group"))
           "a8061dc1305136c6c22b8baf0c0127a9")

    ;; constant-time (limb) Poly1305 vs big-integer reference, varied lengths
    (incf *count*)
    (let ((st 424242) (ok t))
      (flet ((rb (nn) (let ((v (make-array nn :element-type '(unsigned-byte 8))))
                        (dotimes (i nn v)
                          (setf st (logand #xffffffff (logxor st (ash st 13))))
                          (setf st (logand #xffffffff (logxor st (ash st -17))))
                          (setf st (logand #xffffffff (logxor st (ash st 5))))
                          (setf (aref v i) (logand st #xff))))))
        (dotimes (i 300)
          (let ((key (rb 32)) (msg (rb i)))          ; lengths 0..299, incl. partial blocks
            (unless (n:bytes= (n:poly1305-mac key msg) (natrium::poly1305-mac-reference key msg))
              (setf ok nil)))))
      (if ok (format t "  ok    poly1305 constant-time == reference (300 lengths)~%")
          (progn (incf *fails*) (format t "  FAIL  poly1305 ct vs reference~%"))))

    ;; ---- ChaCha20-Poly1305 AEAD (RFC 8439 2.8.2) ----
    (let ((key (hex->bytes "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"))
          (nonce (hex->bytes "070000004041424344454647"))
          (aad (hex->bytes "50515253c0c1c2c3c4c5c6c7"))
          (pt (n:ascii->bytes
               "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")))
      (multiple-value-bind (ct tag) (n:chacha20-poly1305-encrypt key nonce pt aad)
        (check "aead encrypt ciphertext (rfc8439 2.8.2)" ct
               "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")
        (check "aead encrypt tag (rfc8439 2.8.2)" tag "1ae10b594f09e26a7e902ecbd0600691")
        ;; round-trip: decrypt returns the original plaintext
        (incf *count*)
        (let ((dec (n:chacha20-poly1305-decrypt key nonce ct tag aad)))
          (if (and dec (n:bytes= dec pt))
              (format t "  ok    aead decrypt round-trip~%")
              (progn (incf *fails*) (format t "  FAIL  aead decrypt round-trip~%"))))
        ;; tamper: a flipped ciphertext byte must fail authentication (=> NIL)
        (incf *count*)
        (let ((bad (copy-seq ct)))
          (setf (aref bad 0) (logxor (aref bad 0) 1))
          (if (null (n:chacha20-poly1305-decrypt key nonce bad tag aad))
              (format t "  ok    aead rejects tampered ciphertext~%")
              (progn (incf *fails*) (format t "  FAIL  aead accepted tampered ciphertext~%"))))))

    ;; ---- X25519 (RFC 7748) ----
    (check "x25519 vector 1 (rfc7748 5.2)"
           (n:x25519 (hex->bytes "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
                     (hex->bytes "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))
           "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    (check "x25519 vector 2 (rfc7748 5.2)"
           (n:x25519 (hex->bytes "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
                     (hex->bytes "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"))
           "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
    (check "x25519 iterate x1 (rfc7748 5.2)" (rfc7748-iterate 1)
           "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
    (check "x25519 iterate x1000 (rfc7748 5.2)" (rfc7748-iterate 1000)
           "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
    ;; DH agreement (RFC 7748 6.1)
    (let ((ask (hex->bytes "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
          (apk "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
          (bsk (hex->bytes "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
          (bpk "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
          (shared "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))
      (check "x25519 alice public (rfc7748 6.1)" (n:x25519-base ask) apk)
      (check "x25519 bob public (rfc7748 6.1)"   (n:x25519-base bsk) bpk)
      (check "x25519 shared A*bpk (rfc7748 6.1)" (n:x25519 ask (hex->bytes bpk)) shared)
      (check "x25519 shared B*apk (rfc7748 6.1)" (n:x25519 bsk (hex->bytes apk)) shared))
    ;; constant-time ladder vs big-integer reference on random inputs
    (incf *count*)
    (let ((st 2463534242) (ok t))
      (flet ((rb () (let ((v (make-array 32 :element-type '(unsigned-byte 8))))
                      (dotimes (i 32 v)
                        (setf st (logand #xffffffff (logxor st (ash st 13))))
                        (setf st (logand #xffffffff (logxor st (ash st -17))))
                        (setf st (logand #xffffffff (logxor st (ash st 5))))
                        (setf (aref v i) (logand st #xff))))))
        (dotimes (i 200)
          (let ((s (rb)) (u (rb)))
            (unless (n:bytes= (n:x25519 s u) (natrium::x25519-reference s u))
              (setf ok nil)))))
      (if ok (format t "  ok    x25519 constant-time == reference (200 random)~%")
          (progn (incf *fails*) (format t "  FAIL  x25519 ct vs reference~%"))))

    ;; ---- Ed25519 (RFC 8032 7.1) ----
    (dolist (tv (list
                 ;; name  secret-key  public-key  message  signature
                 (list "ed25519 test1"
                       "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
                       "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                       ""
                       "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
                 (list "ed25519 test2"
                       "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
                       "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
                       "72"
                       "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
                 (list "ed25519 test3"
                       "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
                       "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
                       "af82"
                       "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")
                 (list "ed25519 sha(abc)"
                       "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
                       "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
                       "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                       "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704")))
      (destructuring-bind (name sk pk msg sig) tv
        (check (format nil "~a public-key" name) (n:ed25519-public-key (hex->bytes sk)) pk)
        (check (format nil "~a sign" name) (n:ed25519-sign (hex->bytes sk) (hex->bytes msg)) sig)
        (incf *count*)
        (if (n:ed25519-verify (hex->bytes pk) (hex->bytes msg) (hex->bytes sig))
            (format t "  ok    ~a verify~%" name)
            (progn (incf *fails*) (format t "  FAIL  ~a verify~%" name)))))
    ;; negative: a flipped signature byte and a flipped message byte must reject
    (let ((pk (hex->bytes "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"))
          (msg (hex->bytes "72"))
          (sig (hex->bytes "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")))
      (incf *count*)
      (let ((bad (copy-seq sig)))
        (setf (aref bad 10) (logxor (aref bad 10) 1))
        (if (not (n:ed25519-verify pk msg bad))
            (format t "  ok    ed25519 rejects forged signature~%")
            (progn (incf *fails*) (format t "  FAIL  ed25519 accepted forged signature~%"))))
      (incf *count*)
      (if (not (n:ed25519-verify pk (n:ascii->bytes "x") sig))
          (format t "  ok    ed25519 rejects wrong message~%")
          (progn (incf *fails*) (format t "  FAIL  ed25519 accepted wrong message~%"))))
    ;; constant-time Ed25519 vs big-integer reference on random keys/messages
    (incf *count*)
    (let ((st 777777) (ok t))
      (flet ((rb (nn) (let ((v (make-array nn :element-type '(unsigned-byte 8))))
                        (dotimes (i nn v)
                          (setf st (logand #xffffffff (logxor st (ash st 13))))
                          (setf st (logand #xffffffff (logxor st (ash st -17))))
                          (setf st (logand #xffffffff (logxor st (ash st 5))))
                          (setf (aref v i) (logand st #xff))))))
        (dotimes (i 25)
          (let* ((sk (rb 32)) (msg (rb (mod i 40))))
            (unless (and (n:bytes= (n:ed25519-public-key sk) (natrium::ed25519-public-key-reference sk))
                         (n:bytes= (n:ed25519-sign sk msg) (natrium::ed25519-sign-reference sk msg))
                         (n:ed25519-verify (n:ed25519-public-key sk) msg (n:ed25519-sign sk msg)))
              (setf ok nil))))
        ;; Barrett scalar reduction vs mod L on wide random inputs
        (dotimes (i 500)
          (let ((x 0))
            (dotimes (j 8) (setf st (logand #xffffffff (logxor st (ash st 13)))
                                 st (logand #xffffffff (logxor st (ash st -17)))
                                 st (logand #xffffffff (logxor st (ash st 5)))
                                 x (logior (ash x 32) st)))
            (unless (= (natrium::sc-reduce x) (mod x natrium::*l25519*)) (setf ok nil)))))
      (if ok (format t "  ok    ed25519 constant-time == reference (25 keys) + sc-reduce (500)~%")
          (progn (incf *fails*) (format t "  FAIL  ed25519 ct vs reference~%"))))

    ;; ---- random-bytes smoke (exercises the OS-entropy → DRBG path) ----
    (incf *count*)
    (let ((a (n:random-bytes 40)) (b (n:random-bytes 40)))
      (if (and (= 40 (length a)) (= 40 (length b)) (not (n:bytes= a b)))
          (format t "  ok    random-bytes length + distinctness~%")
          (progn (incf *fails*) (format t "  FAIL  random-bytes~%"))))

    ;; ---- constant-time compare ----
    (incf *count*)
    (if (and (n:bytes= (n:sha256 (n:ascii->bytes "abc")) (n:sha256 (n:ascii->bytes "abc")))
             (not (n:bytes= (n:sha256 (n:ascii->bytes "abc")) (n:sha256 (n:ascii->bytes "abd")))))
        (format t "  ok    bytes= constant-time compare~%")
        (progn (incf *fails*) (format t "  FAIL  bytes=~%")))

    (format t "~%~d/~d passed~%" (- *count* *fails*) *count*)
    (when (plusp *fails*)
      (error "natrium: ~d test vector(s) failed" *fails*))
    t))

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

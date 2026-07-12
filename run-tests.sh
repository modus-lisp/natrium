#!/bin/sh
# run-tests.sh — load natrium and run its vector suite (FIPS 180-4 + RFC 4231).
# Pure SBCL, no external dependencies. Exits NON-ZERO on any failure.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
SBCL=${SBCL:-sbcl}

exec "$SBCL" --non-interactive \
  --eval "(require :asdf)" \
  --eval "(push #p\"$HERE/\" asdf:*central-registry*)" \
  --eval '(handler-case
            (progn
              (asdf:load-system "natrium/test")
              (if (uiop:symbol-call :natrium.test :run-all)
                  (progn (format t "~&run-tests.sh: PASS~%") (sb-ext:exit :code 0))
                  (progn (format t "~&run-tests.sh: FAIL~%") (sb-ext:exit :code 1))))
            (error (e)
              (format t "~&run-tests.sh: FAIL -- ~a~%" e)
              (sb-ext:exit :code 1)))'

;;; qg-elisp-lint.el --- Batch byte compilation and checkdoc -*- lexical-binding: t -*-

;;; Commentary:
;; The gate calls these entry points in batch Emacs and reads their JSON report.
;; Compilation output is confined to a directory owned by the gate.

;;; Code:

(require 'bytecomp)
(require 'checkdoc)
(require 'json)

(defun qg-elisp-lint--write (result files failed issues)
  "Write RESULT for FILES, FAILED files and ISSUES as JSON."
  (let ((create-lockfiles nil))
    (with-temp-file result
      (insert (json-encode `((emacs_version . ,emacs-version)
                             (files . ,(vconcat files))
                             (failed . ,(vconcat failed))
                             (issues . ,(vconcat issues))))))))

(defun qg-elisp-lint--compile-file (file)
  "Compile FILE and return non-nil only for a successful compilation."
  (condition-case failure
      (eq (byte-compile-file file) t)
    (error (message "%s: %s" file (error-message-string failure)) nil)))

(defun qg-elisp-lint-compile (files output result)
  "Compile FILES into OUTPUT and write RESULT.
The gate normally calls this once per file in a fresh Emacs."
  (let ((byte-compile-error-on-warn t)
        (create-lockfiles nil)
        (byte-compile-dest-file-function
         (lambda (file)
           (expand-file-name (concat (file-name-nondirectory file) "c") output)))
        failed)
    (dolist (file files)
      (unless (qg-elisp-lint--compile-file file)
        (push file failed)))
    (qg-elisp-lint--write result files (nreverse failed) nil)))

(defun qg-elisp-lint--issue (file position text)
  "Describe a checkdoc issue in FILE at POSITION with TEXT."
  `((file . ,file)
    (line . ,(line-number-at-pos (or position (point-min))))
    (message . ,text)))

(defun qg-elisp-lint-checkdoc (files result)
  "Run checkdoc on FILES and write RESULT with every issue."
  (let ((create-lockfiles nil)
        (issues nil)
        (current-file nil))
    (let ((collect (lambda (position text)
                     (push (qg-elisp-lint--issue current-file position text) issues))))
      (advice-add 'checkdoc-error :before collect)
      (unwind-protect
          (dolist (file files)
            (setq current-file file)
            (checkdoc-file file))
        (advice-remove 'checkdoc-error collect)))
    (qg-elisp-lint--write result files nil (nreverse issues))))

(provide 'qg-elisp-lint)
;;; qg-elisp-lint.el ends here

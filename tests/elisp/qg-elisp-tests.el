;;; qg-elisp-tests.el --- ERT suite for the gate's Emacs Lisp helpers -*- lexical-binding: t -*-

;;; Commentary:
;; Exercise the complexity, child and lint helpers in one batch process.
;; The gate instruments these helpers, so the tests call the loaded
;; definitions instead of loading the files again.

;;; Code:

(require 'cl-lib)
(require 'ert)
(require 'json)
(require 'qg-elisp-child)
(require 'qg-elisp-complexity)
(require 'qg-elisp-lint)

(defconst qg-elisp-tests--complexity-cases
  '(((if x 1 2) . 1)
    ((when x 1) . 1)
    ((unless x 1) . 1)
    ((while x 1) . 1)
    ((dolist (v nil) v) . 1)
    ((dotimes (v 0) v) . 1)
    ((cl-dolist (v nil) v) . 1)
    ((cl-dotimes (v 0) v) . 1)
    ((cl-do ((v 0)) ((> v 0)) v) . 1)
    ((cl-do* ((v 0)) ((> v 0)) v) . 1)
    ((dolist-with-progress-reporter (v nil "fixture") v) . 1)
    ((ignore-errors x) . 1)
    ((bound-and-true-p x) . 1)
    ((and a b c) . 2)
    ((or a b) . 1)
    ((cond (a 1) (b 2) (t 3)) . 2)
    ((cond (a 1) (otherwise 2)) . 1)
    ((if-let ((a x) (b y)) a b) . 2)
    ((if-let* ((a x) (b y)) a b) . 2)
    ((when-let ((a x)) a) . 1)
    ((when-let* ((a x)) a) . 1)
    ((and-let* ((a x) (b y)) a) . 2)
    ((condition-case e (if x 1 2) (error e) (quit e)) . 3)
    ((condition-case-unless-debug e x (error e)) . 1)
    ((pcase x ('a 1) (_ 0)) . 1)
    ((pcase-exhaustive x ('a 1) (_ 0)) . 1)
    ((cl-case x (a 1) (otherwise 0)) . 1)
    ((cl-ecase x (a 1) (b 2)) . 2)
    ((cl-typecase x (integer 1) (t 0)) . 1)
    ((cl-loop for v in x when v collect v) . 2)
    ((cl-loop for v in x when v collect v if v collect v while v until nil
              always v never nil thereis v) . 8)
    ((quote (if x 1 2)) . 0)
    ((list '(if x 1 2)) . 0)
    ((if (and a b) 1 2) . 2)
    ((when (or a b) a) . 2))
  "Each complexity rule family as a form and the decisions it adds.")

(defun qg-elisp-tests--temporary-directory ()
  "Create and return a temporary directory."
  (make-temp-file "qg-elisp-tests-" t))

(defun qg-elisp-tests--write (directory name contents)
  "Write CONTENTS to NAME in DIRECTORY and return the file name."
  (let ((file (expand-file-name name directory)))
    (make-directory (file-name-directory file) t)
    (with-temp-file file
      (insert contents))
    file))

(defun qg-elisp-tests--read (file)
  "Read JSON FILE and return its value."
  (json-read-file file))

(defun qg-elisp-tests--delete (directory)
  "Delete DIRECTORY and its contents."
  (delete-directory directory t))

(defun qg-elisp-tests--entry (report name)
  "Return REPORT's definition entry named NAME, or nil."
  (cl-find name (append (alist-get 'definitions report) nil)
           :key (lambda (item) (alist-get 'name item))
           :test #'equal))

(ert-deftest qg-elisp-tests-complexity-rule-families ()
  "Score every complexity rule family on forms given as data."
  (dolist (case qg-elisp-tests--complexity-cases)
    (should (= (qg-elisp-complexity--decisions (car case)) (cdr case))))
  (should-not (qg-elisp-complexity--rule 'no-such-rule))
  (should (eq (qg-elisp-complexity--rule 'if)
              'qg-elisp-complexity--branch))
  (should (eq (qg-elisp-complexity--rule 'and)
              'qg-elisp-complexity--operands)))

(ert-deftest qg-elisp-tests-complexity-file ()
  "Read definitions from a file and write their complexities."
  (let ((directory (qg-elisp-tests--temporary-directory)))
    (unwind-protect
        (progn
          (qg-elisp-tests--write
           directory "module.el"
           (concat ";;; module.el -*- lexical-binding: t -*-\n"
                   "(defvar qg-elisp-tests-ignored nil)\n"
                   "(defun qg-elisp-tests-first (x) (if x 1 2))\n"
                   "(defun qg-elisp-tests-second (x) (cond (x 1) (t 0)))\n"))
          (qg-elisp-complexity-run
           (file-name-as-directory directory) '("module.el")
           (expand-file-name "result.json" directory))
          (let* ((report (qg-elisp-tests--read
                          (expand-file-name "result.json" directory)))
                 (first (qg-elisp-tests--entry report "qg-elisp-tests-first"))
                 (second (qg-elisp-tests--entry report "qg-elisp-tests-second")))
            (should (= (length (alist-get 'definitions report)) 2))
            (should (equal (alist-get 'file first) "module.el"))
            (should (= (alist-get 'cc first) 2))
            (should (= (alist-get 'cc second) 2))
            (should (> (alist-get 'line first) 0))))
      (qg-elisp-tests--delete directory))))

(ert-deftest qg-elisp-tests-complexity-error-document ()
  "Write the complexity error document when a file cannot be read."
  (let ((directory (qg-elisp-tests--temporary-directory))
        (killed nil))
    (unwind-protect
        (progn
          (qg-elisp-tests--write directory "broken.el"
                                 "(defun unfinished (\n")
          (cl-letf (((symbol-function 'kill-emacs)
                     (lambda (&optional code) (setq killed code))))
            (qg-elisp-complexity-run
             (file-name-as-directory directory) '("broken.el")
             (expand-file-name "result.json" directory)))
          (let ((report (qg-elisp-tests--read
                         (expand-file-name "result.json" directory))))
            (should (= killed 1))
            (should (stringp (alist-get 'error report)))
            (should (string-match-p "broken.el" (alist-get 'error report)))
            (should-not (alist-get 'definitions report))))
      (qg-elisp-tests--delete directory))))

(ert-deftest qg-elisp-tests-child-stop-points ()
  "Instrument a fixture and count its stop points directly."
  (let ((directory (qg-elisp-tests--temporary-directory)))
    (unwind-protect
        (progn
          (qg-elisp-tests--write
           directory "module.el"
           (concat ";;; module.el -*- lexical-binding: t -*-\n"
                   "(defun qg-elisp-tests-fixture (value) (if value 1 2))\n"
                   "(provide 'qg-elisp-tests-fixture)\n"))
          (let* ((root (file-name-as-directory directory))
                 (names (qg-elisp-child--instrument root '("module.el")))
                 (definition (cl-find 'qg-elisp-tests-fixture names :key #'car)))
            (should definition)
            (should (eq (get 'qg-elisp-tests-fixture 'edebug-behavior)
                        'qg-elisp-child))
            (should (> (length (nth 2 definition)) 0))
            (let ((qg-elisp-child--counts (nth 2 definition)))
              (should (= (qg-elisp-child--before 0) 0))
              (should (= (qg-elisp-child--after nil 1 42) 42)))
            (let ((counts (nth 2 definition)))
              (put 'qg-elisp-tests-enter 'edebug-freq-count counts)
              (should (= (qg-elisp-child--enter
                          'qg-elisp-tests-enter nil (lambda () 42))
                         42)))
            (let ((json (qg-elisp-child--definition root definition)))
              (should (equal (alist-get 'symbol json)
                             "qg-elisp-tests-fixture"))
              (should (equal (alist-get 'file json) "module.el"))
              (should (> (alist-get 'position json) 0))
              (should (> (alist-get 'stop_points json) 0))
              (should (> (alist-get 'reached json) 0)))))
      (qg-elisp-tests--delete directory))))

(ert-deftest qg-elisp-tests-child-instrument-error ()
  "Name the file that fails instrumentation."
  (let ((directory (qg-elisp-tests--temporary-directory)))
    (unwind-protect
        (progn
          (qg-elisp-tests--write
           directory "broken.el"
           (concat ";;; broken.el -*- lexical-binding: t -*-\n"
                   "(error \"fixture module failed\")\n"))
          (let ((failure (should-error
                          (qg-elisp-child--instrument
                           (file-name-as-directory directory) '("broken.el")))))
            (should (string-match-p "broken.el" (error-message-string failure)))
            (should (string-match-p "fixture module failed"
                                    (error-message-string failure)))))
      (qg-elisp-tests--delete directory))))

(ert-deftest qg-elisp-tests-child-run-tests ()
  "Intercept exactly one ERT batch call and report its statistics."
  (let ((directory (qg-elisp-tests--temporary-directory)))
    (unwind-protect
        (progn
          (qg-elisp-tests--write
           directory "suite.el"
           (concat "(require 'ert)\n"
                   "(ert-deftest qg-elisp-tests-nested-passing () (should t))\n"
                   "(ert-run-tests-batch-and-exit"
                   " \"qg-elisp-tests-nested-passing\")\n"))
          (let ((stats (qg-elisp-child--run-tests directory "suite.el")))
            (should (= (ert-stats-total stats) 1))
            (should (= (ert-stats-completed-expected stats) 1))
            (should (= (ert-stats-completed-unexpected stats) 0)))
          (qg-elisp-tests--write
           directory "twice.el"
           (concat "(require 'ert)\n"
                   "(ert-run-tests-batch-and-exit"
                   " \"qg-elisp-tests-nested-twice\")\n"
                   "(ert-run-tests-batch-and-exit"
                   " \"qg-elisp-tests-nested-twice\")\n"))
          (let ((failure (should-error
                          (qg-elisp-child--run-tests directory "twice.el"))))
            (should (string-match-p "more than once"
                                    (error-message-string failure))))
          (qg-elisp-tests--write directory "none.el"
                                 "(require 'ert)\n(message \"none\")\n")
          (let ((failure (should-error
                          (qg-elisp-child--run-tests directory "none.el"))))
            (should (string-match-p "called 0 times"
                                    (error-message-string failure)))))
      (qg-elisp-tests--delete directory))))

(ert-deftest qg-elisp-tests-child-failures ()
  "Describe unexpected ERT results with their names and conditions."
  (let ((directory (qg-elisp-tests--temporary-directory)))
    (unwind-protect
        (progn
          (qg-elisp-tests--write
           directory "failing.el"
           (concat "(require 'ert)\n"
                   "(ert-deftest qg-elisp-tests-nested-failing-broken ()"
                   " (should (= 1 2)))\n"
                   "(ert-deftest qg-elisp-tests-nested-failing-surprising ()"
                   " :expected-result :failed (should t))\n"
                   "(ert-run-tests-batch-and-exit"
                   " \"qg-elisp-tests-nested-failing\")\n"))
          (let* ((stats (qg-elisp-child--run-tests directory "failing.el"))
                 (failures (qg-elisp-child--failures stats)))
            (should (= (length failures) 2))
            (let ((broken (cl-find "qg-elisp-tests-nested-failing-broken"
                                   (append failures nil)
                                   :key (lambda (item) (alist-get 'name item))
                                   :test #'equal)))
              (should broken)
              (should (string-match-p "ert-test-failed"
                                      (alist-get 'condition broken))))
            (should (cl-find "qg-elisp-tests-nested-failing-surprising"
                             (append failures nil)
                             :key (lambda (item) (alist-get 'name item))
                             :test #'equal))))
      (qg-elisp-tests--delete directory))))

(ert-deftest qg-elisp-tests-child-result-document ()
  "Write the child result document for a passing fixture suite."
  (let ((directory (qg-elisp-tests--temporary-directory)))
    (unwind-protect
        (progn
          (qg-elisp-tests--write
           directory "module.el"
           (concat ";;; module.el -*- lexical-binding: t -*-\n"
                   "(defun qg-elisp-tests-fixture (value) (if value 1 2))\n"
                   "(provide 'qg-elisp-tests-fixture)\n"))
          (qg-elisp-tests--write
           directory "suite.el"
           (concat "(require 'ert)\n"
                   "(ert-deftest qg-elisp-tests-nested-result ()"
                   " (should (= (qg-elisp-tests-fixture t) 1)))\n"
                   "(ert-run-tests-batch-and-exit"
                   " \"qg-elisp-tests-nested-result\")\n"))
          (qg-elisp-child-run
           (file-name-as-directory directory) '("module.el") "suite.el"
           (expand-file-name "result.json" directory))
          (let* ((report (qg-elisp-tests--read
                          (expand-file-name "result.json" directory)))
                 (entry (cl-find "qg-elisp-tests-fixture"
                                 (append (alist-get 'definitions report) nil)
                                 :key (lambda (item) (alist-get 'symbol item))
                                 :test #'equal)))
            (should (stringp (alist-get 'emacs_version report)))
            (should (= (alist-get 'selected report) 1))
            (should (= (alist-get 'passed report) 1))
            (should (= (alist-get 'failed report) 0))
            (should (equal (alist-get 'failures report) []))
            (should (equal (alist-get 'file entry) "module.el"))
            (should (> (alist-get 'stop_points entry) 0))))
      (qg-elisp-tests--delete directory))))

(ert-deftest qg-elisp-tests-child-error-document ()
  "Write the child error document when a fixture module fails."
  (let ((directory (qg-elisp-tests--temporary-directory))
        (killed nil))
    (unwind-protect
        (progn
          (qg-elisp-tests--write
           directory "broken.el"
           (concat ";;; broken.el -*- lexical-binding: t -*-\n"
                   "(error \"fixture module failed\")\n"))
          (cl-letf (((symbol-function 'kill-emacs)
                     (lambda (&optional code) (setq killed code))))
            (qg-elisp-child-run
             (file-name-as-directory directory) '("broken.el") "suite.el"
             (expand-file-name "result.json" directory)))
          (let ((report (qg-elisp-tests--read
                         (expand-file-name "result.json" directory))))
            (should (= killed 1))
            (should (stringp (alist-get 'error report)))
            (should (string-match-p "fixture module failed"
                                    (alist-get 'error report)))))
      (qg-elisp-tests--delete directory))))

(ert-deftest qg-elisp-tests-lint-compile ()
  "Compile a clean and a warning fixture into a temporary directory."
  (let ((directory (qg-elisp-tests--temporary-directory))
        (output (qg-elisp-tests--temporary-directory)))
    (unwind-protect
        (progn
          (qg-elisp-tests--write
           directory "clean.el"
           (concat ";;; clean.el --- Clean fixture -*- lexical-binding: t -*-\n\n"
                   ";;; Commentary:\n"
                   ";; A clean fixture.\n\n"
                   ";;; Code:\n\n"
                   "(defun qg-elisp-tests-clean () \"Return one.\" 1)\n\n"
                   "(provide 'clean)\n"
                   ";;; clean.el ends here\n"))
          (qg-elisp-tests--write
           directory "warning.el"
           (concat ";;; warning.el --- Warning fixture -*- lexical-binding: t -*-\n\n"
                   ";;; Commentary:\n"
                   ";; A warning fixture.\n\n"
                   ";;; Code:\n\n"
                   "(defun qg-elisp-tests-warning ()"
                   " \"Return a free variable.\" qg-elisp-tests-free-variable)\n\n"
                   "(provide 'warning)\n"
                   ";;; warning.el ends here\n"))
          (let ((default-directory (file-name-as-directory directory)))
            (qg-elisp-lint-compile
             '("clean.el" "warning.el") output
             (expand-file-name "compile.json" directory)))
          (let ((report (qg-elisp-tests--read
                         (expand-file-name "compile.json" directory))))
            (should (equal (append (alist-get 'files report) nil)
                           '("clean.el" "warning.el")))
            (should (equal (append (alist-get 'failed report) nil)
                           '("warning.el")))
            (should (= (length (alist-get 'issues report)) 0))))
      (qg-elisp-tests--delete directory)
      (qg-elisp-tests--delete output))))

(ert-deftest qg-elisp-tests-lint-checkdoc ()
  "Report a checkdoc issue with its file, line and message."
  (let ((directory (qg-elisp-tests--temporary-directory)))
    (unwind-protect
        (progn
          (qg-elisp-tests--write
           directory "documented.el"
           (concat ";;; documented.el --- Documented fixture -*- lexical-binding: t -*-\n\n"
                   ";;; Commentary:\n"
                   ";; A documented fixture.\n\n"
                   ";;; Code:\n\n"
                   "(defun qg-elisp-tests-documented ()"
                   " \"Return one.\" 1)\n\n"
                   "(provide 'documented)\n"
                   ";;; documented.el ends here\n"))
          (qg-elisp-tests--write
           directory "undocumented.el"
           (concat ";;; undocumented.el --- Undocumented fixture"
                   " -*- lexical-binding: t -*-\n\n"
                   ";;; Commentary:\n"
                   ";; An undocumented fixture.\n\n"
                   ";;; Code:\n\n"
                   "(defun qg-elisp-tests-undocumented () 1)\n\n"
                   "(provide 'undocumented)\n"
                   ";;; undocumented.el ends here\n"))
          (let ((default-directory (file-name-as-directory directory)))
            (qg-elisp-lint-checkdoc
             '("documented.el")
             (expand-file-name "clean.json" directory)))
          (should (= (length (alist-get 'issues
                                        (qg-elisp-tests--read
                                         (expand-file-name "clean.json" directory))))
                     0))
          (let ((default-directory (file-name-as-directory directory)))
            (qg-elisp-lint-checkdoc
             '("undocumented.el")
             (expand-file-name "issues.json" directory)))
          (let* ((report (qg-elisp-tests--read
                          (expand-file-name "issues.json" directory)))
                 (issues (alist-get 'issues report))
                 (issue (aref issues 0)))
            (should (> (length issues) 0))
            (should (equal (alist-get 'file issue) "undocumented.el"))
            (should (> (alist-get 'line issue) 0))
            (should (stringp (alist-get 'message issue)))
            (should (string-match-p "documentation"
                                    (downcase (alist-get 'message issue))))))
      (qg-elisp-tests--delete directory))))

(provide 'qg-elisp-tests)
(ert-run-tests-batch-and-exit t)
;;; qg-elisp-tests.el ends here

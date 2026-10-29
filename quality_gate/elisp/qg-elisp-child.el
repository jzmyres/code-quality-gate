;;; qg-elisp-child.el --- Measure ERT tests in a child Emacs -*- lexical-binding: t -*-

;;; Commentary:
;; A staged copy instruments the selected files, runs one batch suite and
;; writes its results and Edebug stop-point counts as JSON.

;;; Code:

(require 'cl-lib)
(require 'edebug)
(require 'ert)
(require 'json)
(require 'subr-x)

(defvar qg-elisp-child--counts nil
  "Visit counts for the instrumented definition that is running.")

(defun qg-elisp-child--enter (name _args body)
  "Run BODY of instrumented definition NAME, counting its stop points."
  (let ((qg-elisp-child--counts (get name 'edebug-freq-count)))
    (funcall body)))

(defun qg-elisp-child--before (index)
  "Count a visit to stop point INDEX."
  (cl-incf (aref qg-elisp-child--counts index))
  index)

(defun qg-elisp-child--after (_before index value)
  "Count a visit to stop point INDEX and return VALUE."
  (cl-incf (aref qg-elisp-child--counts index))
  value)

(add-to-list 'edebug-behavior-alist
             '(qg-elisp-child qg-elisp-child--enter
                              qg-elisp-child--before qg-elisp-child--after))

(defun qg-elisp-child--instrument-file (root file)
  "Evaluate FILE under ROOT with the context supplied by `load'."
  (condition-case failure
      (let ((absolute (expand-file-name file root)))
        (with-current-buffer (find-file-noselect absolute)
          (let ((load-file-name absolute)
                (load-true-file-name (file-truename absolute)))
            (eval-buffer nil nil absolute))))
    (error (error "instrumenting %s: %s" file (error-message-string failure)))))

(defun qg-elisp-child--instrument (root files)
  "Instrument FILES under ROOT and return all definition names, including lambdas."
  (let ((names nil)
        (edebug-all-defs t))
    (let ((edebug-new-definition-function
           (lambda (name)
             (push (list name (car (get name 'edebug))
                         (get name 'edebug-freq-count)) names)
             (put name 'edebug-behavior 'qg-elisp-child))))
      (dolist (file files)
        (qg-elisp-child--instrument-file root file)))
    names))

(defun qg-elisp-child--run-tests (root suite)
  "Load SUITE under ROOT, intercepting exactly one batch invocation."
  (let ((calls 0) stats)
    (cl-letf (((symbol-function 'ert-run-tests-batch-and-exit)
               (lambda (&optional selector)
                 (cl-incf calls)
                 (when (> calls 1)
                   (error "ert-run-tests-batch-and-exit called more than once"))
                 (setq stats (ert-run-tests-batch selector)))))
      (condition-case failure
          (load (expand-file-name suite root) nil t)
        (error (error "loading suite %s: %s" suite (error-message-string failure)))))
    (unless (= calls 1)
      (error "suite %s: expected ert-run-tests-batch-and-exit exactly once, called %d times"
             suite calls))
    stats))

(defun qg-elisp-child--condition (result)
  "Print RESULT's condition as ERT's batch reporter does."
  (if (ert-test-result-with-condition-p result)
      (with-temp-buffer
        (insert "    ")
        (let ((print-escape-newlines t)
              (print-level ert-batch-print-level)
              (print-length ert-batch-print-length))
          (ert--pp-with-indentation-and-newline
           (ert-test-result-with-condition-condition result)))
        (string-trim-right (buffer-string)))
    (ert-string-for-test-result result nil)))

(defun qg-elisp-child--failures (stats)
  "Return STATS' unexpected test results as a JSON array."
  (vconcat
   (cl-loop for test across (ert--stats-tests stats)
            for result across (ert--stats-test-results stats)
            unless (ert-test-result-expected-p test result)
            collect `((name . ,(format "%s" (ert-test-name test)))
                      (condition . ,(qg-elisp-child--condition result))))))

(defun qg-elisp-child--definition (root definition)
  "Return DEFINITION's stop-point counts as a JSON object relative to ROOT."
  (let ((name (nth 0 definition))
        (position (nth 1 definition))
        (counts (nth 2 definition)))
    `((symbol . ,(symbol-name name))
      (file . ,(file-relative-name (buffer-file-name (marker-buffer position)) root))
      (position . ,(marker-position position))
      (stop_points . ,(length counts))
      (reached . ,(cl-count-if (lambda (count) (> count 0)) counts)))))

(defun qg-elisp-child--write (file document)
  "Write DOCUMENT as JSON to FILE."
  (let ((create-lockfiles nil))
    (with-temp-file file
      (insert (json-encode document)))))

(defun qg-elisp-child-run (root files suite result-file)
  "Instrument FILES under ROOT, run SUITE and write JSON to RESULT-FILE."
  (let ((default-directory root))
    (condition-case failure
        (let* ((names (qg-elisp-child--instrument root files))
               (stats (qg-elisp-child--run-tests root suite)))
          (qg-elisp-child--write
           result-file
           `((emacs_version . ,emacs-version)
             (selected . ,(ert-stats-total stats))
             (passed . ,(ert-stats-completed-expected stats))
             (failed . ,(ert-stats-completed-unexpected stats))
             (skipped . ,(ert-stats-skipped stats))
             (failures . ,(qg-elisp-child--failures stats))
             (definitions . ,(vconcat (mapcar (lambda (name)
                                               (qg-elisp-child--definition root name))
                                             names))))))
      (error
       (qg-elisp-child--write result-file `((error . ,(error-message-string failure))))
       (kill-emacs 1)))))

(provide 'qg-elisp-child)
;;; qg-elisp-child.el ends here

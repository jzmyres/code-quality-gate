;;; qg-elisp-complexity.el --- Read Emacs Lisp complexity -*- lexical-binding: t -*-

;;; Commentary:
;; Count the Emacs Lisp default or policy decision rules on top-level definitions.
;; The caller supplies the effective rules as data.
;; This helper reads source and never evaluates or instruments it.

;;; Code:

(require 'cl-lib)
(require 'json)

(defvar qg-elisp-complexity--rules nil
  "Effective decision families, loop clauses and catch-all symbols.")

(defconst qg-elisp-complexity--counters
  '((branch . qg-elisp-complexity--branch)
    (operands . qg-elisp-complexity--operands)
    (cond . qg-elisp-complexity--cond)
    (bindings . qg-elisp-complexity--bindings)
    (handlers . qg-elisp-complexity--handlers)
    (case . qg-elisp-complexity--case)
    (loop . qg-elisp-complexity--loop))
  "Decision family counting algorithms.")

(defun qg-elisp-complexity--clauses (clauses)
  "Count CLAUSES except a final catch-all."
  (- (length clauses)
     (if (and clauses
              (memq (car-safe (car (last clauses)))
                    (alist-get 'catch_all qg-elisp-complexity--rules)))
         1 0)))

(defun qg-elisp-complexity--in (forms)
  "Count decisions in each element of FORMS, which may be dotted."
  (let ((total 0))
    (while (consp forms)
      (setq total (+ total (qg-elisp-complexity--decisions (pop forms)))))
    total))

(defun qg-elisp-complexity--branch (args)
  "Count a branch and the decisions in its ARGS."
  (1+ (qg-elisp-complexity--in args)))

(defun qg-elisp-complexity--operands (args)
  "Count operands after the first and the decisions in ARGS."
  (+ (max 0 (1- (length args))) (qg-elisp-complexity--in args)))

(defun qg-elisp-complexity--cond (args)
  "Count `cond' clauses and their ARGS."
  (+ (qg-elisp-complexity--clauses args) (qg-elisp-complexity--in args)))

(defun qg-elisp-complexity--bindings (args)
  "Count bindings and the decisions in ARGS."
  (+ (length (car args)) (qg-elisp-complexity--in args)))

(defun qg-elisp-complexity--handlers (args)
  "Count handlers and the decisions in ARGS."
  (+ (length (cddr args)) (qg-elisp-complexity--in (cdr args))))

(defun qg-elisp-complexity--case (args)
  "Count case clauses and decisions in ARGS, excluding patterns."
  (+ (qg-elisp-complexity--clauses (cdr args))
     (qg-elisp-complexity--decisions (car args))
     (cl-loop for clause in (cdr args)
              sum (qg-elisp-complexity--in (cdr-safe clause)))))

(defun qg-elisp-complexity--loop (args)
  "Count a loop, conditional clause keywords and decisions in ARGS."
  (+ 1
     (cl-count-if (lambda (arg)
                    (memq arg (alist-get 'loop_clauses qg-elisp-complexity--rules)))
                  args)
     (qg-elisp-complexity--in args)))

(defun qg-elisp-complexity--rule (head)
  "Return the counter for HEAD, or nil."
  (cl-loop for (family . counter) in qg-elisp-complexity--counters
           when (memq head (alist-get family qg-elisp-complexity--rules))
           return counter))

(defun qg-elisp-complexity--decisions (form)
  "Count decisions in FORM, skipping quoted data."
  (let ((head (car-safe form)))
    (cond
     ((or (not (consp form)) (eq head 'quote)) 0)
     ((qg-elisp-complexity--rule head)
      (funcall (qg-elisp-complexity--rule head) (cdr form)))
     (t (qg-elisp-complexity--in form)))))

(defun qg-elisp-complexity--definition (file form end)
  "Return FORM in FILE as JSON data, ending at END."
  (backward-sexp)
  (let ((start (point))
        (line (line-number-at-pos)))
    (goto-char end)
    `((file . ,file)
      (name . ,(symbol-name (nth 1 form)))
      (line . ,line)
      (end_line . ,(line-number-at-pos (1- end)))
      (start . ,start)
      (end . ,end)
      (cc . ,(1+ (qg-elisp-complexity--decisions (nthcdr 3 form)))))))

(defun qg-elisp-complexity--read-file (root file)
  "Read FILE under ROOT and return its top-level definitions."
  (condition-case failure
      (with-temp-buffer
        (insert-file-contents (expand-file-name file root))
        (emacs-lisp-mode)
        (goto-char (point-min))
        (let (definitions)
          (forward-comment (point-max))
          (while (not (eobp))
            (let ((form (read (current-buffer)))
                  (end (point)))
              (when (memq (car-safe form) '(defun defsubst defmacro cl-defun))
                (push (qg-elisp-complexity--definition file form end) definitions)))
            (forward-comment (point-max)))
          (nreverse definitions)))
    (error (error "Cannot read %s: %s" file (error-message-string failure)))))

(defun qg-elisp-complexity-run (root files result-file)
  "Read FILES under ROOT and write complexity JSON to RESULT-FILE.
Use the effective rules in `qg-elisp-complexity--rules'."
  (let ((default-directory root)
        (create-lockfiles nil))
    (condition-case failure
        (let ((definitions (cl-mapcan (lambda (file) (qg-elisp-complexity--read-file root file))
                                      files)))
          (with-temp-file result-file
            (insert (json-encode `((definitions . ,(vconcat definitions)))))))
      (error
       (with-temp-file result-file
         (insert (json-encode `((error . ,(error-message-string failure))))))
       (kill-emacs 1)))))

(provide 'qg-elisp-complexity)
;;; qg-elisp-complexity.el ends here

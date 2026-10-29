;;; qg-elisp-complexity.el --- Read Emacs Lisp complexity -*- lexical-binding: t -*-

;;; Commentary:
;; Count the editor CRAP gate's decision rules on top-level definitions.
;; This helper reads source and never evaluates or instruments it.

;;; Code:

(require 'cl-lib)
(require 'json)

(defconst qg-elisp-complexity--rules
  '(((if when unless while dolist dotimes cl-dolist cl-dotimes cl-do cl-do*
      dolist-with-progress-reporter ignore-errors bound-and-true-p)
     . qg-elisp-complexity--branch)
    ((and or) . qg-elisp-complexity--operands)
    ((cond) . qg-elisp-complexity--cond)
    ((if-let if-let* when-let when-let* and-let*) . qg-elisp-complexity--bindings)
    ((condition-case condition-case-unless-debug) . qg-elisp-complexity--handlers)
    ((pcase pcase-exhaustive cl-case cl-ecase cl-typecase) . qg-elisp-complexity--case)
    ((cl-loop) . qg-elisp-complexity--loop))
  "Decision families and their counters.")

(defconst qg-elisp-complexity--loop-clauses
  '(when if unless while until always never thereis)
  "Conditional `cl-loop' clause keywords.")

(defun qg-elisp-complexity--clauses (clauses)
  "Count CLAUSES except a final catch-all."
  (- (length clauses)
     (if (memq (car-safe (car (last clauses))) '(t _ otherwise)) 1 0)))

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
     (cl-count-if (lambda (arg) (memq arg qg-elisp-complexity--loop-clauses)) args)
     (qg-elisp-complexity--in args)))

(defun qg-elisp-complexity--rule (head)
  "Return the counter for HEAD, or nil."
  (cdr (cl-find-if (lambda (rule) (memq head (car rule)))
                   qg-elisp-complexity--rules)))

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
    (error (error "cannot read %s: %s" file (error-message-string failure)))))

(defun qg-elisp-complexity-run (root files result-file)
  "Read FILES under ROOT and write complexity JSON to RESULT-FILE."
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

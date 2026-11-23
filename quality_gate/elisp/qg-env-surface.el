;;; qg-env-surface.el --- Inventory environment accesses -*- lexical-binding: t -*-

;;; Commentary:
;; Read source forms and report environment accesses without evaluating source.

;;; Code:

(require 'json)

(defun qg-env-surface--row (name path position access)
  "Build a row for NAME in PATH at POSITION with ACCESS."
  `((name . ,name)
    (path . ,path)
    (line . ,(line-number-at-pos position))
    (access . ,(if name access "computed"))))

(defun qg-env-surface--assignments (form)
  "Return environment assignment names in the literal strings in FORM."
  (cond
   ((stringp form)
    (when (string-match "\\`\\([^=]+\\)=" form)
      (list (match-string 1 form))))
   ((consp form)
    (append (qg-env-surface--assignments (car form))
            (qg-env-surface--assignments (cdr form))))))

(defun qg-env-surface--bindings (bindings path position)
  "Report environment BINDINGS for PATH at POSITION."
  (if (proper-list-p bindings)
      (mapcar (lambda (binding)
                (let ((name (car-safe binding)))
                  (qg-env-surface--row (and (stringp name) name) path position "write")))
              bindings)
    (list (qg-env-surface--row nil path position "write"))))

(defun qg-env-surface--reference-p (form)
  "Return whether FORM directly refers to the environment as an operand."
  (and (consp form) (proper-list-p form)
       (not (memq (car form) '(progn prog1 prog2)))
       (memq 'process-environment form)))

(defun qg-env-surface--named (head name path position)
  "Report the named operation HEAD on NAME at POSITION in PATH."
  (list (qg-env-surface--row (and (stringp name) name) path position
                            (if (eq head 'getenv) "read" "write"))))

(defun qg-env-surface--reference (form path position)
  "Report environment names in the referencing FORM at POSITION in PATH."
  (mapcar (lambda (key) (qg-env-surface--row key path position "write"))
          (or (qg-env-surface--assignments form) '(nil))))

(defun qg-env-surface--direct (form path position)
  "Report environment accesses belonging to FORM in PATH at POSITION."
  (let ((head (car-safe form))
        (name (car-safe (cdr-safe form))))
    (cond
     ((memq head '(getenv setenv))
      (qg-env-surface--named head name path position))
     ((eq head 'with-environment-variables)
      (qg-env-surface--bindings name path position))
     ((qg-env-surface--reference-p form)
      (qg-env-surface--reference form path position))
     ((eq form 'process-environment)
      (list (qg-env-surface--row nil path position "read"))))))

(defun qg-env-surface--children (path end reference)
  "Read children in PATH until END, suppressing symbols covered by REFERENCE."
  (let (rows)
    (forward-comment (point-max))
    (while (< (point) (1- end))
      (if (looking-at-p "\\.[[:space:];]")
          (forward-char)
        (setq rows (nconc rows (qg-env-surface--read path reference))))
      (forward-comment (point-max)))
    rows))

(defun qg-env-surface--nested (form path end)
  "Read nested expressions in FORM in PATH, ending at END."
  (cond
   ((looking-at-p "#'")
    (forward-char 2)
    (forward-comment (point-max))
    (when (eq (char-after) ?\()
      (qg-env-surface--read path nil)))
   ((eq (char-after) ?\()
    (forward-char)
    (qg-env-surface--children path end (qg-env-surface--reference-p form)))))

(defun qg-env-surface--read (path reference)
  "Read one form in PATH and return its rows.
When REFERENCE is non-nil, the containing form accounts for direct references."
  (let* ((position (point))
         (form (read (current-buffer)))
         (end (point)))
    (prog1
        (unless (or (eq (car-safe form) 'quote)
                    (and reference (eq form 'process-environment)))
          (goto-char position)
          (nconc (qg-env-surface--direct form path position)
                 (qg-env-surface--nested form path end)))
      (goto-char end))))

(defun qg-env-surface--file (path)
  "Read PATH and return its environment rows."
  (with-temp-buffer
    (insert-file-contents path)
    (set-syntax-table emacs-lisp-mode-syntax-table)
    (goto-char (point-min))
    (forward-comment (point-max))
    (let ((read-circle nil) rows)
      (while (not (eobp))
        (setq rows (nconc rows (qg-env-surface--read path nil)))
        (forward-comment (point-max)))
      rows)))

(defun qg-env-surface-run (paths report)
  "Read PATHS and write environment rows and reader errors to REPORT."
  (let (findings errors)
    (dolist (path paths)
      (condition-case failure
          (setq findings (nconc findings (qg-env-surface--file path)))
        (error (push (format "cannot read %s: %s" path (error-message-string failure)) errors))))
    (with-temp-file report
      (insert (json-encode `((findings . ,(vconcat findings))
                            (errors . ,(vconcat (nreverse errors)))))))))

(provide 'qg-env-surface)
;;; qg-env-surface.el ends here

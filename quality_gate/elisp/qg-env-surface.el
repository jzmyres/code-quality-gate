;;; qg-env-surface.el --- Inventory environment accesses -*- lexical-binding: t -*-

;;; Commentary:

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

(defun qg-env-surface--reference (form path position access)
  "Report names in referencing FORM at POSITION in PATH with ACCESS."
  (mapcar (lambda (key) (qg-env-surface--row key path position access))
          (or (qg-env-surface--assignments form) '(nil))))

(defun qg-env-surface--setq-values (args)
  "Return values assigned to the environment in alternating ARGS."
  (let (values)
    (while (consp args)
      (let ((target (pop args))
            (value (pop args)))
        (when (eq target 'process-environment)
          (push value values))))
    (nreverse values)))

(defun qg-env-surface--list-mutation (form)
  "Return the value written by a list mutation in FORM."
  (pcase (car form)
    ('add-to-list
     (when (equal (nth 1 form) '(quote process-environment))
       (list (nth 2 form))))
    ('push
     (when (eq (nth 2 form) 'process-environment)
       (list (nth 1 form))))))

(defun qg-env-surface--mutation (form context)
  "Return the values FORM writes to the environment in CONTEXT."
  (pcase (car-safe form)
    ((or 'add-to-list 'push) (qg-env-surface--list-mutation form))
    ('setq (qg-env-surface--setq-values (cdr form)))
    ('process-environment
     (when (eq context 'binding)
       (list (nth 1 form))))))

(defun qg-env-surface--value-names (value)
  "Return literal names and unknown parts of an environment VALUE."
  (pcase (car-safe value)
    ('quote (qg-env-surface--assignments (nth 1 value)))
    ((or 'cons 'list 'append) (apply #'append (mapcar #'qg-env-surface--value-names (cdr value))))
    (_ (qg-env-surface--unexpanded-names value))))

(defun qg-env-surface--unexpanded-names (value)
  "Return names for a VALUE outside a recognized list constructor."
  (unless (memq value '(nil process-environment))
    (or (and (stringp value) (qg-env-surface--assignments value)) '(nil))))

(defun qg-env-surface--writes (values path position)
  "Report each assignment in VALUES in PATH at POSITION."
  (let (rows)
    (dolist (value values)
      (dolist (key (or (qg-env-surface--value-names value) '(nil)))
        (push (qg-env-surface--row key path position "write") rows)))
    (nreverse rows)))

(defun qg-env-surface--direct (form path position)
  "Report read and named access rows for FORM in PATH at POSITION."
  (let ((head (car-safe form))
        (name (car-safe (cdr-safe form))))
    (cond
     ((memq head '(getenv setenv))
      (qg-env-surface--named head name path position))
     ((eq head 'with-environment-variables)
      (qg-env-surface--bindings name path position))
     ((qg-env-surface--reference-p form)
      (qg-env-surface--reference form path position "read"))
     ((memq form '(process-environment initial-environment))
      (list (qg-env-surface--row nil path position "read"))))))

(defun qg-env-surface--child-context (context head index)
  "Return the role of child INDEX of HEAD in CONTEXT."
  (cond
   ((eq context 'bindings) 'binding)
   ((and (= index 1) (memq head '(let let*))) 'bindings)))

(defun qg-env-surface--covered-child (child values suppress)
  "Return whether CHILD is already covered by VALUES or SUPPRESS."
  (or (eq suppress 'covered)
      (and values (or (eq child 'process-environment) (memq child values)))))

(defun qg-env-surface--children (form path end context values suppress)
  "Read children of FORM in PATH until END in CONTEXT.
Use VALUES and SUPPRESS to avoid recounting operands."
  (let ((head (car-safe form)) (index 0) rows)
    (forward-comment (point-max))
    (while (< (point) (1- end))
      (if (looking-at-p "\\.[[:space:];]")
          (forward-char)
        (let ((child (car-safe form)))
          (setq rows
                (nconc rows
                       (qg-env-surface--read
                        path
                        (qg-env-surface--child-context context head index)
                        (if (qg-env-surface--covered-child child values suppress)
                            'covered
                          suppress)))))
        (setq form (cdr-safe form) index (1+ index)))
      (forward-comment (point-max)))
    rows))

(defun qg-env-surface--nested (form path end context values suppress)
  "Read children of FORM in PATH up to END, using CONTEXT, VALUES and SUPPRESS."
  (cond
   ((looking-at-p "#'")
    (forward-char 2)
    (forward-comment (point-max))
    (when (eq (char-after) ?\()
      (qg-env-surface--read path nil suppress)))
   ((eq (char-after) ?\()
    (forward-char)
    (qg-env-surface--children form path end context values suppress))))

(defun qg-env-surface--covered-p (form suppress)
  "Return whether FORM's process environment access was counted by SUPPRESS."
  (pcase suppress
    ('covered
     (or (eq form 'process-environment)
         (and (memq (car-safe form) '(cons list append))
              (qg-env-surface--reference-p form))))
    ('operand (eq form 'process-environment))))

(defun qg-env-surface--coverage (form suppress)
  "Return the coverage to pass to children of FORM given SUPPRESS."
  (if (eq suppress 'covered)
      suppress
    (when (qg-env-surface--reference-p form)
      'operand)))

(defun qg-env-surface--rows (form path position values suppress)
  "Report FORM at POSITION in PATH using write VALUES and inherited SUPPRESS."
  (cond
   (values (qg-env-surface--writes values path position))
   ((not (qg-env-surface--covered-p form suppress))
    (qg-env-surface--direct form path position))))

(defun qg-env-surface--read (path context suppress)
  "Read one form in PATH with CONTEXT and inherited SUPPRESS."
  (let* ((position (point))
         (form (read (current-buffer)))
         (end (point))
         (values (qg-env-surface--mutation form context)))
    (prog1
        (unless (eq (car-safe form) 'quote)
          (goto-char position)
          (nconc (qg-env-surface--rows form path position values suppress)
                 (qg-env-surface--nested form path end context values
                                         (qg-env-surface--coverage form suppress))))
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
        (setq rows (nconc rows (qg-env-surface--read path nil nil)))
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

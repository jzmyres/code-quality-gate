"""Build invocations of trusted helpers in a clean batch Emacs."""
from pathlib import Path


def batch_command(
    emacs: str, helper: Path | None, form: str, load_path: tuple[str, ...] = (),
) -> list[str]:
    """Invoke a trusted Lisp helper in a clean batch Emacs."""
    directories = [item for directory in load_path for item in ("-L", directory)]
    load = [] if helper is None else ["-l", str(helper)]
    return [emacs, "-Q", "--batch", *directories, *load, "--eval", form]


MODULE_GRAPH_READER = r"""
(progn
  (require 'cl-lib)
  (require 'json)
  (require 'seq)

  (defun qg-graph-quoted-symbol-p (form)
    (and (eq (proper-list-p form) 2)
         (eq (car form) 'quote)
         (symbolp (cadr form))))

  (defun qg-graph-outside (line description)
    (list (cons 'kind "outside") (cons 'line line)
          (cons 'message (format "%s is outside the extractor" description))))

  (defun qg-graph-canonical-filename-p (filename)
    (let ((case-fold-search nil))
      (seq-every-p (lambda (part)
                     (and (not (member part '("." "..")))
                          (string-match-p
                           (rx string-start (+ (any "A-Za-z0-9._+-")) string-end)
                           part)))
                   (split-string filename "/" nil))))

  (defun qg-graph-head-line (form)
    (line-number-at-pos (symbol-with-pos-pos (car form))))

  (defun qg-graph-require (form)
    (when (and (eq (car-safe form) 'require) (proper-list-p form))
      (let* ((line (qg-graph-head-line form))
             (feature-operand (cadr form))
             (quoted-feature (qg-graph-quoted-symbol-p feature-operand))
             (feature (and quoted-feature (bare-symbol (cadr feature-operand))))
             (feature-problem
              (cond ((not quoted-feature) "computed")
                    ((not (eq feature (intern-soft feature))) "uninterned")))
             (filename (nth 2 form))
             (filename-problem
              (cond ((and (stringp filename) (not (qg-graph-canonical-filename-p filename)))
                     "noncanonical")
                    ((not (or (stringp filename) (null filename))) "computed")))
             (problem
              (cond ((and feature-problem filename-problem)
                     (format "require with a %s feature and a %s filename"
                             feature-problem filename-problem))
                    (feature-problem (format "%s require feature" feature-problem))
                    (filename-problem (format "%s require filename" filename-problem)))))
        (if problem
            (list 'outside line problem)
          (list 'require line feature filename)))))

  (defun qg-graph-provide (form)
    (when (and (eq (car-safe form) 'provide)
               (proper-list-p form)
               (qg-graph-quoted-symbol-p (cadr form)))
      (let ((line (qg-graph-head-line form))
            (feature (bare-symbol (cadadr form))))
        (if (eq feature (intern-soft feature))
            (list 'provide line feature)
          (list 'outside line "uninterned provide feature")))))

  (defun qg-graph-top-level (form)
    (pcase (car-safe form)
      ('provide
       (let ((row (qg-graph-provide form)))
         (when row (list row))))
      ('progn
       (when (proper-list-p form)
         (delq nil (mapcar #'qg-graph-provide (cdr form)))))
      ('require
       (let ((row (qg-graph-require form)))
         (when row (list row))))
      ('eval-when-compile
       (when (proper-list-p form)
         (delq nil (mapcar #'qg-graph-require (cdr form)))))))

  (defun qg-graph-file (path)
    (let ((read-circle nil)
          (caller-buffer (current-buffer))
          (error-line 1)
          (error-stage "preparation")
          (read-shorthands hack-read-symbol-shorthands-function)
          shorthand-source-buffer
          rows)
      (condition-case failure
          (handler-bind
              ((error
                (lambda (_failure)
                  (setq error-line
                        (cond
                         ((eq (current-buffer) caller-buffer) 1)
                         ((and shorthand-source-buffer
                               (not (eq (current-buffer) shorthand-source-buffer)))
                          (+ (line-number-at-pos)
                             (with-current-buffer shorthand-source-buffer
                               (1- (line-number-at-pos)))))
                         (t (line-number-at-pos)))))))
            (let ((hack-read-symbol-shorthands-function
                   (when read-shorthands
                     (lambda ()
                       (setq shorthand-source-buffer (current-buffer))
                       (unwind-protect
                           (funcall read-shorthands)
                         (setq shorthand-source-buffer nil))))))
              (load-with-code-conversion
               (expand-file-name path) path nil t
               (lambda (buffer _filename)
                 (setq error-stage "reader")
                 (with-current-buffer buffer
                   (goto-char (point-min))
                   (let ((load-read-function
                          (lambda (stream)
                            (let ((load-read-function nil)
                                  (symbols-with-pos-enabled t))
                              (dolist (row (qg-graph-top-level (read-positioning-symbols stream)))
                                (push row rows)))
                            nil)))
                     (eval-buffer buffer)))))
              (nreverse rows)))
        (error
         (list (list 'outside error-line
                     (format "Emacs Lisp source with a %s error (%s)"
                             error-stage (error-message-string failure))))))))

  (defun qg-graph-resolve (row modules providers)
    (pcase row
      (`(outside ,line ,description)
       (qg-graph-outside line description))
      (`(require ,line ,feature ,filename)
       (let ((candidates (if filename
                             (delq nil (list (gethash (concat filename ".el") modules)
                                             (gethash filename modules)))
                           (gethash feature providers))))
         (pcase candidates
           (`(,target)
            (list (cons 'kind "require") (cons 'line line) (cons 'target target)))
           ('nil
            (when filename
              (qg-graph-outside
               line (format "require filename '%s' has no measured target and" filename))))
           (_
            (qg-graph-outside
             line (if filename
                      (format "require filename '%s' matches multiple measured files and" filename)
                    (format "require feature '%S' has multiple measured providers and" feature)))))))))

  (let* ((manifest (pop command-line-args-left))
         (report (pop command-line-args-left))
         (inputs (with-temp-buffer
                   (insert-file-contents manifest)
                   (json-parse-buffer :object-type 'alist :array-type 'list)))
         (paths (alist-get 'sources inputs))
         (modules (make-hash-table :test 'equal))
         (providers (make-hash-table :test 'eq))
         (results (make-hash-table :test 'equal)))
    (dolist (path (alist-get 'modules inputs))
      (puthash path path modules))
    (dolist (path paths)
      (let ((rows (qg-graph-file path)))
        (puthash path rows results)
        (dolist (row rows)
          (pcase row
            (`(provide ,_ ,feature)
             (cl-pushnew path (gethash feature providers) :test #'equal))))))
    (dolist (path paths)
      (let ((rows (gethash path results)))
        (puthash path
                 (vconcat (delq nil (mapcar (lambda (row) (qg-graph-resolve row modules providers))
                                            rows)))
                 results)))
    (let ((coding-system-for-write 'utf-8-unix))
      (with-temp-file report
        (insert (json-encode results))))))
"""

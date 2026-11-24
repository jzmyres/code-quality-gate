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
  (require 'json)
  (require 'seq)

  (defun qg-graph-quoted-symbol-p (form)
    (and (eq (proper-list-p form) 2)
         (eq (car form) 'quote)
         (symbolp (cadr form))))

  (defun qg-graph-interned-name (symbol)
    (let* ((symbol (bare-symbol symbol))
           (name (symbol-name symbol)))
      (when (eq symbol (intern-soft name)) name)))

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

  (defun qg-graph-require (form &optional line)
    (when (and (eq (car-safe form) 'require) (proper-list-p form))
      (let* ((line (or line (line-number-at-pos (symbol-with-pos-pos (car form)))))
             (quoted-feature (qg-graph-quoted-symbol-p (cadr form)))
             (feature (and quoted-feature (qg-graph-interned-name (cadadr form))))
             (feature-problem
              (cond ((not quoted-feature) "computed")
                    ((not feature) "uninterned")))
             (filename (nth 2 form))
             (filename-problem
              (cond ((stringp filename)
                     (unless (qg-graph-canonical-filename-p filename)
                       "noncanonical"))
                    ((not (null filename)) "computed")))
             (problem
              (cond ((and feature-problem filename-problem)
                     (format "require with a %s feature and a %s filename"
                             feature-problem filename-problem))
                    (feature-problem (format "%s require feature" feature-problem))
                    (filename-problem (format "%s require filename" filename-problem)))))
        (if problem
            (qg-graph-outside line problem)
          (list (cons 'kind "require") (cons 'line line)
                (cons 'feature feature) (cons 'filename filename))))))

  (defun qg-graph-provide (form &optional line)
    (when (and (eq (car-safe form) 'provide)
               (proper-list-p form)
               (qg-graph-quoted-symbol-p (cadr form)))
      (let ((feature (qg-graph-interned-name (cadadr form))))
        (if feature
            (list (cons 'kind "provide") (cons 'feature feature))
          (qg-graph-outside (or line (line-number-at-pos (symbol-with-pos-pos (car form))))
                            "uninterned provide feature")))))

  (defun qg-graph-top-level (form line)
    (pcase (car-safe form)
      ('provide
       (let ((row (qg-graph-provide form line)))
         (when row (list row))))
      ('progn
       (when (proper-list-p form)
         (delq nil (mapcar #'qg-graph-provide (cdr form)))))
      ('require
       (let ((row (qg-graph-require form line)))
         (when row (list row))))
      ('eval-when-compile
       (when (proper-list-p form)
         (delq nil (mapcar #'qg-graph-require (cdr form)))))))

  (defun qg-graph-file (path)
    (let ((absolute-path (expand-file-name path)) (source-line 1))
      (condition-case failure
          (catch 'qg-graph-records
            (load-with-code-conversion
             absolute-path path nil t
             (lambda (buffer _filename)
               (with-current-buffer buffer
                 (let ((syntax (copy-syntax-table emacs-lisp-mode-syntax-table)) rows)
                   (modify-syntax-entry ?\r " " syntax)
                   (set-syntax-table syntax)
                   (goto-char (point-min))
                   (when (looking-at-p "#!") (forward-line 1))
                   (while (progn (forward-comment (point-max)) (not (eobp)))
                     (setq source-line (line-number-at-pos))
                     (let* ((symbols-with-pos-enabled t)
                            (form (read-positioning-symbols (current-buffer))))
                       (dolist (row (qg-graph-top-level form source-line))
                         (push row rows))))
                   (throw 'qg-graph-records (vconcat (nreverse rows))))))))
        (error (format "%s:%d: %s" path source-line (error-message-string failure))))))

  (let* ((manifest (pop command-line-args-left))
         (report (pop command-line-args-left))
         (paths (with-temp-buffer
                  (insert-file-contents manifest)
                  (json-parse-buffer :array-type 'list)))
         (results (make-hash-table :test 'equal)))
    (dolist (path paths)
      (puthash path (qg-graph-file path) results))
    (let ((coding-system-for-write 'utf-8-unix))
      (with-temp-file report
        (insert (json-encode results))))))
"""

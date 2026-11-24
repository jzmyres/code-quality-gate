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

  (defun qg-graph-quoted-symbol-p (form)
    (and (eq (proper-list-p form) 2)
         (eq (car form) 'quote)
         (symbolp (cadr form))))

  (defun qg-graph-outside (line operand)
    (list (cons 'kind "outside") (cons 'line line)
          (cons 'message (format "computed require %s is outside the extractor" operand))))

  (defun qg-graph-require (form &optional line)
    (when (and (eq (car-safe form) 'require) (proper-list-p form))
      (let* ((line (or line (line-number-at-pos (symbol-with-pos-pos (car form)))))
             (feature (cadr form))
             (filename (nth 2 form))
             (outside (delq nil
                            (list (unless (qg-graph-quoted-symbol-p feature)
                                    (qg-graph-outside line "feature"))
                                  (unless (or (null filename) (stringp filename))
                                    (qg-graph-outside line "filename"))))))
        (or outside (list (list (cons 'kind "require") (cons 'line line)
                                (cons 'feature (symbol-name (bare-symbol (cadr feature))))
                                (cons 'filename filename)))))))

  (defun qg-graph-provide (form)
    (when (and (eq (car-safe form) 'provide)
               (proper-list-p form)
               (qg-graph-quoted-symbol-p (cadr form)))
      (list (cons 'kind "provide")
            (cons 'feature (symbol-name (bare-symbol (cadadr form)))))))

  (defun qg-graph-top-level (form line)
    (pcase (car-safe form)
      ('provide
       (let ((row (qg-graph-provide form)))
         (when row (list row))))
      ('progn
       (when (proper-list-p form)
         (delq nil (mapcar #'qg-graph-provide (cdr form)))))
      ('require (qg-graph-require form line))
      ('eval-when-compile
       (when (proper-list-p form)
         (apply #'append (mapcar #'qg-graph-require (cdr form)))))))

  (defun qg-graph-file (path)
    (with-temp-buffer
      (let ((line 1) rows)
        (condition-case failure
            (progn
              (insert-file-contents path)
              (set-syntax-table emacs-lisp-mode-syntax-table)
              (goto-char (point-min))
              (when (looking-at-p "#!") (forward-line 1))
              (while (progn (forward-comment (point-max)) (not (eobp)))
                (setq line (line-number-at-pos))
                (let* ((symbols-with-pos-enabled t)
                       (form (read-positioning-symbols (current-buffer))))
                  (dolist (row (qg-graph-top-level form line))
                    (push row rows))))
              (vconcat (nreverse rows)))
          (error (format "%s:%d: %s" path line (error-message-string failure)))))))

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

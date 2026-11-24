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

  (defun qg-graph-require (form line)
    (when (and (eq (car-safe form) 'require) (proper-list-p form))
      (let* ((feature (cadr form))
             (filename (nth 2 form))
             (outside (delq nil
                            (list (unless (qg-graph-quoted-symbol-p feature)
                                    (qg-graph-outside line "feature"))
                                  (unless (or (null filename) (stringp filename))
                                    (qg-graph-outside line "filename"))))))
        (or outside (list (list (cons 'kind "require") (cons 'line line)
                                (cons 'feature (symbol-name (cadr feature)))
                                (cons 'filename filename)))))))

  (defun qg-graph-compile-requires (start end)
    (save-excursion
      (goto-char (1+ start))
      (read (current-buffer))
      (let (rows)
        (while (progn (forward-comment (point-max)) (< (point) (1- end)))
          (let ((line (line-number-at-pos))
                (direct (eq (char-after) ?\())
                (form (condition-case nil
                          (read (current-buffer))
                        (invalid-read-syntax (goto-char end) nil))))
            (when direct
              (dolist (row (qg-graph-require form line))
                (push row rows)))))
        (nreverse rows))))

  (defun qg-graph-top-level (form start line)
    (when (eq (char-after start) ?\()
      (pcase (car-safe form)
        ('provide
         (when (and (proper-list-p form) (qg-graph-quoted-symbol-p (cadr form)))
           (list (list (cons 'kind "provide") (cons 'feature (symbol-name (cadadr form)))))))
        ('require (qg-graph-require form line))
        ('eval-when-compile (qg-graph-compile-requires start (point))))))

  (defun qg-graph-file (path)
    (with-temp-buffer
      (let ((line 1) (read-circle nil) rows)
        (condition-case failure
            (progn
              (insert-file-contents path)
              (set-syntax-table emacs-lisp-mode-syntax-table)
              (goto-char (point-min))
              (when (looking-at-p "#!") (forward-line 1))
              (while (progn (forward-comment (point-max)) (not (eobp)))
                (setq line (line-number-at-pos))
                (let* ((start (point))
                       (form (read (current-buffer))))
                  (dolist (row (qg-graph-top-level form start line))
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

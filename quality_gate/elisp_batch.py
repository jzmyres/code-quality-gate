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
  (require 'subr-x)

  (defun qg-graph-quoted-symbol-p (form)
    (and (eq (proper-list-p form) 2)
         (eq (car form) 'quote)
         (symbolp (cadr form))))

  (defun qg-graph-outside (line head operand reason &optional conjunction)
    (list (cons 'kind "outside") (cons 'line line)
          (cons 'form (symbol-name head)) (cons 'operand operand) (cons 'reason reason)
          (cons 'message (format "%s%s is outside the extractor" reason
                                 (if conjunction " and" "")))))

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

  (defun qg-graph-operand (operand)
    (let ((print-symbols-bare t)
          (print-escape-newlines t))
      (cond ((stringp operand) operand)
            ((qg-graph-quoted-symbol-p operand) (symbol-name (cadr operand)))
            (t (prin1-to-string operand)))))

  (defun qg-graph-feature (operand)
    (and (qg-graph-quoted-symbol-p operand) (bare-symbol (cadr operand))))

  (defun qg-graph-feature-problem (operand feature)
    (cond ((not (qg-graph-quoted-symbol-p operand)) "computed")
          ((not (eq feature (intern-soft feature))) "uninterned")))

  (defun qg-graph-candidates (name modules append-suffix must-suffix)
    (delq nil
          (list (and (or (not must-suffix) (string-suffix-p ".el" name))
                     (gethash name modules))
                (and append-suffix (gethash (concat name ".el") modules)))))

  (defun qg-graph-edge (line head target)
    (list (cons 'kind (if (eq head 'require) "require" "path-load"))
          (cons 'line line) (cons 'target target)))

  (defun qg-graph-filename-result (line head operand filename candidates)
    (if (eq (length candidates) 1)
        (qg-graph-edge line head (car candidates))
      (qg-graph-outside line head operand
                        (format "%s filename '%s' %s" head filename
                                (if candidates "matches multiple measured files"
                                  "has no measured target"))
                        t)))

  (defun qg-graph-require (form line operand modules providers)
    (let* ((feature-operand (cadr form))
           (feature (qg-graph-feature feature-operand))
           (feature-problem (qg-graph-feature-problem feature-operand feature))
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
      (cond (problem (qg-graph-outside line 'require
                                      (if (and filename-problem (not feature-problem))
                                          (qg-graph-operand filename)
                                        operand)
                                      problem))
            (filename (qg-graph-filename-result
                       line 'require filename filename (qg-graph-candidates filename modules t nil)))
            (t
             (let ((matches (gethash feature providers)))
               (if (eq (length matches) 1)
                   (qg-graph-edge line 'require (car matches))
                 (qg-graph-outside
                  line 'require operand
                  (format "require feature '%S' %s" feature
                          (if matches "has multiple measured providers" "has no measured provider"))
                  t)))))))

  (defun qg-graph-provide (form line operand arity)
    (let* ((feature-operand (cadr form))
           (feature (qg-graph-feature feature-operand))
           (problem (qg-graph-feature-problem feature-operand feature))
           (subfeatures (nth 2 form)))
      (cond (problem (qg-graph-outside line 'provide operand (format "%s provide feature" problem)))
            ((not (or (null subfeatures)
                      (and (eq (proper-list-p subfeatures) 2)
                           (eq (car subfeatures) 'quote)
                           (listp (cadr subfeatures)))))
             (qg-graph-outside line 'provide operand "provide with unsupported arguments"))
            (t (list 'provide line feature (= arity 2))))))

  (defun qg-graph-load-name (filename prefix)
    (when (and (stringp filename) (not (string-empty-p filename))
               (not (string-prefix-p "/" filename))
               (not (string-prefix-p "~" filename))
               (not (string-match-p "[$:[:cntrl:]]" filename))
               (not (string-search "\\" filename)))
      (catch 'escape
        (let ((parts (reverse prefix)))
          (dolist (part (split-string filename "/" t))
            (cond ((equal part "."))
                  ((equal part "..") (unless (pop parts) (throw 'escape nil)))
                  (t (push part parts))))
          (when parts (mapconcat #'identity (nreverse parts) "/"))))))

  (defun qg-graph-load (form line head operand path modules)
    (let* ((file-call (eq head 'load-file))
           (filename (cadr form))
           (no-suffix (nth 4 form))
           (must-suffix (nth 5 form))
           (prefix (and file-call (butlast (split-string path "/" t))))
           (name (qg-graph-load-name filename prefix)))
      (cond ((not (and (memq no-suffix '(nil t)) (memq must-suffix '(nil t))))
             (qg-graph-outside line head operand "load with unsupported arguments"))
            ((not name)
             (qg-graph-outside line head operand (format "%s with an unusable filename" head)))
            (t (qg-graph-filename-result
                line head operand filename
                (qg-graph-candidates name modules (not (or file-call no-suffix)) must-suffix))))))

  (defun qg-graph-declaration (form head role path modules providers)
    (let* ((line (qg-graph-head-line form))
           (operand (qg-graph-operand (car-safe (cdr form))))
           (arity (proper-list-p form)))
      (cond
       ((not (or (eq role 'top)
                 (if (eq head 'provide) (eq role 'provider) (eq role 'dependency))))
        (qg-graph-outside line head operand (format "%s in an unsupported evaluation context" head)))
       ((not (and arity (<= 2 arity (pcase head
                                     ('load-file 2) ('provide 3) ('require 4) ('load 6)))))
        (qg-graph-outside line head operand (format "%s with unsupported arguments" head)))
       ((eq head 'provide) (qg-graph-provide form line operand arity))
       ((eq head 'require) (qg-graph-require form line operand modules providers))
       (t (qg-graph-load form line head operand path modules)))))

  (defun qg-graph-walk-template (form depth visit)
    (cond
     ((eq (car-safe form) (intern "`"))
      (qg-graph-walk-template (car-safe (cdr form)) (1+ depth) visit))
     ((memq (car-safe form) (list (intern ",") (intern ",@")))
      (let ((operand (car-safe (cdr form))))
        (if (= depth 1) (funcall visit operand nil)
          (qg-graph-walk-template operand (1- depth) visit))))
     ((consp form)
      (qg-graph-walk-template (car form) depth visit)
      (qg-graph-walk-template (cdr form) depth visit))
     ((vectorp form)
      (seq-doseq (part form) (qg-graph-walk-template part depth visit)))))

  (defun qg-graph-tail (form count)
    (dotimes (_ count)
      (setq form (cdr-safe form)))
    form)

  (defun qg-graph-walk (forms path modules providers)
    (let (rows)
      (cl-labels
          ((body (forms role)
             (while (consp forms) (visit (pop forms) role)))
           (visit (form role)
             (pcase (car-safe form)
               ((and (or 'require 'provide 'load 'load-file) head)
                (push (qg-graph-declaration form (bare-symbol head) role path modules providers) rows)
                (body (cdr form) nil))
               ((or 'let 'let*)
                (let ((bindings (car-safe (cdr form))))
                  (while (consp bindings)
                    (let ((binding (pop bindings)))
                      (visit (car-safe (cdr-safe binding)) nil))))
                (body (qg-graph-tail form 2) nil))
               ((or 'defun 'defmacro) (body (qg-graph-tail form 3) nil))
               ('lambda (body (qg-graph-tail form 2) nil))
               ('function
                (let ((function (car-safe (cdr form))))
                  (when (eq (car-safe function) 'lambda) (visit function nil))))
               ('condition-case
                (visit (car-safe (qg-graph-tail form 2)) nil)
                (let ((handlers (qg-graph-tail form 3)))
                  (while (consp handlers) (body (cdr-safe (pop handlers)) nil))))
               ('cond
                (let ((clauses (cdr form)))
                  (while (consp clauses) (body (pop clauses) nil))))
               ('progn (body (cdr form) (and (eq role 'top) 'provider)))
               ('eval-when-compile (body (cdr form) (and (eq role 'top) 'dependency)))
               (_ (when (eq (car-safe form) (intern "`"))
                    (qg-graph-walk-template (car-safe (cdr form)) 1 #'visit))))))
        (body forms 'top))
      (nreverse rows)))

  (defun qg-graph-index-providers (forms path modules providers)
    (dolist (form forms)
      (let ((candidates (if (eq (car-safe form) 'progn) (cdr form) (list form))))
        (while (consp candidates)
          (let ((candidate (pop candidates)))
            (when (eq (car-safe candidate) 'provide)
              (pcase (qg-graph-declaration candidate 'provide 'provider path modules providers)
                (`(provide ,_ ,feature ,_)
                 (cl-pushnew path (gethash feature providers) :test #'equal)))))))))

  (defun qg-graph-file (path)
    (let ((read-circle nil)
          (caller-buffer (current-buffer))
          (error-line 1)
          (error-stage "preparation")
          (read-shorthands hack-read-symbol-shorthands-function)
          shorthand-source-buffer
          content forms)
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
                   (setq content (buffer-string))
                   (goto-char (point-min))
                   (let ((load-read-function
                          (lambda (stream)
                            (let ((load-read-function nil)
                                  (symbols-with-pos-enabled t))
                              (push (read-positioning-symbols stream) forms))
                            nil)))
                     (eval-buffer buffer)))))
              (list content (nreverse forms))))
        (error
         (list (list 'reader-error error-line error-stage
                     (format "Emacs Lisp source with a %s error (%s)"
                             error-stage (error-message-string failure))))))))

  (defun qg-graph-at-source (content function)
    ;; Use the decoded text for positioned heads after the reader handler has exited.
    (with-temp-buffer
      (insert content)
      (let ((symbols-with-pos-enabled t))
        (funcall function))))

  (defun qg-graph-protocol (row)
    (pcase row
      (`(reader-error ,line ,stage ,description)
       (list (cons 'kind "reader-error") (cons 'line line) (cons 'stage stage)
             (cons 'message (format "%s is outside the extractor" description))))
      (`(provide ,line ,feature t)
       (list (cons 'kind "provider") (cons 'line line) (cons 'feature (symbol-name feature))))
      (`(provide . ,_) nil)
      (_ row)))

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
      (let ((input (qg-graph-file path)))
        (puthash path input results)
        (when (stringp (car input))
          (qg-graph-at-source
           (car input) (lambda () (qg-graph-index-providers (cadr input) path modules providers))))))
    (dolist (path paths)
      (let* ((input (gethash path results))
             (rows (if (stringp (car input))
                       (qg-graph-at-source
                        (car input)
                        (lambda () (qg-graph-walk (cadr input) path modules providers)))
                     input)))
        (puthash path (vconcat (delq nil (mapcar #'qg-graph-protocol rows))) results)))
    (let ((coding-system-for-write 'utf-8-unix))
      (with-temp-file report
        (insert (json-encode results))))))
"""

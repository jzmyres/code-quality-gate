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

  (defun qg-graph-char-table-children (table)
    (let* ((parent (char-table-parent table))
           (children (list parent (char-table-range table nil)))
           (index 0))
      (condition-case nil
          (while t
            (push (char-table-extra-slot table index) children)
            (setq index (1+ index)))
        (args-out-of-range nil))
      (when parent
        (setq table (copy-sequence table))
        (set-char-table-parent table nil))
      (map-char-table (lambda (_key value) (push value children)) table)
      children))

  (defun qg-graph-object-children (object)
    (cond ((consp object) (list (car object) (cdr object)))
          ((or (vectorp object) (recordp object) (closurep object))
           (cl-loop for index below (length object) collect (aref object index)))
          ((hash-table-p object)
           (let (children)
             (maphash (lambda (key value) (push key children) (push value children)) object)
             children))
          ((stringp object) (mapcar #'caddr (object-intervals object)))
          ((char-table-p object) (qg-graph-char-table-children object))))

  (defun qg-graph-occurrences (form)
    (let ((symbols-with-pos-enabled nil)
          (counts (make-hash-table :test 'eq))
          (pending (list form)))
      (while pending
        (let* ((object (pop pending))
               (count (gethash object counts 0)))
          (when (< count 2)
            (puthash object (1+ count) counts)
            (setq pending (nconc (qg-graph-object-children object) pending)))))
      counts))

  (defun qg-graph-shared-p (object occurrences)
    (let ((symbols-with-pos-enabled nil))
      (and (or (consp object) (symbol-with-pos-p object) (stringp object))
           (eq (gethash object occurrences) 2))))

  (defun qg-graph-require (form occurrences)
    (when (and (eq (car-safe form) 'require) (proper-list-p form))
      (let* ((line (qg-graph-head-line form))
             (feature-operand (cadr form))
             (quoted-feature (qg-graph-quoted-symbol-p feature-operand))
             (feature (and quoted-feature (bare-symbol (cadr feature-operand))))
             (feature-problem
              (cond ((not quoted-feature) "computed")
                    ((seq-some (lambda (object) (qg-graph-shared-p object occurrences))
                               (list (cdr form) feature-operand (car feature-operand)
                                     (cdr feature-operand) (cadr feature-operand)))
                     "shared")
                    ((not (eq feature (intern-soft feature))) "uninterned")))
             (filename (nth 2 form))
             (filename-problem
              (cond ((and (stringp filename) (not (qg-graph-canonical-filename-p filename)))
                     "noncanonical")
                    ((or (qg-graph-shared-p (cddr form) occurrences)
                         (and (stringp filename) (qg-graph-shared-p filename occurrences)))
                     "shared")
                    ((not (or (stringp filename) (null filename))) "computed")))
             (problem
              (cond ((qg-graph-shared-p (car form) occurrences) "shared require head")
                    ((and feature-problem filename-problem)
                     (format "require with a %s feature and a %s filename"
                             feature-problem filename-problem))
                    (feature-problem (format "%s require feature" feature-problem))
                    (filename-problem (format "%s require filename" filename-problem)))))
        (if problem
            (list 'outside line problem)
          (list 'require line feature filename)))))

  (defun qg-graph-provide (form occurrences)
    (when (and (eq (car-safe form) 'provide)
               (proper-list-p form))
      (cond ((qg-graph-shared-p (car form) occurrences)
             (list 'outside (qg-graph-head-line form) "shared provide head"))
            ((qg-graph-quoted-symbol-p (cadr form))
             (let ((line (qg-graph-head-line form))
                   (feature (bare-symbol (cadadr form))))
               (if (eq feature (intern-soft feature))
                   (list 'provide line feature)
                 (list 'outside line "uninterned provide feature")))))))

  (defun qg-graph-top-level (form occurrences)
    (pcase (car-safe form)
      ('provide
       (let ((row (qg-graph-provide form occurrences)))
         (when row (list row))))
      ('progn
       (when (proper-list-p form)
         (delq nil (mapcar (lambda (child) (qg-graph-provide child occurrences)) (cdr form)))))
      ('require
       (let ((row (qg-graph-require form occurrences)))
         (when row (list row))))
      ('eval-when-compile
       (when (proper-list-p form)
         (delq nil (mapcar (lambda (child) (qg-graph-require child occurrences)) (cdr form)))))))

  (defun qg-graph-file (path)
    (condition-case failure
        (catch 'qg-graph-records
          (load-with-code-conversion
           (expand-file-name path) path nil t
           (lambda (buffer _filename)
             (with-current-buffer buffer
               (goto-char (point-min))
               (let ((symbols-with-pos-enabled t) rows)
                 (while t
                   (let ((form (condition-case nil
                                   (read-positioning-symbols buffer)
                                 (end-of-file
                                  (throw 'qg-graph-records (nreverse rows))))))
                     (dolist (row (qg-graph-top-level form (qg-graph-occurrences form)))
                       (push row rows)))))))))
      (error (format "%s: %s" path (error-message-string failure)))))

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
        (unless (stringp rows)
          (dolist (row rows)
            (pcase row
              (`(provide ,_ ,feature)
               (cl-pushnew path (gethash feature providers) :test #'equal)))))))
    (dolist (path paths)
      (let ((rows (gethash path results)))
        (unless (stringp rows)
          (puthash path
                   (vconcat (delq nil (mapcar (lambda (row) (qg-graph-resolve row modules providers))
                                              rows)))
                   results))))
    (let ((coding-system-for-write 'utf-8-unix))
      (with-temp-file report
        (insert (json-encode results))))))
"""

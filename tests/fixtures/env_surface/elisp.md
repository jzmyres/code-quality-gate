```elisp
(progn
  (getenv "GET")
  (setenv "SET" "value")
  (getenv dynamic)
  (push "PUSH=value" process-environment)
  (setq process-environment new-environment)
  (with-environment-variables (("ONE" "1") ("TWO" "2"))
    (getenv "ONE"))
  process-environment
  '(getenv "quoted")
  (add-to-list 'process-environment "ADDED=1")
  (add-to-list 'process-environment value)
  (push (concat "DYNAMIC=" value) process-environment)
  (setq process-environment (cons "C=1" process-environment))
  (let ((process-environment '("LOCAL=1"))) (getenv "LOCAL"))
  (let* ((process-environment source)) (member "A=1" process-environment))
  (member "A=1" process-environment)
  (copy-sequence initial-environment)
  (setq process-environment (append '("KNOWN=1") unknown)))
```

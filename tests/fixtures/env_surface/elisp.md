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
  '(getenv "quoted"))
```

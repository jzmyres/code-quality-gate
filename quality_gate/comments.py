"""Find source comments outside the fixed table of tool-required lines."""
from __future__ import annotations

import ast
import io
import json
import re
import subprocess
import tokenize
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from . import shell_syntax
from .elisp_batch import batch_command
from .files import SCRIPT_LANGUAGE_BY_SUFFIX


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    text: str


@dataclass(frozen=True)
class ReadError:
    path: str
    text: str


_SHEBANG = r"#![ \t]*/[^ \t\r\n]+(?:[ \t]+[^\r\n]*)?"
_PYTHON_INTERPRETER = re.compile(r"python(?:[23](?:\.[0-9]+)?)?")
_ALLOWED_LINES = {
    "shebang": _SHEBANG,
    "header": r";;; {name} --- (?=\S)[^\r\n]*\S  -\*- lexical-binding: t; -\*-",
    "commentary": r";;; Commentary:",
    "code": r";;; Code:",
    "footer": r";;; {name} ends here",
}


def _allowed(kind: str, text: str, name: str = "") -> bool:
    return re.fullmatch(_ALLOWED_LINES[kind].format(name=re.escape(name)), text) is not None


def _env_command(arguments: list[str]) -> str:
    for part in arguments:
        if not part.startswith("-") and "=" not in part:
            return part
    return ""


def _shebang_words(line: str) -> list[str]:
    return line[2:].split() if _allowed("shebang", line) else []


def _script_interpreter(first_line: bytes) -> str:
    line = first_line.decode("utf-8", errors="replace").rstrip("\r\n")
    words = _shebang_words(line)
    if not words:
        return ""
    interpreter, *arguments = words
    name = Path(interpreter).name
    if name == "env":
        name = Path(_env_command(arguments)).name
    return name


def _python_findings(source: Path, path: str) -> list[Finding]:
    with tokenize.open(source) as stream:
        content = stream.read()
        has_bom = stream.encoding == "utf-8-sig"
    ast.parse(content, filename=path)
    tokens = tokenize.generate_tokens(io.StringIO(content).readline)
    return [
        Finding(path, token.start[0], token.string[:60])
        for token in tokens if token.type == tokenize.COMMENT
        and not (token.start[0] == 1 and not has_bom and _allowed("shebang", token.line.rstrip("\n")))
    ]


_ELISP_SCAN = r"""
(progn
  (require 'json)

  (defun qg-comments-mask (start end)
    "Blank START through END while preserving positions and line breaks."
    (let ((text (buffer-substring-no-properties start end)))
      (goto-char start)
      (delete-region start end)
      (insert (replace-regexp-in-string "[^\n]" " " text))))

  (defun qg-comments-character-p (start)
    "Return whether the question mark at START can start a character literal."
    (or (= start (point-min))
        (and (not (nth 5 (save-excursion (syntax-ppss (1- start)))))
             (or (memq (char-syntax (char-before start)) '(?\  ?\( ?\) ?\' ?\" ?>))
                 (and (eq (char-before start) ?@)
                      (eq (char-before (1- start)) ?,))))))

  (defun qg-comments-scan ()
    "Record comments and mask them for the reader.
Temporarily mask character literals during the syntax scan."
    (let (rows characters)
      (while (re-search-forward "[;?]" nil t)
        (let* ((start (match-beginning 0))
               (end (point))
               (state (syntax-ppss start)))
          (goto-char end)
          (unless (or (nth 3 state) (nth 4 state) (nth 5 state))
            (cond
             ((and (eq (char-after start) ??) (qg-comments-character-p start))
              (goto-char start)
              (read (current-buffer))
              (push (cons start (buffer-substring-no-properties start (point))) characters)
              (qg-comments-mask start (point)))
             ((let ((after (syntax-ppss end)))
                (and (nth 4 after) (eq (nth 8 after) start)))
              (end-of-line)
              (push (vector (line-number-at-pos start)
                            (buffer-substring-no-properties start (min (+ start 60) (point)))
                            (save-excursion
                              (goto-char start)
                              (buffer-substring-no-properties
                               (line-beginning-position) (line-end-position))))
                    rows)
              (qg-comments-mask start (point)))))))
      (dolist (character characters)
        (goto-char (car character))
        (delete-char (length (cdr character)))
        (insert (cdr character)))
      (vconcat (nreverse rows))))

  (defun qg-comments-file (path)
    (with-temp-buffer
      (insert-file-contents path)
      (delay-mode-hooks (emacs-lisp-mode))
      (goto-char (point-max))
      (skip-chars-backward " \t\r\n\f")
      (let ((last (line-number-at-pos))
            (commentary (lm-commentary-start))
            (code (lm-code-start)))
        (goto-char (point-min))
        (let* ((shebang (when (looking-at "#!")
                          (prog1 (concat (when (coding-system-get buffer-file-coding-system :bom)
                                           "\uFEFF")
                                         (buffer-substring-no-properties (point) (line-end-position)))
                            (qg-comments-mask (point) (line-end-position))
                            (goto-char (point-min)))))
               (rows (qg-comments-scan)))
          (goto-char (point-min))
          (skip-chars-forward " \t\r\n\f")
          (let ((first-code (+ (line-number-at-pos) (if (eobp) 1 0))))
            (while (not (eobp))
              (read (current-buffer))
              (skip-chars-forward " \t\r\n\f"))
            (vector rows last first-code
                    (and commentary (line-number-at-pos commentary))
                    (and code (line-number-at-pos code)) shebang))))))

  (let* ((manifest (pop command-line-args-left))
         (paths (with-temp-buffer
                  (insert-file-contents manifest)
                  (json-parse-buffer :array-type 'list)))
         (results (mapcar
                   (lambda (path)
                     (condition-case failure
                         (vector path (qg-comments-file path) nil)
                       (error (vector path nil (error-message-string failure)))))
                   paths)))
    (princ (json-encode (vconcat results)))))
"""


def _elisp_sections(
    physical_lines: dict[int, str], first_code: int, commentary: int | None, code: int | None,
) -> dict[str, int]:
    if commentary is None or commentary >= first_code:
        return {}
    if not _allowed("commentary", physical_lines.get(commentary, "")):
        return {}
    sections = {"commentary": commentary}
    if code is not None and commentary < code:
        sections["code"] = code
    return sections


def _elisp_exempt_lines(rows: list, name: str, positions: list, emacs_script: bool) -> set[int]:
    last, first_code, commentary, code = positions
    physical_lines = {line: physical for line, _, physical in rows}
    eligible = {"header": 2 if emacs_script else 1, "footer": last}
    eligible.update(_elisp_sections(physical_lines, first_code, commentary, code))
    return {
        line for kind, line in eligible.items()
        if _allowed(kind, physical_lines.get(line, ""), name)
    }


def _elisp_reports(root: Path, files: list[str], emacs: str, budget: int) -> list:
    with TemporaryDirectory(prefix="qg-comments-") as temporary:
        manifest = Path(temporary) / "files.json"
        manifest.write_text(json.dumps(files, ensure_ascii=False), encoding="utf-8")
        command = [*batch_command(emacs, Path("lisp-mnt"), _ELISP_SCAN), str(manifest)]
        result = subprocess.run(command, cwd=root, timeout=budget, capture_output=True, check=True)
    return json.loads(result.stdout)


def _emacs_script(shebang: str) -> bool:
    words = _shebang_words(shebang)
    if not words:
        return False
    interpreter, *arguments = words
    name = Path(interpreter).name
    if name == "env":
        return bool(arguments) and Path(arguments[0]).name == "emacs"
    return name == "emacs"


def _elisp_rows(path: str, report: list) -> list[Finding]:
    rows, *positions, shebang = report
    emacs_script = _emacs_script(shebang or "")
    exempt = _elisp_exempt_lines(rows, Path(path).name, positions, emacs_script)
    findings = [Finding(path, line, text) for line, text, _ in rows if line not in exempt]
    if shebang and not emacs_script:
        findings.insert(0, Finding(path, 1, shebang.removeprefix("\ufeff")[:60]))
    return findings


def _elisp_findings(
    root: Path, files: list[str], emacs: str, budget: int,
) -> tuple[list[Finding], list[ReadError]]:
    try:
        reports = _elisp_reports(root, files, emacs, budget)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        return [], [ReadError(path, f"cannot read {path}: {error}") for path in files]

    findings, errors = [], []
    for path, report, error in reports:
        if error is None:
            findings.extend(_elisp_rows(path, report))
        else:
            errors.append(ReadError(path, f"cannot read {path}: {error}"))
    return findings, errors


def _shell_comment_fields(node: dict[str, Any]) -> dict[str, type]:
    if "Hash" not in node:
        return {}
    fields = {"Hash.Line": int}
    if "Text" in node:
        fields["Text"] = str
    return fields


def _shell_comment_nodes(tree: dict[str, Any]) -> Iterator[dict[str, Any]]:
    pending = [tree]
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(reversed(node))
        if isinstance(node, dict):
            if "Hash" in node:
                yield node
            pending.extend(reversed(node.values()))


def _shell_findings(source: Path, path: str, budget: int) -> list[Finding]:
    content = source.read_bytes()
    tree = shell_syntax.parse(content, path, _shell_comment_fields, budget=budget)
    findings = []
    for node in _shell_comment_nodes(tree):
        line = node["Hash"]["Line"]
        text = "#" + node.get("Text", "")
        if not (line == 1 and content.startswith(b"#!") and _allowed("shebang", text)):
            findings.append(Finding(path, line, text[:60]))
    return findings


def _script_findings(source: Path, path: str, budget: int) -> list[Finding] | None:
    language = SCRIPT_LANGUAGE_BY_SUFFIX.get(source.suffix)
    if language == "python":
        return _python_findings(source, path)
    if language == "bash":
        return _shell_findings(source, path, budget)
    with source.open("rb") as stream:
        interpreter = _script_interpreter(stream.readline(4096))
    if interpreter in {"sh", "bash"}:
        return _shell_findings(source, path, budget)
    if _PYTHON_INTERPRETER.fullmatch(interpreter):
        return _python_findings(source, path)
    return None


def _read_script(root: Path, path: str, budget: int) -> tuple[list[Finding], list[ReadError]]:
    try:
        findings = _script_findings(root / path, path, budget)
    except (OSError, SyntaxError, tokenize.TokenError, ValueError) as error:
        detail = str(error).removeprefix(f"{path}: ")
        return [], [ReadError(path, f"cannot read {path}: {detail}")]
    if findings is None:
        return [], [ReadError(path, f"{path}: no comments driver")]
    return findings, []


def measure(
    root: Path, files: list[str], emacs: str = "emacs", budget: int = 30,
) -> tuple[list[Finding], list[ReadError]]:
    """Report forbidden comments and files that could not be analyzed."""
    paths = sorted(set(files))
    elisp = [path for path in paths if path.endswith(".el")]
    findings, errors = _elisp_findings(root, elisp, emacs, budget) if elisp else ([], [])
    for path in paths:
        if not path.endswith(".el"):
            rows, failures = _read_script(root, path, budget)
            findings.extend(rows)
            errors.extend(failures)
    findings.sort(key=lambda row: (row.path, row.line))
    return findings, errors

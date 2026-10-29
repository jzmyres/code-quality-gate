"""Locations, interpreter options, and scopes shared by the owner matchers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import re


@dataclass(frozen=True)
class Occurrence:
    kind: str
    value: str
    line: int
    start: int
    end: int
    scope: tuple[str, int]
    cover_scopes: frozenset[tuple[str, int]]
    reason: str | None = None


def covered(forbidden: Occurrence, allowed: Occurrence) -> bool:
    if forbidden.kind == allowed.kind == "text-regex":
        return allowed.start <= forbidden.start and allowed.end >= forbidden.end
    if forbidden.scope in allowed.cover_scopes:
        return True
    return False


# Invocation options from these manuals (zsh names include its option aliases):
# https://docs.python.org/3/using/cmdline.html
# https://github.com/python/cpython/blob/2.7/Doc/using/cmdline.rst
# https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html
# https://manpages.debian.org/bookworm/dash/dash.1.en.html
# https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html
# https://zsh.sourceforge.io/Doc/Release/Invocation.html
# https://zsh.sourceforge.io/Doc/Release/Options.html
# https://www.ibm.com/docs/en/aix/7.3.0?topic=k-ksh93-command
# Values describe the effect on parsing argv: flag, operand, command, stdin,
# end of options, or exit. The same tables are used for shell and Python argv.
def _options(flags: str, **special: str) -> dict[str, str]:
    return {**dict.fromkeys(flags, "flag"), **special}


_ZSH_NAMES = """
ALIASES ALIAS_FUNC_DEF ALL_EXPORT ALWAYS_LAST_PROMPT ALWAYS_TO_END APPEND_CREATE
APPEND_HISTORY AUTO_CD AUTO_CONTINUE AUTO_LIST AUTO_MENU AUTO_NAME_DIRS AUTO_PARAM_KEYS
AUTO_PARAM_SLASH AUTO_PUSHD AUTO_REMOVE_SLASH AUTO_RESUME BAD_PATTERN BANG_HIST
BARE_GLOB_QUAL BASH_AUTO_LIST BASH_REMATCH BEEP BG_NICE BRACE_CCL BRACE_EXPAND
BSD_ECHO CASE_GLOB CASE_MATCH CASE_PATHS CDABLE_VARS CD_SILENT CHASE_DOTS
CHASE_LINKS CHECK_JOBS CHECK_RUNNING_JOBS CLOBBER CLOBBER_EMPTY COMBINING_CHARS
COMPLETE_ALIASES COMPLETE_IN_WORD CONTINUE_ON_ERROR CORRECT CORRECT_ALL
CSH_JUNKIE_HISTORY CSH_JUNKIE_LOOPS CSH_JUNKIE_QUOTES CSH_NULLCMD CSH_NULL_GLOB
C_BASES C_PRECEDENCES DEBUG_BEFORE_CMD DOT_GLOB DVORAK EMACS EQUALS ERR_EXIT
ERR_RETURN EVAL_LINENO EXEC EXTENDED_GLOB EXTENDED_HISTORY FLOW_CONTROL FORCE_FLOAT
FUNCTION_ARGZERO GLOB GLOBAL_EXPORT GLOBAL_RCS GLOB_ASSIGN GLOB_COMPLETE GLOB_DOTS
GLOB_STAR_SHORT GLOB_SUBST HASH_ALL HASH_CMDS HASH_DIRS HASH_EXECUTABLES_ONLY
HASH_LIST_ALL HIST_ALLOW_CLOBBER HIST_APPEND HIST_BEEP HIST_EXPAND
HIST_EXPIRE_DUPS_FIRST HIST_FCNTL_LOCK HIST_FIND_NO_DUPS HIST_IGNORE_ALL_DUPS
HIST_IGNORE_DUPS HIST_IGNORE_SPACE HIST_LEX_WORDS HIST_NO_FUNCTIONS HIST_NO_STORE
HIST_REDUCE_BLANKS HIST_SAVE_BY_COPY HIST_SAVE_NO_DUPS HIST_SUBST_PATTERN HIST_VERIFY
HUP IGNORE_BRACES IGNORE_CLOSE_BRACES IGNORE_EOF INC_APPEND_HISTORY
INC_APPEND_HISTORY_TIME INTERACTIVE INTERACTIVE_COMMENTS KSH_ARRAYS KSH_AUTOLOAD
KSH_GLOB KSH_OPTION_PRINT KSH_TYPESET KSH_ZERO_SUBSCRIPT LIST_AMBIGUOUS LIST_BEEP
LIST_PACKED LIST_ROWS_FIRST LIST_TYPES LOCAL_LOOPS LOCAL_OPTIONS LOCAL_PATTERNS
LOCAL_TRAPS LOG LOGIN LONG_LIST_JOBS MAGIC_EQUAL_SUBST MAIL_WARN MAIL_WARNING
MARK_DIRS MENU_COMPLETE MONITOR MULTIBYTE MULTIOS MULTI_FUNC_DEF NOMATCH NOTIFY
NULL_GLOB NUMERIC_GLOB_SORT OCTAL_ZEROES ONE_CMD OVERSTRIKE PATH_DIRS PATH_SCRIPT
PHYSICAL PIPE_FAIL POSIX_ALIASES POSIX_ARGZERO POSIX_BUILTINS POSIX_CD
POSIX_IDENTIFIERS POSIX_JOBS POSIX_STRINGS POSIX_TRAPS PRINT_EIGHT_BIT
PRINT_EXIT_VALUE PRIVILEGED PROMPT_BANG PROMPT_CR PROMPT_PERCENT PROMPT_SP
PROMPT_SUBST PROMPT_VARS PUSHD_IGNORE_DUPS PUSHD_MINUS PUSHD_SILENT PUSHD_TO_HOME
RCS RC_EXPAND_PARAM RC_QUOTES REC_EXACT REMATCH_PCRE RESTRICTED RM_STAR_SILENT
RM_STAR_WAIT SHARE_HISTORY SHIN_STDIN SHORT_LOOPS SHORT_REPEAT SH_FILE_EXPANSION
SH_GLOB SH_NULLCMD SH_OPTION_LETTERS SH_WORD_SPLIT SINGLE_COMMAND SINGLE_LINE_ZLE
SOURCE_TRACE STDIN SUN_KEYBOARD_HACK TRACK_ALL TRANSIENT_RPROMPT TRAPS_ASYNC
TYPESET_SILENT TYPESET_TO_UNSET UNSET VERBOSE VI WARN_CREATE_GLOBAL WARN_NESTED_VAR
XTRACE ZLE
"""
_ZSH_LONG = {name.lower().replace("_", ""): "flag" for name in _ZSH_NAMES.split()}
_ZSH_LONG.update({"emulate": "operand", "help": "exit", "version": "exit"})


@dataclass(frozen=True)
class OptionTable:
    short: dict[str, str]
    long: dict[str, str]
    shell: bool = False


_TABLES = {
    "python": OptionTable(
        _options("bBdEiIOPqRsSuvx", c="command", m="command", W="operand", X="operand",
                 h="exit", V="exit", **{"?": "exit"}),
        {"check-hash-based-pycs": "operand", "help": "exit", "help-all": "exit",
         "help-env": "exit", "help-xoptions": "exit", "version": "exit"},
    ),
    "python2": OptionTable(
        _options("3bBdEiORsStuvUxX", c="command", m="command", Q="operand", W="operand",
                 h="exit", V="exit", **{"?": "exit"}),
        {"help": "exit", "version": "exit"},
    ),
    "bash": OptionTable(
        _options("abefhiklmnprtuvxBCEHPTD", c="command", o="operand", O="operand", s="stdin"),
        {**dict.fromkeys(("debug", "debugger", "dump-po-strings", "dump-strings", "login",
                          "noediting", "noprofile", "norc", "posix", "pretty-print",
                          "restricted", "verbose"), "flag"),
         "init-file": "operand", "rcfile": "operand", "help": "exit", "version": "exit"},
        True,
    ),
    "dash": OptionTable(_options("aCefnuvxIimqlVEbp", c="command", o="operand", s="stdin"), {}, True),
    "sh": OptionTable(_options("abCefhimnpuvx", c="command", o="operand", s="stdin"), {}, True),
    "ksh": OptionTable(_options("abCefhikmnprtuvxBDP",
                                c="command", o="operand", R="operand", s="stdin"), {}, True),
    "zsh": OptionTable(_options("0123456789BCDEFGHIJKLMNOPQRSTUVWXYZadefghiklmnprtuvwxy",
                                b="end", c="command", o="operand", s="stdin", **{"-": "end"}),
                       _ZSH_LONG, True),
}
# An unversioned "python" can name either Python 2 or 3, whose -X options
# differ. Do not guess how many arguments it consumes.
_TABLES["python-generic"] = OptionTable(
    {**_TABLES["python"].short, "X": "ambiguous"}, _TABLES["python"].long
)
_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh"})
_PYTHONS = re.compile(r"python[0-9]+(?:\.[0-9]+)*")


def _kind(word: str) -> str | None:
    name = PurePosixPath(word).name
    if name in _SHELLS:
        return name
    if name == "python":
        return "python-generic"
    if _PYTHONS.fullmatch(name):
        return "python2" if name == "python2" or name.startswith("python2.") else "python"
    return None


@dataclass(frozen=True)
class ScriptResult:
    index: int | None = None
    error_index: int | None = None
    reason: str | None = None


def _long_option(value: str, kind: str, table: OptionTable) -> str | None:
    name = value[2:]
    if kind == "zsh":
        name = name.lower().replace("-", "").replace("_", "")
        if name not in table.long and name.startswith("no"):
            name = name[2:]
    return table.long.get(name)


def _end_short(letter: str, sh_letters: bool) -> bool:
    return letter != "b" or not sh_letters


def _short_option(value: str, table: OptionTable, sh_letters: bool) -> tuple[str | None, bool, bool | None]:
    end = False
    stdin = None
    for position, letter in enumerate(value[1:]):
        action = table.short.get(letter)
        if action == "stdin":
            stdin = value[0] == "-"
        elif action == "end":
            end = _end_short(letter, sh_letters)
        elif action != "flag":
            return action, position < len(value) - 2, stdin
    return ("end" if end else "flag"), False, stdin


def _ambiguous_shell_operand(value: str, table: OptionTable) -> bool:
    return any(table.short.get(letter) == "operand" for letter in value[1:-1])


def _shell_flags(value: str, table: OptionTable) -> tuple[str | None, bool, bool | None, int]:
    actions = [table.short.get(letter) for letter in value[1:]]
    if None in actions:
        return None, False, None, 0
    if "command" in actions:
        return "command", False, None, 0
    stdin = (value[0] == "-") if "stdin" in actions else None
    count = actions.count("operand")
    return ("operand" if count else "flag"), False, stdin, count


def _shell_short_option(
    value: str, kind: str, table: OptionTable
) -> tuple[str | None, bool, bool | None, int]:
    if kind in ("sh", "ksh") and _ambiguous_shell_operand(value, table):
        return "ambiguous-shell", False, None, 0
    return _shell_flags(value, table)


def _single_option(
    value: str, table: OptionTable, sh_letters: bool
) -> tuple[str | None, bool, bool | None, int]:
    action, attached, stdin = _short_option(value, table, sh_letters)
    return action, attached, stdin, int(action == "operand" and not attached)


def _option(
    value: str, kind: str, table: OptionTable, sh_letters: bool
) -> tuple[str | None, bool, bool | None, int]:
    if value.startswith("--") or (kind == "zsh" and value.startswith("+-")):
        action = _long_option(value, kind, table)
        return action, False, None, int(action == "operand")
    if table.shell and kind != "zsh":
        return _shell_short_option(value, kind, table)
    return _single_option(value, table, sh_letters)


def _operand_error(words: list[str | None], index: int) -> ScriptResult | None:
    if index < len(words) and words[index] is None:
        return ScriptResult(error_index=index, reason="cannot determine option operand")
    return None


def _zsh_option_name(value: str, operand: str | None) -> tuple[str, bool]:
    short = "o" in value[1:] and not value.startswith(("--", "+-"))
    name = operand if short else value[2:]
    name = (name or "").lower().replace("-", "").replace("_", "")
    enabled = value.startswith("-")
    if name.startswith("no"):
        return name[2:], not enabled
    return name, enabled


class _ScriptScan:
    def __init__(self, words: list[str | None], kind: str) -> None:
        self.words = words
        self.kind = kind
        self.table = _TABLES[kind]
        self.index = 1
        self.stdin = False
        self.ended = False
        self.sh_letters = False

    def _zsh_name(self, value: str, operand: str | None) -> None:
        if self.kind != "zsh":
            return
        if value == "--emulate":
            self.sh_letters = operand in ("sh", "ksh")
            return
        name, enabled = _zsh_option_name(value, operand)
        if name == "shoptionletters":
            self.sh_letters = enabled
        if name in ("shinstdin", "stdin"):
            self.stdin = enabled

    def _operand(self, value: str, attached: bool, count: int) -> ScriptResult | None:
        operand = value[value.find("o") + 1:] if attached else None
        for _ in range(count):
            self.index += 1
            error = _operand_error(self.words, self.index)
            if error:
                return error
            if self.index < len(self.words):
                operand = self.words[self.index]
        self._zsh_name(value, operand)
        return None

    def _option_error(self, action: str | None) -> ScriptResult | None:
        if action is None:
            return ScriptResult(error_index=self.index, reason=f"unknown {self.kind} option")
        if action == "ambiguous":
            return ScriptResult(error_index=self.index, reason="python option depends on interpreter version")
        if action == "ambiguous-shell":
            return ScriptResult(error_index=self.index,
                                reason="shell option syntax depends on implementation")
        return None

    def _option(self, value: str) -> ScriptResult | None:
        action, attached, stdin, count = _option(value, self.kind, self.table, self.sh_letters)
        error = self._option_error(action)
        if error:
            return error
        if action in ("command", "exit"):
            return ScriptResult()
        if stdin is not None:
            self.stdin = stdin
        if action == "end":
            self.ended = True
        if action == "operand":
            return self._operand(value, attached, count)
        self._zsh_name(value, None)
        return None

    def _step(self) -> ScriptResult | None:
        value = self.words[self.index]
        if value is None:
            return ScriptResult(error_index=self.index,
                                reason="cannot determine interpreter option or script")
        if self._end_options(value):
            self.ended = True
            return None
        if self._is_script(value):
            return ScriptResult(index=self.index) if not self.stdin and value != "-" else ScriptResult()
        return self._option(value)

    def _end_options(self, value: str) -> bool:
        markers = ("--", "+-", "-", "+") if self.kind == "zsh" else ("--", "-", "+")
        return not self.ended and (value == "--" or (self.table.shell and value in markers))

    def _is_script(self, value: str) -> bool:
        prefixes = ("-", "+") if self.table.shell else ("-",)
        return self.ended or not value.startswith(prefixes) or value == "-"

    def scan(self) -> ScriptResult:
        while self.index < len(self.words):
            result = self._step()
            if result is not None:
                return result
            self.index += 1
        return ScriptResult()


def script_index(words: list[str | None]) -> ScriptResult:
    if not words or words[0] is None:
        return ScriptResult()
    kind = _kind(words[0])
    return _ScriptScan(words, kind).scan() if kind else ScriptResult()

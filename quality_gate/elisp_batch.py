"""Build invocations of trusted helpers in a clean batch Emacs."""
from pathlib import Path


def batch_command(emacs: str, helper: Path, form: str, load_path: tuple[str, ...] = ()) -> list[str]:
    """Invoke a trusted Lisp helper in a clean batch Emacs."""
    directories = [item for directory in load_path for item in ("-L", directory)]
    return [emacs, "-Q", "--batch", *directories, "-l", str(helper), "--eval", form]

"""Structure check — asserts the files the README documents exist, and
locks in the CWD-independence fix for the install/uninstall scripts.
Pure-Python; no WDK or kernel environment required."""
import os

import pytest

SRC_FILES = [
    "kernel_fuzzer.c",
    "kernel_fuzzer.h",
    "sources",
    "build.bat",
    "client.py",
    "install.bat",
    "uninstall.bat",
]

ROOT_FILES = [
    "README.md",
    "BUILD_AND_VERIFY.md",
    "SIGNING.md",
    "LICENSE",
]


@pytest.mark.parametrize("name", SRC_FILES)
def test_src_file_present(repo_root, name):
    assert os.path.isfile(os.path.join(repo_root, "src", name)), f"missing src/{name}"


@pytest.mark.parametrize("name", ROOT_FILES)
def test_root_file_present(repo_root, name):
    assert os.path.isfile(os.path.join(repo_root, name)), f"missing {name}"


@pytest.mark.parametrize("script", ["install.bat", "uninstall.bat"])
def test_service_scripts_are_cwd_independent(repo_root, script):
    """Both lifecycle scripts must `cd /d "%~dp0"` so they work from any
    caller CWD (BUILD_AND_VERIFY previously listed this as open)."""
    with open(os.path.join(repo_root, "src", script), "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    assert 'cd /d "%~dp0"' in text, f"{script} is not CWD-independent (missing cd /d \"%~dp0\")"

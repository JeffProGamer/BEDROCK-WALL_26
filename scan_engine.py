import hashlib
import os
from pathlib import Path
from typing import List, Tuple

SUSPICIOUS_EXTENSIONS = {
    '.bat',
    '.cmd',
    '.dll',
    '.exe',
    '.js',
    '.ps1',
    '.scr',
    '.vbs',
}

SUSPICIOUS_NAME_TOKENS = {
    'malware',
    'payload',
    'ransom',
    'trojan',
    'virus',
}

SKIPPED_DIR_NAMES = {
    '$recycle.bin',
    '.git',
    '.hg',
    '.pytest_cache',
    '.svn',
    '__pycache__',
}


def _hash_file(path: str) -> str:
    sha256 = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def scan_files(path: str) -> List[Tuple[str, str, str]]:
    results: List[Tuple[str, str, str]] = []
    root = Path(path)
    if not root.exists():
        return results

    for current_root, dirs, files in os.walk(root, onerror=lambda _error: None):
        dirs[:] = sorted(directory for directory in dirs if directory.lower() not in SKIPPED_DIR_NAMES)
        files.sort()
        for file_name in files:
            full_path_obj = Path(current_root) / file_name
            full_path = str(full_path_obj)
            lower_name = file_name.lower()
            extension = full_path_obj.suffix.lower()
            if extension in SUSPICIOUS_EXTENSIONS or any(token in lower_name for token in SUSPICIOUS_NAME_TOKENS):
                status = 'Threat Detected'
            else:
                status = 'Safe'
            try:
                results.append((full_path, status, _hash_file(full_path)))
            except OSError:
                continue
    return results

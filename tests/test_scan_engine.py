import os
import tempfile
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scan_engine import scan_files


def test_scan_files_detects_known_threats(tmp_path):
    threat_file = tmp_path / 'malware.exe'
    threat_file.write_bytes(b'fake binary')
    safe_file = tmp_path / 'notes.txt'
    safe_file.write_text('safe content', encoding='utf-8')

    results = scan_files(str(tmp_path))

    assert any(status == 'Threat Detected' for path, status, _hash in results if path.endswith('malware.exe'))
    assert any(status == 'Safe' for path, status, _hash in results if path.endswith('notes.txt'))


def test_scan_files_uses_exact_file_extensions(tmp_path):
    safe_file = tmp_path / 'release.exe.notes.txt'
    safe_file.write_text('safe content', encoding='utf-8')

    results = scan_files(str(tmp_path))

    assert any(status == 'Safe' for path, status, _hash in results if path.endswith('release.exe.notes.txt'))

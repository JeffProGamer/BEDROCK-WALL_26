import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import security_suite
from security_suite import build_security_summary


def test_build_security_summary_detects_threats(tmp_path):
    threat_file = tmp_path / 'payload.exe'
    threat_file.write_bytes(b'fake payload')
    safe_file = tmp_path / 'notes.txt'
    safe_file.write_text('safe', encoding='utf-8')

    summary = build_security_summary(str(tmp_path))

    assert summary['threat_count'] >= 1
    assert any(item['path'].endswith('payload.exe') and item['status'] == 'Threat Detected' for item in summary['threats'])
    assert summary['risk_score'] >= 0


def test_clean_scan_with_unknown_checks_stays_low_risk(tmp_path, monkeypatch):
    safe_file = tmp_path / 'notes.txt'
    safe_file.write_text('safe', encoding='utf-8')
    unknown = {'available': False, 'status': 'Unable to query'}

    monkeypatch.setattr(security_suite, '_windows_defender_status', lambda: unknown)
    monkeypatch.setattr(security_suite, '_windows_firewall_status', lambda: unknown)
    monkeypatch.setattr(security_suite, '_public_ip_check', lambda: unknown)

    summary = build_security_summary(str(tmp_path))

    assert summary['threat_count'] == 0
    assert summary['risk_level'] == 'Low'

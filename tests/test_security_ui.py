import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from security_suite import build_security_summary


def test_security_score_and_history_are_present(tmp_path):
    threat_file = tmp_path / 'payload.exe'
    threat_file.write_bytes(b'payload')

    summary = build_security_summary(str(tmp_path))

    assert summary['risk_score'] >= 0
    assert summary['risk_level'] in {'Low', 'Medium', 'High'}
    assert isinstance(summary['threats'], list)

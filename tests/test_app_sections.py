import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import get_app_sections


def test_app_sections_include_core_tabs():
    sections = get_app_sections()
    assert 'Dashboard' in sections
    assert 'Scan' in sections
    assert 'VPN' in sections
    assert 'Hardening' in sections
    assert 'Report' in sections

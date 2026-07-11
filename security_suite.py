import os
import platform
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

import requests

from scan_engine import scan_files


def _json_bool(value: Any) -> bool:
    return str(value).lower() == 'true' or value is True


def _windows_defender_status() -> Dict[str, Any]:
    if platform.system().lower() != 'windows':
        return {'available': False, 'status': 'Not available on this platform'}

    try:
        completed = subprocess.run(
            ['powershell', '-NoProfile', '-Command', 'Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled,AntivirusEnabled,AntispywareEnabled | ConvertTo-Json -Compress'],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if completed.returncode != 0:
            return {'available': False, 'status': 'Unable to query Defender status'}
        payload = completed.stdout.strip()
        if not payload:
            return {'available': False, 'status': 'No Defender data returned'}
        data = json.loads(payload)
        antivirus = _json_bool(data.get('AntivirusEnabled'))
        realtime = _json_bool(data.get('RealTimeProtectionEnabled'))
        antispyware = _json_bool(data.get('AntispywareEnabled'))
        if antivirus and realtime and antispyware:
            return {'available': True, 'secure': True, 'status': 'Enabled'}
        return {'available': True, 'secure': False, 'status': 'Needs attention'}
    except Exception:
        return {'available': False, 'status': 'Unable to query Defender status'}


def _windows_firewall_status() -> Dict[str, Any]:
    if platform.system().lower() != 'windows':
        return {'available': False, 'status': 'Not available on this platform'}

    try:
        completed = subprocess.run(
            ['netsh', 'advfirewall', 'show', 'allprofiles'],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if completed.returncode != 0:
            return {'available': False, 'status': 'Unable to query firewall status'}
        output = completed.stdout.strip().lower()
        profile_count = output.count('state')
        enabled_count = output.count('state                                 on')
        secure = profile_count > 0 and enabled_count >= profile_count
        return {
            'available': True,
            'secure': secure,
            'status': 'Enabled' if secure else 'Needs attention',
        }
    except Exception:
        return {'available': False, 'status': 'Unable to query firewall status'}


def _public_ip_check() -> Dict[str, Any]:
    try:
        response = requests.get('https://api.ipify.org', timeout=10)
        if response.ok:
            return {'available': True, 'ip': response.text.strip()}
        return {'available': False, 'status': 'Unable to determine public IP'}
    except Exception:
        return {'available': False, 'status': 'Network unavailable'}


def _normalize_scan_roots(scan_root: str | os.PathLike[str] | Iterable[str | os.PathLike[str]]) -> List[str]:
    if isinstance(scan_root, (str, os.PathLike)):
        return [str(scan_root)]
    return [str(root) for root in scan_root]


def build_security_summary(scan_root: str | os.PathLike[str] | Iterable[str | os.PathLike[str]]) -> Dict[str, Any]:
    scan_roots = _normalize_scan_roots(scan_root)
    results = []
    for root in scan_roots:
        results.extend(scan_files(root))
    threats = [
        {'path': path, 'status': status, 'hash': file_hash}
        for path, status, file_hash in results
        if status == 'Threat Detected'
    ]

    hardening_checks = []
    defender = _windows_defender_status()
    firewall = _windows_firewall_status()
    public_ip = _public_ip_check()

    hardening_checks.append({
        'name': 'Windows Defender',
        'status': defender.get('status', 'Unknown'),
        'available': defender.get('available', False),
    })
    hardening_checks.append({
        'name': 'Windows Firewall',
        'status': firewall.get('status', 'Unknown'),
        'available': firewall.get('available', False),
    })
    hardening_checks.append({
        'name': 'Public IP check',
        'status': public_ip.get('ip', public_ip.get('status', 'Unknown')),
        'available': public_ip.get('available', False),
    })

    protection_penalty = 0
    for check in (defender, firewall):
        if check.get('available') and not check.get('secure', False):
            protection_penalty += 15

    network_penalty = 0 if public_ip.get('available', False) else 5

    threat_penalty = len(threats) * 25
    if len(threats) >= 3:
        threat_penalty += 15
    if len(threats) >= 5:
        threat_penalty += 15

    risk_score = max(0, min(100, threat_penalty + protection_penalty + network_penalty))
    if risk_score < 35:
        risk_level = 'Low'
    elif risk_score < 75:
        risk_level = 'Medium'
    else:
        risk_level = 'High'

    return {
        'target': scan_roots[0] if len(scan_roots) == 1 else '; '.join(scan_roots),
        'targets': scan_roots,
        'threat_count': len(threats),
        'threats': threats,
        'hardening_checks': hardening_checks,
        'risk_score': risk_score,
        'risk_level': risk_level,
    }

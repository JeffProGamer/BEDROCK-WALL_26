import base64
import csv
import io
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from tkinter import messagebox
from urllib.parse import urlparse

import requests


VPN_GATE_API_URL = "https://www.vpngate.net/api/iphone/"
GITHUB_TEST_URL = "https://api.github.com/meta"
BLOCKED_OPENVPN_DIRECTIVES = {
    "auth-user-pass-verify",
    "client-connect",
    "client-disconnect",
    "down",
    "ipchange",
    "learn-address",
    "plugin",
    "route-up",
    "script-security",
    "tls-verify",
    "up",
}


@dataclass(frozen=True)
class VPNConnection:
    host_name: str
    ip: str
    score: int
    ping: int
    speed: int
    country_long: str
    country_short: str
    sessions: int
    uptime: int
    operator: str
    config_data_base64: str

    @property
    def has_network(self) -> bool:
        return bool(self.config_data_base64) and self.score > 0 and self.speed > 0

    @property
    def display_name(self) -> str:
        country = self.country_long or self.country_short or "Unknown"
        return f"{self.host_name} ({country}, ping {self.ping} ms)"


class VPNManager:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.fetched_profile = root_dir / 'vpn_fetched.ovpn'
        self.provider_api_url = os.getenv('VPN_GATE_API_URL', VPN_GATE_API_URL)
        self.provider_api_urls = [self.provider_api_url]
        fallback_url = 'http://www.vpngate.net/api/iphone/'
        if fallback_url not in self.provider_api_urls:
            self.provider_api_urls.append(fallback_url)
        self.last_provider_connection: VPNConnection | None = None
        self.last_github_status = "GitHub reachability has not been checked."
        self.ovpn_candidates = [
            root_dir / 'vpn.ovpn',
            root_dir / 'config.ovpn',
            root_dir / 'openvpn.ovpn',
            self.fetched_profile,
        ]

    def find_openvpn_executable(self) -> str | None:
        candidates = [
            r'C:\Program Files\OpenVPN\bin\openvpn.exe',
            r'C:\Program Files\OpenVPN\bin\openvpn-gui.exe',
            os.getenv('OPENVPN_BIN'),
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        return None

    def find_profile(self) -> str | None:
        for profile in self.ovpn_candidates:
            if profile.exists():
                return str(profile)
        return None

    def parse_provider_connections(self, payload: str) -> list[VPNConnection]:
        lines = [line.strip() for line in payload.splitlines() if line.strip()]
        header_index = next((index for index, line in enumerate(lines) if line.startswith('#HostName,')), None)
        if header_index is None:
            return []

        header = lines[header_index].lstrip('#')
        rows: list[str] = []
        for line in lines[header_index + 1:]:
            if line.startswith('*'):
                break
            rows.append(line)

        reader = csv.DictReader(io.StringIO('\n'.join([header, *rows])))
        connections: list[VPNConnection] = []
        for row in reader:
            connection = VPNConnection(
                host_name=row.get('HostName', '').strip(),
                ip=row.get('IP', '').strip(),
                score=self._to_int(row.get('Score')),
                ping=self._to_int(row.get('Ping')),
                speed=self._to_int(row.get('Speed')),
                country_long=row.get('CountryLong', '').strip(),
                country_short=row.get('CountryShort', '').strip(),
                sessions=self._to_int(row.get('NumVpnSessions')),
                uptime=self._to_int(row.get('Uptime')),
                operator=row.get('Operator', '').strip(),
                config_data_base64=row.get('OpenVPN_ConfigData_Base64', '').strip(),
            )
            if connection.host_name and connection.ip:
                connections.append(connection)
        return connections

    def fetch_provider_connections(self) -> list[VPNConnection]:
        headers = {
            'Accept': 'text/plain,*/*',
            'User-Agent': 'BEDROCK-WALL/1.0 OpenVPN profile fetcher',
        }
        last_error: Exception | None = None
        for url in self.provider_api_urls:
            try:
                response = requests.get(url, headers=headers, timeout=15)
                response.raise_for_status()
                connections = self.parse_provider_connections(response.text)
                if connections:
                    return connections
                last_error = ValueError('The provider response did not include VPN connections.')
            except (requests.RequestException, ValueError) as exc:
                last_error = exc

        if last_error:
            raise last_error
        return []

    def select_best_connection(
        self,
        connections: list[VPNConnection],
        preferred_country: str | None = None,
    ) -> VPNConnection | None:
        preferred = (preferred_country or '').strip().lower()
        available = [
            connection
            for connection in connections
            if connection.has_network and self.connection_profile_is_safe(connection)
        ]
        if not available:
            return None

        def quality_key(connection: VPNConnection) -> tuple[int, int, int, int, int]:
            country_match = 0
            if preferred:
                country_match = int(
                    preferred in connection.country_long.lower()
                    or preferred == connection.country_short.lower()
                )
            ping = connection.ping if connection.ping > 0 else 999999
            return (country_match, connection.score, connection.speed, -ping, connection.uptime)

        return max(available, key=quality_key)

    def fetch_profile_for_network_user(self, preferred_country: str | None = None) -> str | None:
        connections = self.fetch_provider_connections()
        connection = self.select_best_connection(connections, preferred_country=preferred_country)
        if not connection:
            return None

        profile = self.decode_openvpn_config(connection)
        self.fetched_profile.write_text(profile, encoding='utf-8')
        self.last_provider_connection = connection
        self.last_github_status = self.check_github_reachability()
        return str(self.fetched_profile)

    def decode_openvpn_config(self, connection: VPNConnection) -> str:
        encoded = connection.config_data_base64.strip()
        encoded += '=' * (-len(encoded) % 4)
        try:
            config = base64.b64decode(encoded, validate=True).decode('utf-8')
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError('The fetched VPN connection did not include a valid OpenVPN profile.') from exc

        self.validate_openvpn_config(config, connection)
        return self.build_custom_connector_profile(config)

    def connection_profile_is_safe(self, connection: VPNConnection) -> bool:
        try:
            self.decode_openvpn_config(connection)
        except ValueError:
            return False
        return True

    def validate_openvpn_config(self, config: str, connection: VPNConnection) -> None:
        directives = self._profile_directives(config)
        directive_names = {name for name, _value in directives}
        if "client" not in directive_names or "remote" not in directive_names:
            raise ValueError('The fetched VPN connection did not include a usable OpenVPN client profile.')

        remote_values = [value for name, value in directives if name == "remote"]
        expected_hosts = {connection.host_name.lower(), connection.ip.lower()}
        if not any(value.split()[0].lower() in expected_hosts for value in remote_values if value.split()):
            raise ValueError('The fetched VPN profile remote does not match the selected provider connection.')

        blocked = sorted(directive_names.intersection(BLOCKED_OPENVPN_DIRECTIVES))
        if blocked:
            names = ', '.join(blocked)
            raise ValueError(f'The fetched VPN profile includes unsafe OpenVPN directive(s): {names}.')

        auth_files = [
            value for name, value in directives
            if name == "auth-user-pass" and value.strip()
        ]
        if auth_files:
            raise ValueError('The fetched VPN profile tries to read credentials from a local file.')

    def build_custom_connector_profile(self, config: str) -> str:
        lines = [line.rstrip() for line in config.replace('\r\n', '\n').replace('\r', '\n').split('\n')]
        additions = [
            "",
            "# BEDROCK WALL custom connector safety layer",
            "auth-nocache",
            'setenv BEDROCKWALL_CONNECTOR "github-ready"',
        ]
        existing = {line.strip().lower() for line in lines}
        for addition in additions:
            if addition and addition.lower() in existing:
                continue
            lines.append(addition)
        return "\n".join(lines).strip() + "\n"

    def check_github_reachability(self, url: str = GITHUB_TEST_URL) -> str:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc not in {"api.github.com", "github.com"}:
            raise ValueError("GitHub reachability checks must target github.com over HTTPS.")

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "BEDROCK-WALL/1.0 GitHub VPN connector",
        }
        try:
            response = requests.get(url, headers=headers, timeout=8)
            if response.status_code == 403:
                return "GitHub reachable, but rate limited."
            response.raise_for_status()
            return "GitHub reachable over HTTPS."
        except requests.RequestException as exc:
            return f"GitHub check failed: {exc}"

    @staticmethod
    def _profile_directives(config: str) -> list[tuple[str, str]]:
        directives: list[tuple[str, str]] = []
        in_inline_block = False
        for raw_line in config.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("<") and line.endswith(">"):
                in_inline_block = not line.startswith("</")
                continue
            if in_inline_block:
                continue
            name, _, value = line.partition(" ")
            directives.append((name.lower(), value.strip()))
        return directives

    @staticmethod
    def _to_int(value: str | None) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    def connect(self) -> bool:
        openvpn = self.find_openvpn_executable()
        profile = self.find_profile()
        if not openvpn:
            messagebox.showwarning('VPN', 'OpenVPN is not installed. Install OpenVPN and add a .ovpn profile to the app folder.')
            return False
        if not profile:
            try:
                profile = self.fetch_profile_for_network_user()
            except (requests.RequestException, ValueError, OSError) as exc:
                messagebox.showwarning(
                    'VPN',
                    f'No local .ovpn profile was found, and the app could not fetch a public VPN connection: {exc}',
                )
                return False
            if not profile:
                messagebox.showwarning(
                    'VPN',
                    'No usable public VPN connection was found. Place a file named vpn.ovpn, config.ovpn, or openvpn.ovpn in the app folder.',
                )
                return False

        try:
            subprocess.Popen([openvpn, '--config', profile], shell=False)
            if self.last_provider_connection and profile == str(self.fetched_profile):
                messagebox.showinfo(
                    'VPN',
                    f'VPN connection launched through {self.last_provider_connection.display_name}. If prompted, allow the OpenVPN client to connect.',
                )
            else:
                messagebox.showinfo('VPN', 'VPN connection launched. If prompted, allow the OpenVPN client to connect.')
            return True
        except OSError as exc:
            messagebox.showerror('VPN', f'Unable to start OpenVPN: {exc}')
            return False

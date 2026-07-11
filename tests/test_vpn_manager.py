import base64

from vpn_manager import VPNConnection, VPNManager


def encoded_profile(remote_host: str) -> str:
    profile = f"client\nremote {remote_host} 1194\n"
    return base64.b64encode(profile.encode("utf-8")).decode("ascii")


def connection(
    host_name: str,
    score: int,
    speed: int,
    ping: int = 40,
    config_data_base64: str | None = None,
) -> VPNConnection:
    return VPNConnection(
        host_name=host_name,
        ip="203.0.113.10",
        score=score,
        ping=ping,
        speed=speed,
        country_long="United States",
        country_short="US",
        sessions=4,
        uptime=120,
        operator="tester",
        config_data_base64=config_data_base64 if config_data_base64 is not None else encoded_profile(host_name),
    )


def test_parse_provider_connections_reads_vpngate_payload(tmp_path):
    manager = VPNManager(tmp_path)
    payload = "\n".join(
        [
            "*vpn_servers",
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64",
            f"relay-one,203.0.113.1,90,18,50000000,United States,US,12,300,10,20,2weeks,operator,message,{encoded_profile('relay-one')}",
            "*end",
        ]
    )

    connections = manager.parse_provider_connections(payload)

    assert len(connections) == 1
    assert connections[0].host_name == "relay-one"
    assert connections[0].has_network


def test_select_best_connection_uses_available_network(tmp_path):
    manager = VPNManager(tmp_path)
    offline = connection("offline", score=1000, speed=0)
    slower = connection("slower", score=200, speed=10_000_000, ping=50)
    faster = connection("faster", score=300, speed=80_000_000, ping=20)

    selected = manager.select_best_connection([offline, slower, faster])

    assert selected == faster


def test_fetch_profile_for_network_user_caches_selected_profile(tmp_path, monkeypatch):
    manager = VPNManager(tmp_path)
    selected = connection("relay-cache", score=500, speed=70_000_000)
    monkeypatch.setattr(manager, "fetch_provider_connections", lambda: [selected])
    monkeypatch.setattr(manager, "check_github_reachability", lambda: "GitHub reachable over HTTPS.")

    profile_path = manager.fetch_profile_for_network_user()

    assert profile_path == str(tmp_path / "vpn_fetched.ovpn")
    profile = (tmp_path / "vpn_fetched.ovpn").read_text(encoding="utf-8")
    assert "remote relay-cache 1194" in profile
    assert "auth-nocache" in profile
    assert 'setenv BEDROCKWALL_CONNECTOR "github-ready"' in profile
    assert manager.last_provider_connection == selected
    assert manager.last_github_status == "GitHub reachable over HTTPS."


def test_select_best_connection_rejects_unsafe_profile(tmp_path):
    manager = VPNManager(tmp_path)
    unsafe_profile = base64.b64encode(b"client\nremote unsafe 1194\nscript-security 2\nup bad.bat\n").decode("ascii")
    unsafe = connection("unsafe", score=1000, speed=90_000_000, config_data_base64=unsafe_profile)
    safe = connection("safe", score=10, speed=10_000_000)

    selected = manager.select_best_connection([unsafe, safe])

    assert selected == safe


def test_decode_openvpn_config_rejects_remote_mismatch(tmp_path):
    manager = VPNManager(tmp_path)
    mismatched = connection(
        "expected-host",
        score=100,
        speed=50_000_000,
        config_data_base64=encoded_profile("different-host"),
    )

    try:
        manager.decode_openvpn_config(mismatched)
    except ValueError as exc:
        assert "remote does not match" in str(exc)
    else:
        raise AssertionError("Expected mismatched remote profile to be rejected")


def test_github_reachability_only_accepts_github_https(tmp_path):
    manager = VPNManager(tmp_path)

    try:
        manager.check_github_reachability("http://example.com")
    except ValueError as exc:
        assert "github.com over HTTPS" in str(exc)
    else:
        raise AssertionError("Expected non-GitHub reachability target to be rejected")

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PAGES = ROOT / "pages"


def test_site_pages_use_shared_stylesheet_and_navigation():
    for name in ["index.html", "security.html", "vpn.html"]:
        html = (PAGES / name).read_text(encoding="utf-8")
        assert 'href="styles.css"' in html
        assert 'class="topbar"' in html
        assert "BEDROCK WALL" in html


def test_site_styles_use_bedrock_texture():
    css = (PAGES / "styles.css").read_text(encoding="utf-8")
    assert "../resources/bedrock_texture.png" in css


def test_vpn_page_keeps_fetch_controls():
    html = (PAGES / "vpn.html").read_text(encoding="utf-8")
    assert "Fetch Available Connections" in html
    assert "parseConnections" in html


def test_site_pages_offer_windows_app_download():
    installer_target = ROOT / "dist-msi" / "BedrockWallSetup.msi"
    download_target = ROOT / "dist-new" / "BedrockWallApp.exe"
    assert installer_target.exists()
    assert download_target.exists()

    for name in ["index.html", "security.html", "vpn.html"]:
        html = (PAGES / name).read_text(encoding="utf-8")
        assert 'href="../dist-msi/BedrockWallSetup.msi"' in html
        assert "download" in html


def test_site_runner_is_packaged_for_users():
    runner = (ROOT / "site_runner.py").read_text(encoding="utf-8")
    spec = (ROOT / "BedrockWallSite.spec").read_text(encoding="utf-8")

    assert "ThreadingHTTPServer" in runner
    assert "webbrowser.open" in runner
    assert "dist-msi" in runner
    assert "name='BedrockWallSite'" in spec
    assert "dist-new/BedrockWallApp.exe" in spec


def test_msi_installer_is_defined_without_source_files():
    installer = (ROOT / "installer" / "BedrockWallInstaller.wxs").read_text(encoding="utf-8")

    assert 'Name="BEDROCK WALL"' in installer
    assert "BedrockWallSite.exe" in installer
    assert "BedrockWallApp.exe" in installer
    assert ".py" not in installer

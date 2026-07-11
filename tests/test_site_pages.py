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
    download_target = ROOT / "dist-new" / "BedrockWallApp.exe"
    assert download_target.exists()

    for name in ["index.html", "security.html", "vpn.html"]:
        html = (PAGES / name).read_text(encoding="utf-8")
        assert 'href="../dist-new/BedrockWallApp.exe"' in html
        assert "download" in html


def test_site_runner_is_packaged_for_users():
    runner = (ROOT / "site_runner.py").read_text(encoding="utf-8")
    spec = (ROOT / "BedrockWallSite.spec").read_text(encoding="utf-8")

    assert "ThreadingHTTPServer" in runner
    assert "webbrowser.open" in runner
    assert "name='BedrockWallSite'" in spec
    assert "dist-new/BedrockWallApp.exe" in spec

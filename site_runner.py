import functools
import socket
import sys
import threading
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parent
SITE_ROOT = Path(getattr(sys, "_MEIPASS", SOURCE_DIR))
HOME_PAGE = "/pages/index.html"


class BedrockWallSiteHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return


def _find_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def run_site() -> str:
    port = _find_port()
    handler = functools.partial(BedrockWallSiteHandler, directory=str(SITE_ROOT))
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}{HOME_PAGE}"
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return url


if __name__ == "__main__":
    run_site()

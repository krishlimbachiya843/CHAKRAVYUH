"""
CHAKRAVYUH - HTTP Honeypot Listener
===================================

Emulates an HTTP web server (Apache/nginx) to attract and log
reconnaissance and exploitation attempts against web services.

Behavior:
    - Listens on a configurable TCP port.
    - Serves a benign default page to avoid tipping off attackers.
    - Logs the request line, headers, User-Agent, and raw request.
"""

import socket
import threading
from core.logger import log_attack


class HTTPListener(threading.Thread):
    """
    Fake HTTP server that captures and logs incoming requests.

    Runs in its own thread. Each client connection is handled in a
    separate worker thread to support concurrent attackers.
    """

    def __init__(self, port: int, banner: str, custom_html: str = None):
        super().__init__(daemon=True)
        self.port = port
        self.banner = banner
        self.custom_html = custom_html or self._default_response()
        self.running = False
        self.sock = None

    def _default_response(self) -> str:
        """Build a default HTTP response with the configured banner."""
        body = "<html><body><h1>It works!</h1></body></html>"
        return (
            f"HTTP/1.1 200 OK\r\n"
            f"Server: {self.banner}\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
            f"{body}"
        )

    def run(self) -> None:
        """Start the listener loop."""
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", self.port))
        self.sock.listen(50)
        self.sock.settimeout(1.0)

        print(f"[HTTP] Listening on port {self.port} | Banner: {self.banner}")

        while self.running:
            try:
                client, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_client,
                args=(client, addr),
                daemon=True
            ).start()

    def _handle_client(self, client: socket.socket, addr: tuple) -> None:
        """Parse and log a single HTTP request."""
        try:
            client.settimeout(5)
            request = client.recv(8192).decode(errors="ignore")
            if not request:
                return

            # Extract User-Agent header for pattern recognition
            user_agent = ""
            for line in request.split("\r\n"):
                if line.lower().startswith("user-agent:"):
                    user_agent = line.split(":", 1)[1].strip()
                    break

            log_attack(
                src_ip=addr[0],
                src_port=addr[1],
                protocol="HTTP",
                port=self.port,
                event_type="request",
                user_agent=user_agent,
                raw_data=request[:2000]
            )

            client.sendall(self.custom_html.encode())
        except Exception as exc:
            print(f"[HTTP] Handler error: {exc}")
        finally:
            client.close()

    def stop(self) -> None:
        """Stop the listener and release the socket."""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
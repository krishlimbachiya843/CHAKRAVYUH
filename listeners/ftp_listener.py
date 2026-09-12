"""
CHAKRAVYUH - FTP Honeypot Listener
==================================

Emulates a vsFTPd/ProFTPD file server to capture credential
harvesting and brute-force attempts against FTP services.

Behavior:
    - Sends a realistic FTP banner on connect.
    - Handles USER, PASS, and QUIT commands.
    - Logs every credential attempt with username and password.
"""

import socket
import threading
from core.logger import log_attack


class FTPListener(threading.Thread):
    """
    Fake FTP server that captures login attempts.

    Each connection is handled in a separate thread. All credential
    attempts are logged to the central database.
    """

    def __init__(self, port: int, banner: str):
        super().__init__(daemon=True)
        self.port = port
        self.banner = banner
        self.running = False
        self.sock = None

    def run(self) -> None:
        """Start the listener loop."""
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", self.port))
        self.sock.listen(50)
        self.sock.settimeout(1.0)

        print(f"[FTP]  Listening on port {self.port} | Banner: {self.banner}")

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
        """Handle an FTP session and capture credentials."""
        try:
            client.settimeout(30)
            client.sendall(f"220 ({self.banner})\r\n".encode())

            username = ""
            password = ""

            while True:
                data = client.recv(4096).decode(errors="ignore").strip()
                if not data:
                    break

                command, _, argument = data.partition(" ")
                command = command.upper()

                if command == "USER":
                    username = argument
                    client.sendall(
                        b"331 Please specify the password.\r\n"
                    )
                elif command == "PASS":
                    password = argument
                    log_attack(
                        src_ip=addr[0],
                        src_port=addr[1],
                        protocol="FTP",
                        port=self.port,
                        event_type="login_attempt",
                        username=username,
                        password=password,
                        raw_data=data
                    )
                    client.sendall(b"530 Login incorrect.\r\n")
                elif command == "QUIT":
                    client.sendall(b"221 Goodbye.\r\n")
                    break
                else:
                    client.sendall(b"500 Unknown command.\r\n")
        except Exception:
            pass
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
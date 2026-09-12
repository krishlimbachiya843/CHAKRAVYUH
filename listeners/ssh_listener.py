"""
CHAKRAVYUH - SSH Honeypot Listener
==================================

Emulates an OpenSSH server using the Paramiko library to capture
SSH credential attempts and handshake metadata.

Design Notes:
    - The host key is generated once and persisted to disk so the
      server presents a consistent fingerprint across restarts.
    - All authentication attempts are logged with username/password.
"""

import os
import socket
import threading
import paramiko
from core.logger import log_attack

# Path to persisted RSA host key. Generated on first run, then reused
# so that SSH clients do not raise "host key changed" warnings.
KEY_PATH = "logs/ssh_host_key"


def _load_or_create_host_key() -> paramiko.RSAKey:
    """Load the RSA host key from disk, generating it if absent."""
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    if os.path.exists(KEY_PATH):
        return paramiko.RSAKey(filename=KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(KEY_PATH)
    return key


HOST_KEY = _load_or_create_host_key()


class _SSHSession(paramiko.ServerInterface):
    """
    Paramiko server interface that captures authentication attempts.
    """

    def __init__(self, addr: tuple, port: int):
        self.addr = addr
        self.port = port
        self.event = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        """Log every password authentication attempt and reject it."""
        log_attack(
            src_ip=self.addr[0],
            src_port=self.addr[1],
            protocol="SSH",
            port=self.port,
            event_type="login_attempt",
            username=username,
            password=password
        )
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.OPEN_SUCCEEDED


class SSHListener(threading.Thread):
    """
    Fake SSH server that captures authentication attempts.
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

        print(f"[SSH]  Listening on port {self.port} | Banner: {self.banner}")

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
        """Handle a single SSH session."""
        transport = None
        try:
            transport = paramiko.Transport(client)
            transport.local_version = f"SSH-2.0-{self.banner}"
            transport.add_server_key(HOST_KEY)

            server = _SSHSession(addr, self.port)
            transport.start_server(server=server)

            log_attack(
                src_ip=addr[0],
                src_port=addr[1],
                protocol="SSH",
                port=self.port,
                event_type="connect",
                raw_data=f"banner={self.banner}"
            )

            server.event.wait(10)
        except Exception:
            pass
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass

    def stop(self) -> None:
        """Stop the listener and release the socket."""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
"""
CHAKRAVYUH - Service Manager
============================

Central lifecycle manager for all honeypot listeners. Provides a
simple API to start, stop, and query the state of each service.

Design Notes:
    - Services are keyed by protocol name ("http", "ftp", "ssh").
    - Only one instance of each service can run at a time.
    - All operations are thread-safe at the listener level.
"""

from listeners.http_listener import HTTPListener
from listeners.ftp_listener import FTPListener
from listeners.ssh_listener import SSHListener


class ServiceManager:
    """
    Manages the lifecycle of honeypot listeners.
    """

    LISTENER_MAP = {
        "http": HTTPListener,
        "ftp":  FTPListener,
        "ssh":  SSHListener,
    }

    def __init__(self):
        self.services = {}

    def start(self, name: str, port: int, banner: str, **kwargs):
        """
        Start a honeypot service.

        Parameters
        ----------
        name : str
            Service identifier ('http', 'ftp', 'ssh').
        port : int
            TCP port to listen on.
        banner : str
            Server banner to present to attackers.

        Returns
        -------
        tuple
            (success: bool, message: str)
        """
        if name in self.services and self.services[name].running:
            return False, f"{name.upper()} is already running"

        listener_class = self.LISTENER_MAP.get(name)
        if not listener_class:
            return False, f"Unknown service: {name}"

        # HTTP listener supports custom HTML content
        if name == "http":
            service = listener_class(
                port, banner, custom_html=kwargs.get("custom_html")
            )
        else:
            service = listener_class(port, banner)

        service.start()
        self.services[name] = service
        return True, f"{name.upper()} started on port {port}"

    def stop(self, name: str):
        """
        Stop a running honeypot service.

        Parameters
        ----------
        name : str
            Service identifier ('http', 'ftp', 'ssh').

        Returns
        -------
        tuple
            (success: bool, message: str)
        """
        service = self.services.get(name)
        if not service:
            return False, f"{name.upper()} is not running"

        service.stop()
        del self.services[name]
        return True, f"{name.upper()} stopped"

    def status(self) -> dict:
        """
        Return the running state of all services.

        Returns
        -------
        dict
            Mapping of service name to boolean running state.
        """
        return {
            name: getattr(service, "running", False)
            for name, service in self.services.items()
        }


# Global singleton instance
manager = ServiceManager()
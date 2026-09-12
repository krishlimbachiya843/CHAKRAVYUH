"""
CHAKRAVYUH - Listeners Package
==============================

Contains all honeypot service listeners. Each listener emulates a specific
network service (HTTP, FTP, SSH) and captures attacker activity.

Listeners:
    - HTTPListener: Emulates an Apache/nginx web server
    - FTPListener: Emulates a vsFTPd/ProFTPD file server
    - SSHListener: Emulates an OpenSSH server using Paramiko
"""

__version__ = "2.0.0"
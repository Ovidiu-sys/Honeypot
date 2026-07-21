"""
SSH emulator using Paramiko in server mode.
Accepts any credentials (to capture everything the attackers try),
opens a fake shell, and logs all events through core/logger.py.

How Paramiko server mode works:
  - Paramiko implements the SSH protocol at the library level.
  - Normally, it is used as a CLIENT (to connect to an SSH server).
  - In server mode, YOU are the server—you receive connections from others.
  - You must implement an interface (ServerInterface) that decides which
    credentials to accept, what channels to open, etc.

"""

import socket
import threading
import paramiko
from pathlib import Path

from .fake_shell import handle_command, get_prompt

HOST_KEY_PATH = Path(__file__).resolve().parent.parent / "data" / "host_key"


def _get_or_create_host_key() -> paramiko.RSAKey:
    """
    Server's RSA key ( SSH ), the equivalent of /etc/ssh/ssh_host_rsa_key
    We generate it once and save it, so that it doesn't change every restart (host key changed)

    """
    if HOST_KEY_PATH.exists():
        return paramiko.RSAKey(filename=str(HOST_KEY_PATH))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(HOST_KEY_PATH))
    return key

class _HoneypotSSHInterface(paramiko.ServerInterface):
    # paramiko interface for the SSH server 
    # overwrites the methods that decides what is allowed and what is not
    def __init__(self,logger,geo,client_ip,client_port):
        self.logger = logger
        self.geo = geo
        self.client_ip = client_ip
        self.client_port = client_port
        self.attempt_id = None
        self.country = None
        self.city = None
        self.event = threading.Event()

    def check_channel_request(self,kind,chanid):
        # reject the authentication with the public key (only passwords)
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self,username,password):
        self.country, self.city = self.geo.lookup(self.client_ip)
        self.attempt_id = self.logger.log_ssh_attempt(
            ip = self.client_ip,
            port = self.client_port,
            username = username,
            password = password,
            country = self.country,
            city = self.city
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self,username,key):
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self,username):
        return "password"

    def check_channel_shell_request(self,channel):
        self.event.set()
        return True

    def check_channel_pty_request(self,channel,term,width,height,pixelwidth,pixelheight,modes):
        return True


def _handle_client(client_socket, client_addr, host_key, logger, geo):
    # Gestionate a single SSH connection in a separated thread
    client_ip, client_port = client_addr

    transport = None

    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)

        server_interface = _HoneypotSSHInterface(logger,geo, client_ip, client_port)
        try:
            transport.start_server(server=server_interface)
        except paramiko.SSHException:
            return
        
        # 30 seconds for the attacker to authenticate 
        channel = transport.accept(30)
        if channel is None:
            return 
        
        # shell request
        server_interface.event.wait(10)
        if not server_interface.event.is_set():
            return 
        
        # send the initial prompt
        channel.send(get_prompt().encode())

        #main loop for the fake shell
        buffer = ""
        while transport.is_active():
            try:
                channel.settimeout(60.0)# 60 seconds inactivity = disconnected

                data = channel.recv(1024)
                if not data:
                    break

                for char in data.encode("utf-8", errors="ignore"):
                    if char in ("\r","\n"):
                        channel.send(b"\r\n")
                        command = buffer.strip()
                        buffer = ""

                        if not command:
                            channel.send(get_prompt().encode())
                            continue

                        response = handle_command(command)
                        
                        # log the command
                        if server_interface.attempt_id is not None:
                            logger.log_ssh_command(
                                attempt_id = server_interface.attempt_id,
                                ip = client_ip,
                                command = command,
                                country = server_interface.country
                            )
                            
                            if response == "__EXIT__":
                                channel.send(b"logout\r\n")
                                break

                            if response:
                                channel.send((response + "\r\n").encode())

                            channel.send(get_prompt().encode())

                        elif char == "\x7f": #backspace
                            if buffer:
                                buffer = buffer[:-1]
                                channel.send(b"\x08 \x08")

                        elif char == "\x03": # CTRL + C
                            buffer = ""
                            channel.send(b"^C\r\n")
                            channel.send(get_prompt().encode())

                        else:
                            buffer+=char
                            channel.send(char.encode())
                            
            except socket.timeout:
                break
            except Exception:
                break
    except Exception:
        pass
    finally:
        if transport:
            transport.close()
        client_socket.close()


class SSHHoneypot:
    def __init__(self,logger, geo,host:str = "0.0.0.0", port:int = 22):
        self.logger = logger
        self.geo = geo
        self.host = host
        self.port = port
        self.host_key = _get_or_create_host_key()
        self._server_socket = None

    def start(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        self._server_socket.bind((self.host,self.port))
        self._server_socket.listen(100)
        print(f"[SSH] The honeypot listens pe {self.host}:{self.port}")

        while True:
            try:
                client_socket, client_addr = self._server_socket.accept()
                thread = threading.Thread(
                    target = _handle_client,
                    args = (client_socket, client_addr, self.host_key,self.logger, self.geo),
                    daemon=True
                )
                thread.start()
            except OSError:
                break

    def stop(self):
        if self._server_socket:
            self._server_socket.close()

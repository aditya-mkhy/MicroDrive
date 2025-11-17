import socket
import ssl
import json
import struct
import os

class Network:
    def __init__(self, host: str, port: int, cert_dir: str= None, as_server: bool = None):

        """
        Initialize the Networking class.

        This class provides a unified interface for TCP communication. It can work
        as either a server or a client depending on the 'as_server' argument.

        - If as_server=True:
            The instance behaves as a server. It binds to the given host and port,
            listens for incoming clients, accepts them automatically, and manages
            client connections and disconnections internally.

        - If as_server=False:
            The instance behaves as a client. It connects to the given host and port
            and maintains the connection, handling reconnection or disconnection
            events smoothly.

        Regardless of mode, the class exposes simple send() and recv() methods that
        work identically for both server and client roles. All socket setup,
        connection handling, and data transfer management is abstracted away, so the
        user only needs to focus on exchanging data.

        Parameters:
            host (str): Host address to bind or connect to.
            port (int): Port number to bind or connect to.
            cert_dir (str) : certs path for ssl
            as_server (bool): Whether the instance should operate in server mode.

        """

        base_dir = os.path.dirname(os.path.abspath(__file__))
        if cert_dir is None:
            cert_dir = os.path.join(base_dir, "certs")

        self.host = host
        self.port = port
        self.cert_dir = cert_dir

        # this will be developed later
        self.as_server = as_server

        if as_server:
            self.certfile = os.path.join(cert_dir, "server_cert.pem")
            self.keyfile  = os.path.join(cert_dir, "server_key.pem")
            self.cafile   = os.path.join(cert_dir, "ca_cert.pem")

        else:
            self.ca_cert     = os.path.join(cert_dir, "ca_cert.pem")
            self.client_cert = os.path.join(cert_dir, "pc_client_cert.pem")
            self.client_key  = os.path.join(cert_dir, "pc_client_key.pem")


    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        TLS server context:
        - Uses server certificate + key
        - Requires client certificate signed by our CA
        """
        if self.as_server:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = False
            ctx.load_verify_locations(cafile=self.cafile)
            # Optional hardening:
            # ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            return ctx

        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.ca_cert)
        # use our own CA, so hostname checking doesn't matter.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)

        return ctx
    
    
    def connect(self, timeout: int = None):
        pass
        

if __name__ == "__main__":
    network = Network()
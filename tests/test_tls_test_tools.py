"""
Unit tests for the test helpers! These also serve as an example of how to use
the helpers in actual unit tests.
"""

# Standard
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from typing import Optional
import os
import random
import socket
import ssl
import tempfile
import threading

# Third Party
from flask import Flask
from werkzeug.serving import make_server
import alog
import grpc
import pytest
import requests

# Local
from . import greeter_pb2, greeter_pb2_grpc
import tls_test_tools

## Helpers #####################################################################

log = alog.use_channel("TEST")
alog.configure(
    default_level=os.getenv("LOG_LEVEL", "info"),
    filters=os.getenv("LOG_FILTERS", ""),
)


@pytest.fixture
def open_port() -> int:
    yield tls_test_tools.open_port()


class Greeter(greeter_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        return greeter_pb2.HelloReply(message=f"Hello {request.name}")


@contextmanager
def run_grpc_server(
    port: int,
    tls_key: Optional[str] = None,
    tls_cert: Optional[str] = None,
    mtls_client_ca: Optional[str] = None,
) -> str:
    # Create the server and add the servicer
    server = grpc.server(ThreadPoolExecutor(max_workers=1))
    greeter_pb2_grpc.add_GreeterServicer_to_server(Greeter(), server)

    # Add the port based on TLS setup
    hostname = f"[::]:{port}"
    if tls_key and tls_cert:
        log.debug2("Running with TLS")
        creds_kwargs = {}
        if mtls_client_ca:
            log.debug2("Running with mTLS")
            creds_kwargs["root_certificates"] = mtls_client_ca
            creds_kwargs["require_client_auth"] = True
        server_credentials = grpc.ssl_server_credentials(
            [(tls_key.encode("utf-8"), tls_cert.encode("utf-8"))],
            **creds_kwargs,
        )
        server.add_secure_port(hostname, server_credentials)
    else:
        server.add_insecure_port(hostname)

    # Start running and yield the client hostname
    server.start()
    try:
        yield f"localhost:{port}"
    finally:
        # Shut down the server
        server.stop(0)


class FlaskServerThread(threading.Thread):
    """Helper to run a server in a thread so it can be shut down easily"""

    def __init__(
        self,
        app: Flask,
        port: int,
        tls_key: Optional[str] = None,
        tls_cert: Optional[str] = None,
        mtls_client_ca: Optional[str] = None,
    ):
        super().__init__()
        server_kwargs = {}
        if tls_key and tls_cert:
            log.debug2("Running with TLS")
            with tempfile.TemporaryDirectory() as workdir:
                certfile = os.path.join(workdir, "cert.pem")
                keyfile = os.path.join(workdir, "key.pem")
                with open(certfile, "w") as handle:
                    handle.write(tls_cert)
                with open(keyfile, "w") as handle:
                    handle.write(tls_key)
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx.load_cert_chain(certfile, keyfile)
                if mtls_client_ca:
                    log.debug2("Running with mTLS")
                    cafile = os.path.join(workdir, "ca.pem")
                    with open(cafile, "w") as handle:
                        handle.write(mtls_client_ca)
                    ssl_ctx.load_verify_locations(cafile)
                    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
            server_kwargs = {"ssl_context": ssl_ctx}
        self.server = make_server("127.0.0.1", port, app, **server_kwargs)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


@contextmanager
def run_http_server(
    port: int,
    tls_key: Optional[str] = None,
    tls_cert: Optional[str] = None,
    mtls_client_ca: Optional[str] = None,
):
    app = Flask("foobar")

    @app.route("/")
    def hello():
        return "Hello world!"

    server = FlaskServerThread(app, port, tls_key, tls_cert, mtls_client_ca)
    server.start()
    protocol = "https" if (tls_key and tls_cert) else "http"
    try:
        yield f"{protocol}://localhost:{port}"
    finally:
        server.shutdown()


## Tests #######################################################################


def test_run_grpc_tls(open_port):
    """Test that a grpc server can boot with tls and a client call works"""
    ca_key = tls_test_tools.generate_key()[0]
    ca_cert = tls_test_tools.generate_ca_cert(ca_key)
    tls_key, tls_cert = tls_test_tools.generate_derived_key_cert_pair(ca_key)
    with run_grpc_server(open_port, tls_key, tls_cert) as hname:
        creds = grpc.ssl_channel_credentials(ca_cert.encode("utf-8"))
        channel = grpc.secure_channel(hname, creds)
        client = greeter_pb2_grpc.GreeterStub(channel)
        resp = client.SayHello(greeter_pb2.HelloRequest(name="Gabe"))
        assert resp
        assert "Gabe" in resp.message


def test_run_grpc_mtls(open_port):
    """Test that a grpc server can boot with mtls and a client call works"""
    ca_key = tls_test_tools.generate_key()[0]
    ca_cert = tls_test_tools.generate_ca_cert(ca_key)
    tls_key, tls_cert = tls_test_tools.generate_derived_key_cert_pair(ca_key)
    with run_grpc_server(open_port, tls_key, tls_cert, ca_cert) as hname:
        client_key, client_cert = tls_test_tools.generate_derived_key_cert_pair(ca_key)
        creds = grpc.ssl_channel_credentials(
            ca_cert.encode("utf-8"),
            client_key.encode("utf-8"),
            client_cert.encode("utf-8"),
        )
        channel = grpc.secure_channel(hname, creds)
        client = greeter_pb2_grpc.GreeterStub(channel)
        resp = client.SayHello(greeter_pb2.HelloRequest(name="Gabe"))
        assert resp
        assert "Gabe" in resp.message


def test_run_http_tls(open_port):
    """Test that an http server can boot with tls and a client call works"""
    ca_key = tls_test_tools.generate_key()[0]
    ca_cert = tls_test_tools.generate_ca_cert(ca_key)
    tls_key, tls_cert = tls_test_tools.generate_derived_key_cert_pair(ca_key)
    with run_http_server(open_port, tls_key, tls_cert) as hname:
        with tempfile.NamedTemporaryFile("w") as ca_handle:
            ca_handle.write(ca_cert)
            ca_handle.flush()
            resp = requests.get(hname, verify=ca_handle.name)
            resp.raise_for_status()


def test_run_http_mtls(open_port):
    """Test that a http server can boot with mtls and a client call works"""
    ca_key = tls_test_tools.generate_key()[0]
    ca_cert = tls_test_tools.generate_ca_cert(ca_key)
    tls_key, tls_cert = tls_test_tools.generate_derived_key_cert_pair(ca_key)
    with run_http_server(open_port, tls_key, tls_cert, ca_cert) as hname:
        client_key, client_cert = tls_test_tools.generate_derived_key_cert_pair(ca_key)
        with tempfile.TemporaryDirectory() as workdir:
            ca_file = os.path.join(workdir, "ca.pem")
            client_key_file = os.path.join(workdir, "client.key.pem")
            client_cert_file = os.path.join(workdir, "client.cert.pem")
            with open(ca_file, "w") as handle:
                handle.write(ca_cert)
            with open(client_key_file, "w") as handle:
                handle.write(client_key)
            with open(client_cert_file, "w") as handle:
                handle.write(client_cert)
            resp = requests.get(
                hname, verify=ca_file, cert=(client_cert_file, client_key_file)
            )
            resp.raise_for_status()


def test_random_port_collision():
    """Make sure that open_port correctly gives an actual open port when the
    first one it tries is occupied
    """
    random.seed(42)
    first_port = tls_test_tools.open_port()
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", first_port))
        sock.listen(0)
        random.seed(42)
        second_port = tls_test_tools.open_port()
    assert first_port != second_port

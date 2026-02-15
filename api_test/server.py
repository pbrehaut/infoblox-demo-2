"""Simple Flask server with client certificate authentication."""

import logging
import ssl
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)


def generate_server_certificate(
        cert_path: Path,
        key_path: Path,
        days: int = 365
) -> None:
    """Generate a self-signed server certificate.

    Args:
        cert_path: Path where the certificate will be saved.
        key_path: Path where the private key will be saved.
        days: Number of days the certificate is valid for.
    """
    logger.info("Generating self-signed server certificate...")

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Build certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost")
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=days))
        .sign(private_key, hashes.SHA256())
    )

    # Write private key
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    logger.info(f"Server certificate generated: {cert_path}")
    logger.info(f"Server key generated: {key_path}")


def setup_ssl_context(
        server_cert: Path,
        server_key: Path,
        ca_cert: Path
) -> ssl.SSLContext:
    """Create SSL context configured for client certificate authentication.

    Args:
        server_cert: Path to server certificate.
        server_key: Path to server private key.
        ca_cert: Path to CA certificate for verifying clients.

    Returns:
        Configured SSL context.
    """
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=str(server_cert), keyfile=str(server_key))
    context.load_verify_locations(cafile=str(ca_cert))
    context.verify_mode = ssl.CERT_REQUIRED

    return context


@app.route("/")
def index() -> str:
    """Handle root route."""
    return "<h1>Authentication successful!</h1>"


def main() -> None:
    """Run the Flask server with client certificate authentication."""
    script_dir = Path(__file__).parent

    server_cert = script_dir / "server.cert.pem"
    server_key = script_dir / "server.key.pem"
    ca_cert = script_dir / "ca.cert.pem"

    # Check if CA certificate exists
    if not ca_cert.exists():
        logger.error(f"CA certificate not found: {ca_cert}")
        logger.error("Please ensure ca.cert.pem is in the same directory as this script")
        return

    # Generate server certificate if it doesn't exist
    if not server_cert.exists() or not server_key.exists():
        generate_server_certificate(server_cert, server_key)

    # Setup SSL context
    ssl_context = setup_ssl_context(server_cert, server_key, ca_cert)

    # Run server
    port = 8443
    logger.info(f"Starting server on https://localhost:{port}")
    logger.info("Client certificate authentication is REQUIRED")

    app.run(host="localhost", port=port, ssl_context=ssl_context)


if __name__ == "__main__":
    main()
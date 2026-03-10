"""
Standalone test for Infoblox certificate authentication.

Tests the connection using client cert + basic auth with verbose logging
to diagnose certificate presentation issues.
"""

import logging
import ssl
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

requests.packages.urllib3.disable_warnings()

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)
logging.getLogger("urllib3").setLevel(logging.DEBUG)

# =============================================================================
# CONFIGURATION
# =============================================================================

INFOBLOX_HOST = "10.10.10.213"
WAPI_VERSION = "v2.13.7"
BASE_URL = f"https://{INFOBLOX_HOST}/wapi/{WAPI_VERSION}"

CLIENT_USER = "api-user"
ADMIN_PASS = "changeme"

CLIENT_CERT_FILE = Path("api-user.crt")
CLIENT_KEY_FILE = Path("api-user.key")
CA_CERT_FILE = Path("support-ca.crt")

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

logger.info("=== Pre-flight checks ===")
logger.info("Working directory: %s", Path.cwd())
logger.info("Client cert path: %s", CLIENT_CERT_FILE.resolve())
logger.info("Client key path:  %s", CLIENT_KEY_FILE.resolve())
logger.info("Client cert exists: %s", CLIENT_CERT_FILE.resolve().exists())
logger.info("Client key exists:  %s", CLIENT_KEY_FILE.resolve().exists())

if not CLIENT_CERT_FILE.exists():
    logger.error("Client cert file not found — cannot continue")
    exit(1)
if not CLIENT_KEY_FILE.exists():
    logger.error("Client key file not found — cannot continue")
    exit(1)

# Verify the cert/key pair loads with Python's ssl module
logger.info("Verifying cert/key pair with ssl.SSLContext...")
try:
    ctx = ssl.create_default_context()
    ctx.load_cert_chain(str(CLIENT_CERT_FILE.resolve()), str(CLIENT_KEY_FILE.resolve()))
    logger.info("ssl.load_cert_chain succeeded — cert and key are a valid pair")
except ssl.SSLError as e:
    logger.error("ssl.load_cert_chain FAILED: %s", e)
    exit(1)

# =============================================================================
# CERTIFICATE INSPECTION
# =============================================================================

logger.info("")
logger.info("=== Certificate inspection ===")

# --- Client certificate ---
with open(CLIENT_CERT_FILE, "rb") as f:
    client_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

serial_hex = format(client_cert.serial_number, "x").upper()
logger.info("Client cert serial number : %d  (0x%s)", client_cert.serial_number, serial_hex)
logger.info("Client cert subject       : %s", client_cert.subject.rfc4514_string())
logger.info("Client cert issuer        : %s", client_cert.issuer.rfc4514_string())
logger.info(
    "Client cert validity      : %s  →  %s",
    client_cert.not_valid_before_utc,
    client_cert.not_valid_after_utc,
)

# --- CA / issuing certificate ---
if CA_CERT_FILE.exists():
    with open(CA_CERT_FILE, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    ca_serial_hex = format(ca_cert.serial_number, "x").upper()
    logger.info("")
    logger.info("CA cert serial number     : %d  (0x%s)", ca_cert.serial_number, ca_serial_hex)
    logger.info("CA cert subject           : %s", ca_cert.subject.rfc4514_string())
    logger.info("CA cert issuer            : %s", ca_cert.issuer.rfc4514_string())

    # --- Step 1: DN equality check ---
    logger.info("")
    if client_cert.issuer == ca_cert.subject:
        logger.info("ISSUER DN MATCH ✓  — client cert issuer DN matches CA cert subject DN")
    else:
        logger.warning("ISSUER DN MISMATCH ✗ — client cert issuer DN does NOT match CA cert subject DN")
        logger.warning("  Client issuer : %s", client_cert.issuer.rfc4514_string())
        logger.warning("  CA subject    : %s", ca_cert.subject.rfc4514_string())

    # --- Step 2: Cryptographic signature verification ---
    # Confirm the CA actually signed the client cert (not just a DN match).
    logger.info("")
    logger.info("Verifying client cert signature against CA public key...")
    try:
        # cryptography >= 40.x exposes verify_directly_issued_by()
        ca_cert.verify_directly_issued_by(ca_cert)          # self-check: CA is self-signed
        client_cert.verify_directly_issued_by(ca_cert)      # actual check
        logger.info("CRYPTO SIGNATURE VALID ✓  — CA public key successfully verified client cert signature")
    except AttributeError:
        # Fallback for cryptography < 40: verify manually via the public key
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
        from cryptography.exceptions import InvalidSignature
        ca_pub = ca_cert.public_key()
        try:
            if isinstance(ca_pub, RSAPublicKey):
                ca_pub.verify(
                    client_cert.signature,
                    client_cert.tbs_certificate_bytes,
                    asym_padding.PKCS1v15(),
                    client_cert.signature_hash_algorithm,
                )
            elif isinstance(ca_pub, EllipticCurvePublicKey):
                from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
                ca_pub.verify(
                    client_cert.signature,
                    client_cert.tbs_certificate_bytes,
                    ECDSA(client_cert.signature_hash_algorithm),
                )
            else:
                ca_pub.verify(
                    client_cert.signature,
                    client_cert.tbs_certificate_bytes,
                    client_cert.signature_hash_algorithm,
                )
            logger.info("CRYPTO SIGNATURE VALID ✓  — CA public key successfully verified client cert signature")
        except InvalidSignature:
            logger.error("CRYPTO SIGNATURE INVALID ✗ — client cert was NOT signed by the CA private key")
        except Exception as verify_err:
            logger.error("CRYPTO SIGNATURE CHECK ERROR: %s", verify_err)
    except Exception as e:
        logger.error("CRYPTO SIGNATURE INVALID ✗ — %s", e)
else:
    logger.warning("CA cert file not found at %s — skipping issuer verification", CA_CERT_FILE.resolve())

# =============================================================================
# TEST: CERT + BASIC AUTH
# =============================================================================

logger.info("")
logger.info("=== Test: client cert + basic auth ===")

test_session = requests.Session()
test_session.cert = (str(CLIENT_CERT_FILE.resolve()), str(CLIENT_KEY_FILE.resolve()))
test_session.verify = False
test_session.auth = (CLIENT_USER, ADMIN_PASS)

logger.info("session.cert = %s", test_session.cert)
logger.info("session.auth = (%s, %s)", CLIENT_USER, ADMIN_PASS)
logger.info("GET %s/grid ...", BASE_URL)

try:
    resp = test_session.get(f"{BASE_URL}/authpolicy?_return_fields=usage_type,auth_services", timeout=10)
    logger.info("Response status: %d", resp.status_code)
    logger.info("Response headers: %s", dict(resp.headers))
    if resp.status_code == 200:
        logger.info("SUCCESS — certificate auth is working")
        logger.info("Response body: %s", resp.text)
    else:
        logger.warning("FAILED with status %d", resp.status_code)
        logger.warning("Response body: %s", resp.text)
except requests.exceptions.Timeout:
    logger.error("TIMEOUT — request took longer than 10 seconds")
except requests.exceptions.SSLError as e:
    logger.error("SSL ERROR: %s", e)
except Exception as e:
    logger.error("%s: %s", type(e).__name__, e)

# =============================================================================
# TEST: BASIC AUTH ONLY (NO CERT) — as a control
# =============================================================================

logger.info("")
logger.info("=== Test: basic auth only (no cert) — control ===")

test_session_basic = requests.Session()
test_session_basic.verify = False
test_session_basic.auth = (CLIENT_USER, ADMIN_PASS)

logger.info("session.cert = None")
logger.info("session.auth = (%s, %s)", CLIENT_USER, ADMIN_PASS)
logger.info("GET %s/grid ...", BASE_URL)

try:
    resp = test_session_basic.get(f"{BASE_URL}/authpolicy?_return_fields=usage_type,auth_services", timeout=10)
    logger.info("Response status: %d", resp.status_code)
    if resp.status_code == 200:
        logger.info("SUCCESS — basic auth control test passed")
    else:
        logger.warning("FAILED with status %d", resp.status_code)
        logger.warning("Response body: %s", resp.text)
except Exception as e:
    logger.error("%s: %s", type(e).__name__, e)
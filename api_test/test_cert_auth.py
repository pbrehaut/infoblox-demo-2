"""
Standalone test for Infoblox certificate authentication.

Tests the connection using client cert + basic auth with verbose logging
to diagnose certificate presentation issues.
"""

import logging
import ssl
from pathlib import Path

import requests

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

CLIENT_EMAIL = "api-user@example.com"
ADMIN_PASS = "infoblox"

CLIENT_CERT_FILE = Path("client.cert.pem")
CLIENT_KEY_FILE = Path("client.key.pem")

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
# TEST: CERT + BASIC AUTH
# =============================================================================

logger.info("")
logger.info("=== Test: client cert + basic auth ===")

test_session = requests.Session()
test_session.cert = (str(CLIENT_CERT_FILE.resolve()), str(CLIENT_KEY_FILE.resolve()))
test_session.verify = False
test_session.auth = (CLIENT_EMAIL, ADMIN_PASS)

logger.info("session.cert = %s", test_session.cert)
logger.info("session.auth = (%s, ***)", CLIENT_EMAIL)
logger.info("GET %s/grid ...", BASE_URL)

try:
    resp = test_session.get(f"{BASE_URL}/grid", timeout=10)
    logger.info("Response status: %d", resp.status_code)
    logger.info("Response headers: %s", dict(resp.headers))
    if resp.status_code == 200:
        logger.info("SUCCESS — certificate auth is working")
        logger.info("Response body: %s", resp.text[:500])
    else:
        logger.warning("FAILED with status %d", resp.status_code)
        logger.warning("Response body: %s", resp.text[:500])
except requests.exceptions.Timeout:
    logger.error("TIMEOUT — request took longer than 10 seconds")
except requests.exceptions.SSLError as e:
    logger.error("SSL ERROR: %s", e)
except Exception as e:
    logger.error("%s: %s", type(e).__name__, e)

# =============================================================================
# TEST: CERT ONLY (NO BASIC AUTH)
# =============================================================================

logger.info("")
logger.info("=== Test: client cert only (no basic auth) ===")

test_session_cert_only = requests.Session()
test_session_cert_only.cert = (str(CLIENT_CERT_FILE.resolve()), str(CLIENT_KEY_FILE.resolve()))
test_session_cert_only.verify = False

logger.info("session.cert = %s", test_session_cert_only.cert)
logger.info("session.auth = None")
logger.info("GET %s/grid ...", BASE_URL)

try:
    resp = test_session_cert_only.get(f"{BASE_URL}/grid", timeout=10)
    logger.info("Response status: %d", resp.status_code)
    logger.info("Response headers: %s", dict(resp.headers))
    if resp.status_code == 200:
        logger.info("SUCCESS — certificate-only auth is working")
        logger.info("Response body: %s", resp.text[:500])
    else:
        logger.warning("FAILED with status %d", resp.status_code)
        logger.warning("Response body: %s", resp.text[:500])
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
test_session_basic.auth = ("admin", "infoblox")

logger.info("session.cert = None")
logger.info("session.auth = (admin, ***)")
logger.info("GET %s/grid ...", BASE_URL)

try:
    resp = test_session_basic.get(f"{BASE_URL}/grid", timeout=10)
    logger.info("Response status: %d", resp.status_code)
    if resp.status_code == 200:
        logger.info("SUCCESS — basic auth control test passed")
    else:
        logger.warning("FAILED with status %d", resp.status_code)
        logger.warning("Response body: %s", resp.text[:500])
except Exception as e:
    logger.error("%s: %s", type(e).__name__, e)
"""
Infoblox Certificate Authentication Setup - Lab Script

This script:
1. Generates CA and client certificates (skips if files already exist)
2. Uploads CA cert to Infoblox
3. Creates admin user and Certificate Authentication Service
4. Tests the connection with certificate auth + basic auth
"""

import datetime
import logging
from pathlib import Path

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

requests.packages.urllib3.disable_warnings()

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def log_cert_details(cert: x509.Certificate, label: str) -> None:
    """Log key details of an X.509 certificate.

    Args:
        cert: The certificate to inspect.
        label: A human-readable label for log output (e.g. "CA" or "Client").
    """
    subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    logger.info("       %s cert details:", label)
    logger.info("         Subject CN : %s", subject_cn[0].value if subject_cn else "N/A")
    logger.info("         Issuer CN  : %s", issuer_cn[0].value if issuer_cn else "N/A")
    logger.info("         Serial     : %s", format(cert.serial_number, "x"))
    logger.info("         Not before : %s", cert.not_valid_before_utc)
    logger.info("         Not after  : %s", cert.not_valid_after_utc)
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        emails = san_ext.value.get_values_for_type(x509.RFC822Name)
        if emails:
            logger.info("         SAN email  : %s", ", ".join(emails))
    except x509.ExtensionNotFound:
        pass


# =============================================================================
# CONFIGURATION - EDIT THESE VALUES
# =============================================================================

INFOBLOX_HOST = "10.10.10.213"
MEMBER_HOSTNAME = "ibgd.azureonpremlab1.local"
WAPI_VERSION = "v2.13.7"

CLIENT_EMAIL = "api-user@example.com"  # Must match the admin user we create
CA_COMMON_NAME = "Infoblox CA"
CLIENT_COMMON_NAME = "api-user@example.com"
CERT_VALID_DAYS = 365

# Output files
CA_CERT_FILE = Path("ca.cert.pem")
CA_KEY_FILE = Path("ca.key.pem")
CLIENT_CERT_FILE = Path("client.cert.pem")
CLIENT_KEY_FILE = Path("client.key.pem")

# =============================================================================
# PROMPT FOR CREDENTIALS
# =============================================================================

logger.info("Infoblox Certificate Authentication Setup")
# admin_user = input("Enter Infoblox admin username: ")
admin_user = "admin"
logger.debug("Got username: '%s'", admin_user)

# Using regular input instead of getpass (getpass hangs in PyCharm)
# admin_pass = input("Enter Infoblox admin password: ")
admin_pass = "infoblox"
logger.debug("Got password")

BASE_URL = f"https://{INFOBLOX_HOST}/wapi/{WAPI_VERSION}"
logger.debug("BASE_URL = %s", BASE_URL)

logger.debug("Creating requests.Session()")
session = requests.Session()
session.auth = (admin_user, admin_pass)
session.verify = False
session.trust_env = False
logger.debug("Session ready")

# Quick connection test
logger.info("Testing connection to %s ...", BASE_URL)
try:
    resp = session.get(f"{BASE_URL}/grid", timeout=10)
    logger.info("Response: %d", resp.status_code)
    if resp.status_code == 401:
        logger.error("Authentication failed - check username/password")
        exit(1)
    elif resp.status_code != 200:
        logger.error("%s", resp.text)
        exit(1)
    logger.info("Connection OK!")
except requests.exceptions.Timeout:
    logger.error("Connection timeout - check host/network")
    exit(1)
except requests.exceptions.ConnectionError as e:
    logger.error("Connection failed - %s", e)
    exit(1)

# =============================================================================
# STEP 1: GENERATE CA CERTIFICATE
# =============================================================================

logger.info("[1/6] Generating CA certificate...")

if CA_CERT_FILE.exists() and CA_KEY_FILE.exists():
    logger.info("       CA files already exist, loading from disk")
    ca_key = serialization.load_pem_private_key(
        CA_KEY_FILE.read_bytes(),
        password=None,
        backend=default_backend(),
    )
    ca_cert = x509.load_pem_x509_certificate(
        CA_CERT_FILE.read_bytes(),
        backend=default_backend(),
    )
    logger.info("       Loaded: %s, %s", CA_CERT_FILE, CA_KEY_FILE)
    log_cert_details(ca_cert, "CA")
else:
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend(),
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME)]))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CERT_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    CA_KEY_FILE.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CA_CERT_FILE.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    logger.info("       Saved: %s, %s", CA_CERT_FILE, CA_KEY_FILE)
    log_cert_details(ca_cert, "CA")

# =============================================================================
# STEP 2: GENERATE CLIENT CERTIFICATE
# =============================================================================

logger.info("[2/6] Generating client certificate...")

if CLIENT_CERT_FILE.exists() and CLIENT_KEY_FILE.exists():
    logger.info("       Client files already exist, skipping generation")
    client_cert = x509.load_pem_x509_certificate(
        CLIENT_CERT_FILE.read_bytes(),
        backend=default_backend(),
    )
    log_cert_details(client_cert, "Client")
else:
    now = datetime.datetime.now(datetime.timezone.utc)

    client_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend(),
    )

    client_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CLIENT_COMMON_NAME)]))
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CERT_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(CLIENT_EMAIL)]), critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    CLIENT_KEY_FILE.write_bytes(
        client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CLIENT_CERT_FILE.write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))
    logger.info("       Saved: %s, %s", CLIENT_CERT_FILE, CLIENT_KEY_FILE)
    log_cert_details(client_cert, "Client")

# =============================================================================
# STEP 3: UPLOAD CA CERTIFICATE TO INFOBLOX
# =============================================================================

logger.info("[3/6] Uploading CA certificate to Infoblox...")

# Initialize upload
logger.debug("       POST %s/fileop?_function=uploadinit ...", BASE_URL)
resp = session.post(f"{BASE_URL}/fileop?_function=uploadinit", json={}, timeout=10)
logger.debug("       Response: %d", resp.status_code)
if resp.status_code != 200:
    logger.error("       %s", resp.text)
    logger.error("       CA certificate upload FAILED - cannot continue.")
    exit(1)
token = resp.json()["token"]
upload_url = resp.json()["url"]
logger.debug("       Got upload URL: %s...", upload_url[:60])

# Upload file
logger.debug("       Uploading %s...", CA_CERT_FILE)
with CA_CERT_FILE.open("rb") as f:
    resp = session.post(upload_url, files={"file": f}, timeout=10)
logger.debug("       Response: %d", resp.status_code)

# Register certificate
logger.debug("       POST fileop?_function=uploadcertificate ...")
resp = session.post(
    f"{BASE_URL}/fileop?_function=uploadcertificate",
    json={
        "certificate_usage": "EAP_CA",
        "member": MEMBER_HOSTNAME,
        "token": token,
    },
    timeout=10,
)
logger.debug("       Response: %d", resp.status_code)
if resp.status_code != 200:
    logger.error("       %s", resp.text)

# Get certificate reference by matching serial number
logger.debug("       GET cacertificate ...")
resp = session.get(f"{BASE_URL}/cacertificate", timeout=10)
logger.debug("       Response: %d", resp.status_code)

# Match by serial number (cryptography uses int, Infoblox uses hex string)
our_serial = format(ca_cert.serial_number, "x")
logger.debug("       Looking for serial: %s", our_serial)

ca_cert_ref = None
for cert in resp.json():
    logger.debug(
        "       Found cert: serial=%s dn=%s",
        cert.get("serial"),
        cert.get("distinguished_name"),
    )
    if cert.get("serial", "").lstrip("0") == our_serial.lstrip("0"):
        ca_cert_ref = cert["_ref"]
        break

if ca_cert_ref is None:
    logger.error("       Could not find uploaded CA certificate")
    exit(1)

logger.info("       CA cert ref: %s", ca_cert_ref)

# =============================================================================
# STEP 4: CREATE ADMIN USER
# =============================================================================

logger.info("[4/6] Creating admin user: %s...", CLIENT_EMAIL)

# Check if user exists
logger.debug("       GET adminuser?name=%s ...", CLIENT_EMAIL)
resp = session.get(f"{BASE_URL}/adminuser", params={"name": CLIENT_EMAIL}, timeout=10)
logger.debug("       Response: %d", resp.status_code)
existing = resp.json()
if existing:
    user_ref = existing[0]["_ref"]
    logger.info("       User already exists: %s", user_ref)
else:
    logger.debug("       POST adminuser ...")
    resp = session.post(
        f"{BASE_URL}/adminuser",
        json={
            "admin_groups": ["admin-group"],
            "name": CLIENT_EMAIL,
            "password": "changeme",
        },
        timeout=10,
    )
    logger.debug("       Response: %d", resp.status_code)
    if resp.status_code != 201:
        logger.error("       %s", resp.text)
    user_ref = resp.json()
    logger.info("       Created: %s", user_ref)

# =============================================================================
# STEP 5: CREATE CERTIFICATE AUTHENTICATION SERVICE
# =============================================================================

logger.info("[5/6] Creating Certificate Authentication Service...")

# Check if CAS exists
logger.debug("       GET certificate:authservice?name=cert-login ...")
resp = session.get(
    f"{BASE_URL}/certificate:authservice", params={"name": "cert-login"}, timeout=10
)
logger.debug("       Response: %d", resp.status_code)
existing = resp.json()
if existing:
    cas_ref = existing[0]["_ref"]
    logger.info("       CAS already exists: %s", cas_ref)
else:
    logger.debug("       POST certificate:authservice ...")
    resp = session.post(
        f"{BASE_URL}/certificate:authservice",
        json={
            "name": "cert-login",
            "ocsp_check": "DISABLED",
            "ca_certificates": [ca_cert_ref],
            "enable_password_request": False,
            "client_cert_subject": "",
            "trust_model": "DIRECT",
            "user_match_type": "AUTO_MATCH",
            "auto_populate_login": "SAN_EMAIL",
        },
        timeout=10,
    )
    logger.debug("       Response: %d", resp.status_code)
    if resp.status_code != 201:
        logger.error("       %s", resp.text)
    cas_ref = resp.json()
    logger.info("       Created: %s", cas_ref)

# Add CAS to auth policy (must be first in the list)
logger.debug("       GET authpolicy ...")
resp = session.get(
    f"{BASE_URL}/authpolicy", params={"_return_fields": "auth_services"}, timeout=10
)
logger.debug("       Response: %d", resp.status_code)
authpolicy = resp.json()[0]
logger.debug("       Current auth_services: %s", authpolicy["auth_services"])
if cas_ref not in authpolicy["auth_services"]:
    logger.debug("       PUT %s ...", authpolicy["_ref"])
    resp = session.put(
        f"{BASE_URL}/{authpolicy['_ref']}",
        json={"auth_services": [cas_ref] + authpolicy["auth_services"]},
        timeout=10,
    )
    logger.debug("       Response: %d", resp.status_code)
    logger.info("       Added CAS to auth policy")
else:
    logger.info("       CAS already in auth policy")

# =============================================================================
# STEP 6: TEST CERTIFICATE AUTHENTICATION
# =============================================================================

logger.info("[6/6] Testing certificate authentication...")

test_session = requests.Session()
test_session.cert = (str(CLIENT_CERT_FILE), str(CLIENT_KEY_FILE))
test_session.verify = False
test_session.auth = (CLIENT_EMAIL, "changeme")

logger.info("       GET %s/grid (using client cert + basic auth) ...", BASE_URL)
logger.debug("       Cert: %s", CLIENT_CERT_FILE)
logger.debug("       Key:  %s", CLIENT_KEY_FILE)
logger.debug("       Basic auth user: %s", CLIENT_EMAIL)
try:
    resp = test_session.get(f"{BASE_URL}/grid", timeout=10)
    logger.info("       Response: %d", resp.status_code)
    if resp.status_code == 200:
        logger.info("       SUCCESS! Certificate authentication is working.")
        logger.debug("       Response body: %s", resp.text[:200])
    else:
        logger.warning("       FAILED with status %d", resp.status_code)
        logger.warning("       Response: %s", resp.text)
        logger.warning("       You may need to restart Infoblox services.")
except requests.exceptions.Timeout:
    logger.error("       TIMEOUT - request took longer than 10 seconds")
except requests.exceptions.SSLError as e:
    logger.error("       SSL ERROR: %s", e)
except Exception as e:
    logger.error("       %s: %s", type(e).__name__, e)

# =============================================================================
# DONE
# =============================================================================

# logger.info("=" * 45)
# logger.info("SETUP COMPLETE")
# logger.info("=" * 45)
# logger.info(
#     "\nGenerated files:\n"
#     "  %s      - CA certificate (uploaded to Infoblox)\n"
#     "  %s       - CA private key (keep secure)\n"
#     "  %s  - Client certificate\n"
#     "  %s   - Client private key\n"
#     "\n"
#     "To use certificate authentication in Python:\n"
#     "\n"
#     "    import requests\n"
#     "\n"
#     "    session = requests.Session()\n"
#     '    session.cert = ("%s", "%s")\n'
#     "    session.verify = False\n"
#     "\n"
#     '    resp = session.get("https://%s/wapi/%s/network")\n'
#     "    print(resp.json())\n",
#     CA_CERT_FILE,
#     CA_KEY_FILE,
#     CLIENT_CERT_FILE,
#     CLIENT_KEY_FILE,
#     CLIENT_CERT_FILE,
#     CLIENT_KEY_FILE,
#     INFOBLOX_HOST,
#     WAPI_VERSION,
# )
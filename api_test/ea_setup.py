"""
Infoblox WAPI extensible attribute setup and inheritance demo.

Creates all extensible attribute definitions from the EA specification
tables, attaches sample values to existing network objects, and creates
a child network to verify inheritance behaviour.

Usage:
    python ea_setup.py
"""

import json
import logging
import sys
from dataclasses import dataclass, field
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

requests.packages.urllib3.disable_warnings()

# =============================================================================
# CONFIGURATION
# =============================================================================

INFOBLOX_HOST: str = "10.10.10.213"
WAPI_VERSION: str = "v2.13.7"
BASE_URL: str = f"https://{INFOBLOX_HOST}/wapi/{WAPI_VERSION}"

CLIENT_CERT_FILE: Path = Path(__file__).parent / "client.cert.pem"
CLIENT_KEY_FILE: Path = Path(__file__).parent / "client.key.pem"

# =============================================================================
# LOGGING
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# =============================================================================
# EA DEFINITIONS
# =============================================================================

# WAPI object type strings for allowed_object_types.
# Adjust these if your NIOS version uses different identifiers.
IPV4_CONTAINER: str = "NetworkContainer"
IPV4_NETWORK: str = "Network"
IPV6_CONTAINER: str = "IPv6NetworkContainer"
IPV6_NETWORK: str = "IPv6Network"

ALL_NETWORK_TYPES: List[str] = [
    IPV4_CONTAINER, IPV4_NETWORK, IPV6_CONTAINER, IPV6_NETWORK,
]
NETWORKS_ONLY: List[str] = [IPV4_NETWORK, IPV6_NETWORK]


@dataclass
class EADefinition:
    """Specification for an extensible attribute to create.

    Attributes:
        name: EA name as it will appear in Infoblox.
        ea_type: WAPI type — STRING or ENUM.
        flags: WAPI flags string, e.g. "IM" for Inheritable + Mandatory.
            Must be in order: A, C, G, I, L, M, P, R, S, V.
        list_values: Allowed values for ENUM types.
        allowed_object_types: Object types this EA can be associated with.
            Empty list means no restriction (all types).
        comment: Description of the EA.
    """

    name: str
    ea_type: str
    flags: str = ""
    list_values: List[str] = field(default_factory=list)
    allowed_object_types: List[str] = field(default_factory=list)
    comment: str = ""


# ---- Table 1: Core EAs ----

CORE_EA_DEFINITIONS: List[EADefinition] = [
    EADefinition(
        name="Group",
        ea_type="ENUM",
        flags="IM",
        list_values=["Group_A", "Group_B", "Group_C"],
        allowed_object_types=ALL_NETWORK_TYPES,
        comment="Network group classification",
    ),
    EADefinition(
        name="Sub-Group",
        ea_type="ENUM",
        flags="IM",
        list_values=["SubGroup_1", "SubGroup_2", "SubGroup_3"],
        allowed_object_types=ALL_NETWORK_TYPES,
        comment="Network sub-group classification",
    ),
    EADefinition(
        name="Environment",
        ea_type="ENUM",
        flags="I",
        list_values=["Prod", "Non-Prod"],
        allowed_object_types=ALL_NETWORK_TYPES,
        comment="Deployment environment",
    ),
    EADefinition(
        name="Location",
        ea_type="ENUM",
        flags="I",
        list_values=["AU-East", "AU-West", "AU-Central"],
        allowed_object_types=ALL_NETWORK_TYPES,
        comment="Geographic location",
    ),
    EADefinition(
        name="City",
        ea_type="ENUM",
        flags="I",
        list_values=["Sydney", "Melbourne", "Brisbane", "Perth"],
        allowed_object_types=ALL_NETWORK_TYPES,
        comment="City",
    ),
    EADefinition(
        name="Building",
        ea_type="ENUM",
        flags="I",
        list_values=["Building_A", "Building_B", "Building_C"],
        allowed_object_types=ALL_NETWORK_TYPES,
        comment="Building identifier",
    ),
    EADefinition(
        name="Site_ID",
        ea_type="STRING",
        flags="I",
        allowed_object_types=ALL_NETWORK_TYPES,
        comment="Unique site identifier",
    ),
    EADefinition(
        name="Site_Code",
        ea_type="STRING",
        flags="I",
        allowed_object_types=ALL_NETWORK_TYPES,
        comment="Site code",
    ),
]

# ---- Table 2: Network-only and unrestricted EAs ----

NETWORK_EA_DEFINITIONS: List[EADefinition] = [
    EADefinition(
        name="BGP_ASN",
        ea_type="STRING",
        flags="",
        allowed_object_types=NETWORKS_ONLY,
        comment="BGP autonomous system number",
    ),
    EADefinition(
        name="VLAN",
        ea_type="STRING",
        flags="",
        allowed_object_types=NETWORKS_ONLY,
        comment="VLAN identifier",
    ),
    EADefinition(
        name="VLAN Domain",
        ea_type="STRING",
        flags="",
        allowed_object_types=NETWORKS_ONLY,
        comment="VLAN domain",
    ),
    EADefinition(
        name="VRF",
        ea_type="STRING",
        flags="",
        allowed_object_types=NETWORKS_ONLY,
        comment="VRF name",
    ),
    EADefinition(
        name="Description",
        ea_type="STRING",
        flags="I",
        comment="General description",
    ),
    EADefinition(
        name="Comments",
        ea_type="STRING",
        flags="I",
        comment="Additional comments",
    ),
    EADefinition(
        name="SNOW_Ref",
        ea_type="STRING",
        flags="I",
        comment="ServiceNow reference number",
    ),
    EADefinition(
        name="MVE",
        ea_type="ENUM",
        flags="I",
        list_values=["MNS", "HCS", "EUPSD", "ESM", "MacGov", "DAFF Cloud Team"],
        comment="Managed virtual environment owner",
    ),
]

# ---- Table 3: APO Specific EAs (no object type restrictions) ----

APO_EA_DEFINITIONS: List[EADefinition] = [
    EADefinition(
        name="Tenant",
        ea_type="ENUM",
        flags="I",
        list_values=["Tenant_A", "Tenant_B", "Tenant_C"],
        comment="APO tenant",
    ),
    EADefinition(
        name="Landscape",
        ea_type="ENUM",
        flags="I",
        list_values=["Landscape_1", "Landscape_2", "Landscape_3"],
        comment="APO landscape",
    ),
    EADefinition(
        name="APO_Environment",
        ea_type="ENUM",
        flags="I",
        list_values=["Dev", "Test", "Staging", "Production"],
        comment="APO environment classification",
    ),
    EADefinition(
        name="Region",
        ea_type="ENUM",
        flags="I",
        list_values=["Region_1", "Region_2", "Region_3"],
        comment="APO region",
    ),
    EADefinition(
        name="Zone",
        ea_type="ENUM",
        flags="I",
        list_values=["Zone_A", "Zone_B", "Zone_C"],
        comment="APO zone",
    ),
    EADefinition(
        name="Status",
        ea_type="ENUM",
        flags="I",
        list_values=["Active", "Inactive", "Planned", "Decommissioned"],
        comment="APO status",
    ),
    EADefinition(
        name="Asset",
        ea_type="ENUM",
        flags="I",
        list_values=["Asset_1", "Asset_2", "Asset_3"],
        comment="APO asset reference",
    ),
]

ALL_EA_DEFINITIONS: List[EADefinition] = (
    CORE_EA_DEFINITIONS + NETWORK_EA_DEFINITIONS + APO_EA_DEFINITIONS
)


# =============================================================================
# AUTHENTICATION
# =============================================================================


def authenticate(session: requests.Session) -> bool:
    """Authenticate to Infoblox WAPI, trying cert auth then basic auth.

    Args:
        session: The requests session to configure.

    Returns:
        True if authentication succeeded.
    """
    # Try certificate auth first
    if CLIENT_CERT_FILE.exists() and CLIENT_KEY_FILE.exists():
        logger.info("Attempting certificate authentication...")
        session.cert = (
            str(CLIENT_CERT_FILE.resolve()),
            str(CLIENT_KEY_FILE.resolve()),
        )
        session.verify = False

        try:
            resp = session.get(f"{BASE_URL}/grid", timeout=10)
            if resp.ok:
                logger.info("Certificate authentication succeeded")
                return True
            logger.warning("Certificate auth returned %d", resp.status_code)
        except requests.exceptions.RequestException as exc:
            logger.warning("Certificate auth failed: %s", exc)
    else:
        logger.info("Certificate files not found, skipping cert auth")

    # Fall back to basic auth
    logger.info("Falling back to basic authentication")
    username: str = input("  Username: ")
    password: str = getpass("  Password: ")

    session.cert = None
    session.auth = (username, password)
    session.verify = False

    try:
        resp = session.get(f"{BASE_URL}/grid", timeout=10)
        if resp.ok:
            logger.info("Basic authentication succeeded as %s", username)
            return True
        logger.error("Basic auth failed with status %d: %s", resp.status_code, resp.text[:200])
        return False
    except requests.exceptions.RequestException as exc:
        logger.error("Basic auth request failed: %s", exc)
        return False


# =============================================================================
# EA CREATION
# =============================================================================


def build_ea_payload(ea_def: EADefinition) -> Dict[str, Any]:
    """Build the WAPI JSON payload for creating an extensible attribute definition.

    Args:
        ea_def: The EA definition specification.

    Returns:
        Dict suitable for POSTing to the extensibleattributedef endpoint.
    """
    payload: Dict[str, Any] = {
        "name": ea_def.name,
        "type": ea_def.ea_type,
        "comment": ea_def.comment,
    }

    if ea_def.flags:
        payload["flags"] = ea_def.flags

    if ea_def.ea_type == "ENUM" and ea_def.list_values:
        payload["list_values"] = [{"value": v} for v in ea_def.list_values]

    if ea_def.allowed_object_types:
        payload["allowed_object_types"] = ea_def.allowed_object_types

    return payload


def create_ea_definition(
    session: requests.Session, ea_def: EADefinition
) -> bool:
    """Create a single extensible attribute definition via WAPI.

    Handles the case where the EA already exists gracefully.

    Args:
        session: Authenticated requests session.
        ea_def: The EA definition to create.

    Returns:
        True if the EA was created or already exists.
    """
    url: str = f"{BASE_URL}/extensibleattributedef"
    payload: Dict[str, Any] = build_ea_payload(ea_def)

    logger.info("Creating EA '%s' (type=%s, flags='%s')", ea_def.name, ea_def.ea_type, ea_def.flags)
    logger.debug("Payload: %s", json.dumps(payload, indent=2))

    try:
        resp = session.post(url, json=payload, timeout=10)

        if resp.status_code == 201:
            logger.info("  Created EA '%s' -> %s", ea_def.name, resp.json())
            return True
        elif resp.status_code == 400 and "already exists" in resp.text.lower():
            logger.info("  EA '%s' already exists, skipping", ea_def.name)
            return True
        else:
            logger.error(
                "  Failed to create EA '%s': %d - %s",
                ea_def.name, resp.status_code, resp.text[:300],
            )
            return False
    except requests.exceptions.RequestException as exc:
        logger.error("  Request failed for EA '%s': %s", ea_def.name, exc)
        return False


def create_all_ea_definitions(session: requests.Session) -> int:
    """Create all extensible attribute definitions.

    Args:
        session: Authenticated requests session.

    Returns:
        Count of successfully created (or pre-existing) EAs.
    """
    logger.info("=" * 60)
    logger.info("Creating %d extensible attribute definitions", len(ALL_EA_DEFINITIONS))
    logger.info("=" * 60)

    success_count: int = 0
    for ea_def in ALL_EA_DEFINITIONS:
        if create_ea_definition(session, ea_def):
            success_count += 1

    logger.info(
        "EA creation complete: %d/%d succeeded",
        success_count, len(ALL_EA_DEFINITIONS),
    )
    return success_count


# =============================================================================
# FIND EXISTING OBJECTS
# =============================================================================


def find_network_container(
    session: requests.Session,
) -> Optional[Dict[str, Any]]:
    """Find the first available IPv4 network container.

    Args:
        session: Authenticated requests session.

    Returns:
        The network container object dict, or None if not found.
    """
    url: str = f"{BASE_URL}/networkcontainer"
    params: Dict[str, Any] = {
        "_return_fields+": "extattrs,comment",
        "_return_as_object": 1,
        "_max_results": 5,
    }

    logger.info("Searching for network containers...")

    try:
        resp = session.get(url, params=params, timeout=15)
        if not resp.ok:
            logger.error("Failed to fetch containers: %d - %s", resp.status_code, resp.text[:200])
            return None

        containers: List[Dict[str, Any]] = resp.json().get("result", [])
        if not containers:
            logger.warning("No network containers found")
            return None

        container = containers[0]
        logger.info(
            "Found container: %s (ref: %s)",
            container.get("network", "unknown"),
            container.get("_ref", "unknown")[:50],
        )
        return container
    except requests.exceptions.RequestException as exc:
        logger.error("Request failed: %s", exc)
        return None


def find_network(session: requests.Session) -> Optional[Dict[str, Any]]:
    """Find the first available IPv4 network.

    Args:
        session: Authenticated requests session.

    Returns:
        The network object dict, or None if not found.
    """
    url: str = f"{BASE_URL}/network"
    params: Dict[str, Any] = {
        "_return_fields+": "extattrs,comment",
        "_return_as_object": 1,
        "_max_results": 5,
    }

    logger.info("Searching for networks...")

    try:
        resp = session.get(url, params=params, timeout=15)
        if not resp.ok:
            logger.error("Failed to fetch networks: %d - %s", resp.status_code, resp.text[:200])
            return None

        networks: List[Dict[str, Any]] = resp.json().get("result", [])
        if not networks:
            logger.warning("No networks found")
            return None

        network = networks[0]
        logger.info(
            "Found network: %s (ref: %s)",
            network.get("network", "unknown"),
            network.get("_ref", "unknown")[:50],
        )
        return network
    except requests.exceptions.RequestException as exc:
        logger.error("Request failed: %s", exc)
        return None


# =============================================================================
# ATTACH EA VALUES TO OBJECTS
# =============================================================================

# Sample EA values to attach to a parent container/network.
# Only includes inheritable EAs so we can verify inheritance on children.
SAMPLE_PARENT_EXTATTRS: Dict[str, Dict[str, str]] = {
    "Group": {"value": "Group_A"},
    "Sub-Group": {"value": "SubGroup_1"},
    "Environment": {"value": "Prod"},
    "Location": {"value": "AU-East"},
    "City": {"value": "Sydney"},
    "Building": {"value": "Building_A"},
    "Site_ID": {"value": "SYD-001"},
    "Site_Code": {"value": "SYD"},
    "Description": {"value": "Lab test parent network"},
    "Comments": {"value": "Set by ea_setup.py"},
    "SNOW_Ref": {"value": "SNOW-LAB-0001"},
    "MVE": {"value": "MNS"},
    "Tenant": {"value": "Tenant_A"},
    "Landscape": {"value": "Landscape_1"},
    "APO_Environment": {"value": "Dev"},
    "Region": {"value": "Region_1"},
    "Zone": {"value": "Zone_A"},
    "Status": {"value": "Active"},
    "Asset": {"value": "Asset_1"},
}


def attach_extattrs_to_object(
    session: requests.Session,
    object_ref: str,
    extattrs: Dict[str, Dict[str, str]],
    object_label: str,
) -> bool:
    """Attach extensible attribute values to an existing Infoblox object.

    Args:
        session: Authenticated requests session.
        object_ref: The _ref of the object to update.
        extattrs: Dict of EA name -> {"value": ...} pairs.
        object_label: Human-readable label for logging.

    Returns:
        True if the update succeeded.
    """
    url: str = f"{BASE_URL}/{object_ref}"
    payload: Dict[str, Any] = {"extattrs+": extattrs}

    logger.info("Attaching %d EAs to %s", len(extattrs), object_label)
    logger.debug("Payload: %s", json.dumps(payload, indent=2))

    try:
        resp = session.put(url, json=payload, timeout=10)

        if resp.ok:
            logger.info("  Successfully attached EAs to %s", object_label)
            return True
        else:
            logger.error(
                "  Failed to attach EAs to %s: %d - %s",
                object_label, resp.status_code, resp.text[:300],
            )
            return False
    except requests.exceptions.RequestException as exc:
        logger.error("  Request failed for %s: %s", object_label, exc)
        return False


# =============================================================================
# CREATE CHILD NETWORK & VERIFY INHERITANCE
# =============================================================================


def create_child_network(
    session: requests.Session,
    parent_cidr: str,
) -> Optional[str]:
    """Create a child /28 network inside a parent for inheritance testing.

    Picks the first /28 within the parent range using next_available_network.

    Args:
        session: Authenticated requests session.
        parent_cidr: The parent network CIDR, e.g. "10.10.200.0/24".

    Returns:
        The _ref of the created child network, or None on failure.
    """
    url: str = f"{BASE_URL}/network"
    # Use next_available_network to find a free /28 within the parent
    payload: Dict[str, Any] = {
        "network": {
            "_object_function": "next_available_network",
            "_result_field": "networks",
            "_object": "networkcontainer",
            "_object_parameters": {"network": parent_cidr},
            "_parameters": {"cidr": 28, "num": 1},
        },
        "comment": "Child network created by ea_setup.py for inheritance test",
    }

    logger.info("Creating child /28 network inside %s...", parent_cidr)
    logger.debug("Payload: %s", json.dumps(payload, indent=2))

    try:
        resp = session.post(url, json=payload, timeout=15)

        if resp.status_code == 201:
            child_ref: str = resp.json()
            logger.info("  Created child network -> %s", child_ref)
            return child_ref
        else:
            logger.error(
                "  Failed to create child network: %d - %s",
                resp.status_code, resp.text[:300],
            )
            return None
    except requests.exceptions.RequestException as exc:
        logger.error("  Request failed: %s", exc)
        return None


def verify_inheritance(
    session: requests.Session,
    child_ref: str,
) -> None:
    """Fetch a child network and log which EAs were inherited.

    Args:
        session: Authenticated requests session.
        child_ref: The _ref of the child network.
    """
    url: str = f"{BASE_URL}/{child_ref}"
    params: Dict[str, Any] = {
        "_return_fields+": "extattrs",
        "_return_as_object": 1,
    }

    logger.info("Verifying inheritance on child network...")

    try:
        resp = session.get(url, params=params, timeout=10)

        if not resp.ok:
            logger.error("Failed to fetch child: %d - %s", resp.status_code, resp.text[:200])
            return

        result: Dict[str, Any] = resp.json().get("result", resp.json())
        child_extattrs: Dict[str, Any] = result.get("extattrs", {})

        if not child_extattrs:
            logger.warning("  No EAs found on child network — inheritance may not have applied")
            return

        logger.info("  Child network has %d EAs:", len(child_extattrs))
        for ea_name, ea_data in sorted(child_extattrs.items()):
            value = ea_data.get("value", "?")
            inheritance = ea_data.get("inheritance_source", None)
            inherited_label: str = " (inherited)" if inheritance else ""
            logger.info("    %s = %s%s", ea_name, value, inherited_label)

    except requests.exceptions.RequestException as exc:
        logger.error("  Request failed: %s", exc)


# =============================================================================
# MAIN
# =============================================================================


def main() -> None:
    """Entry point — runs the full EA setup and inheritance demo."""
    logger.info("=" * 60)
    logger.info("Infoblox EA Setup & Inheritance Demo")
    logger.info("Target: %s", BASE_URL)
    logger.info("=" * 60)

    session = requests.Session()

    # Step 1: Authenticate
    if not authenticate(session):
        logger.error("Authentication failed — aborting")
        sys.exit(1)

    # Step 2: Create all EA definitions
    success_count: int = create_all_ea_definitions(session)
    if success_count == 0:
        logger.error("No EAs created — aborting")
        sys.exit(1)

    # Step 3: Find existing objects to attach EAs to
    logger.info("=" * 60)
    logger.info("Finding existing objects for EA attachment")
    logger.info("=" * 60)

    container = find_network_container(session)
    network = find_network(session)

    if not container and not network:
        logger.error("No network containers or networks found — aborting")
        sys.exit(1)

    # Step 4: Attach EAs to existing objects
    logger.info("=" * 60)
    logger.info("Attaching sample EA values to objects")
    logger.info("=" * 60)

    if container:
        container_cidr: str = container.get("network", "unknown")
        attach_extattrs_to_object(
            session,
            container["_ref"],
            SAMPLE_PARENT_EXTATTRS,
            f"container {container_cidr}",
        )

    if network:
        network_cidr: str = network.get("network", "unknown")
        # Attach a subset — only network-applicable non-inherited EAs
        network_specific_extattrs: Dict[str, Dict[str, str]] = {
            "BGP_ASN": {"value": "65001"},
            "VLAN": {"value": "100"},
            "VLAN Domain": {"value": "lab-domain"},
            "VRF": {"value": "LAB-VRF"},
        }
        attach_extattrs_to_object(
            session,
            network["_ref"],
            network_specific_extattrs,
            f"network {network_cidr}",
        )

    # Step 5: Create child network and verify inheritance
    if container:
        logger.info("=" * 60)
        logger.info("Testing inheritance with child network")
        logger.info("=" * 60)

        child_ref = create_child_network(session, container_cidr)
        if child_ref:
            verify_inheritance(session, child_ref)
        else:
            logger.warning("Skipping inheritance verification — child creation failed")
    else:
        logger.warning("No container found — skipping inheritance test")

    logger.info("=" * 60)
    logger.info("EA setup complete")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()

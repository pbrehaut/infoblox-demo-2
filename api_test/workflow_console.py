"""
Infoblox WAPI workflow demonstration with sequential terminal UI.

Demonstrates the ServiceNow-to-Infoblox IP provisioning flow
with a flowing Rich terminal display showing each HTTP request
and response as separate panels connected by arrows.

Steps:
    0. Authenticate (cert-first, basic auth fallback)
    1. Ensure ServiceNow_Reference EA exists
    2. Retrieve target IP subnet with Extensible Attributes
    3. Get next available IP from a subnet
    4. Reserve the IP with a ServiceNow reference EA
"""

import json
import logging
import random
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from getpass import getpass
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

requests.packages.urllib3.disable_warnings()

# =============================================================================
# CONFIGURATION
# =============================================================================

INFOBLOX_HOST: str = "10.10.10.213"
WAPI_VERSION: str = "v2.13.7"
BASE_URL: str = f"https://{INFOBLOX_HOST}/wapi/{WAPI_VERSION}"

CLIENT_CERT_FILE: Path = Path(__file__).parent / "client.cert.pem"
CLIENT_KEY_FILE: Path = Path(__file__).parent / "client.key.pem"

DEMO_SNOW_REFERENCE: str = "SNOW-INC0012345"
TARGET_NETWORK: str = "10.10.200.0/24"

# =============================================================================
# LOGGING (minimal — Rich handles the display)
# =============================================================================

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

console = Console()

PANEL_WIDTH: int = 80


# =============================================================================
# DISPLAY HELPERS
# =============================================================================


def print_arrow() -> None:
    """Print a downward arrow connector between panels."""
    console.print("    │", style="dim")
    console.print("    ▼", style="dim")


def print_prompt(message: str = "Press Enter to continue...") -> None:
    """Print an arrow then wait for the user to press Enter.

    Args:
        message: The prompt message to display.
    """
    print_arrow()
    console.print()
    console.print(f"  [bold cyan]{message}[/bold cyan]", end="")
    input()
    console.print()


def print_request_panel(
    step_name: str,
    method: str,
    url: str,
    body: Optional[Dict[str, Any]] = None,
) -> None:
    """Print an HTTP request panel.

    Args:
        step_name: Name of the workflow step.
        method: HTTP method (GET, POST, etc.).
        url: The request URL.
        body: Optional request body dict.
    """
    lines = Text()
    lines.append("\n")
    lines.append("  REQUEST\n", style="bold cyan")
    lines.append(f"  {method} ", style="bold yellow")
    lines.append(f"{url}\n", style="white")

    if body is not None:
        lines.append("\n")
        lines.append("  Body:\n", style="bold cyan")
        body_json = json.dumps(body, indent=2)
        for line in body_json.split("\n"):
            lines.append(f"  {line}\n", style="white")

    lines.append("")

    console.print(Panel(
        lines,
        title=f"[bold]● {step_name}[/bold]",
        border_style="yellow",
        width=PANEL_WIDTH,
    ))


def print_response_panel(
    step_name: str,
    status: int,
    body: Optional[Any] = None,
    error: Optional[str] = None,
    summary: Optional[str] = None,
) -> None:
    """Print an HTTP response panel.

    Args:
        step_name: Name of the workflow step.
        status: HTTP response status code.
        body: Optional response body.
        error: Optional error message.
        summary: Optional result summary line.
    """
    success = 200 <= status < 300
    status_style = "bold green" if success else "bold red"
    border = "green" if success else "red"
    icon = "✓" if success else "✗"

    lines = Text()
    lines.append("\n")
    lines.append("  RESPONSE\n", style="bold cyan")
    lines.append("  Status: ", style="bold cyan")
    lines.append(f"{status}\n", style=status_style)

    if body is not None:
        lines.append("\n")
        lines.append("  Body:\n", style="bold cyan")
        if isinstance(body, (dict, list)):
            body_json = json.dumps(body, indent=2)
            body_lines = body_json.split("\n")
            if len(body_lines) > 20:
                body_lines = body_lines[:18] + [
                    "  ...",
                    f"  ({len(body_lines) - 18} more lines)",
                ]
            for line in body_lines:
                lines.append(f"  {line}\n", style="white")
        else:
            lines.append(f"  {body}\n", style="white")

    if error:
        lines.append(f"\n  Error: {error}\n", style="bold red")

    if summary:
        lines.append(f"\n  {icon} {summary}\n", style=status_style)

    lines.append("")

    console.print(Panel(
        lines,
        title=f"[bold]{icon} {step_name}[/bold]",
        border_style=border,
        width=PANEL_WIDTH,
    ))


def print_info_panel(
    step_name: str,
    message: str,
    status: str = "info",
) -> None:
    """Print a non-HTTP informational panel.

    Args:
        step_name: Name of the workflow step.
        message: The info message to display.
        status: One of 'info', 'success', 'failed', 'skipped'.
    """
    style_map = {
        "info": ("dim", "blue", "○"),
        "success": ("green", "green", "✓"),
        "failed": ("bold red", "red", "✗"),
        "skipped": ("dim yellow", "yellow", "–"),
    }
    text_style, border, icon = style_map.get(status, style_map["info"])

    lines = Text()
    lines.append(f"\n  {message}\n", style=text_style)

    console.print(Panel(
        lines,
        title=f"[bold]{icon} {step_name}[/bold]",
        border_style=border,
        width=PANEL_WIDTH,
    ))


# =============================================================================
# WORKFLOW RUNNER
# =============================================================================


class WorkflowRunner:
    """Runs the Infoblox workflow with sequential terminal display.

    Attributes:
        session: The authenticated requests session.
    """

    def __init__(self) -> None:
        self.session: Optional[requests.Session] = None

    # -------------------------------------------------------------------------
    # Step implementations
    # -------------------------------------------------------------------------

    def _step_cert_auth(self) -> bool:
        """Step 0: Attempt certificate authentication.

        Returns:
            True if cert auth succeeded.
        """
        step_name = "Auth (cert)"

        self.session = requests.Session()

        if not CLIENT_CERT_FILE.exists() or not CLIENT_KEY_FILE.exists():
            print_info_panel(
                step_name,
                "Certificate files not found — skipping",
                status="failed",
            )
            return False

        self.session.cert = (
            str(CLIENT_CERT_FILE.resolve()),
            str(CLIENT_KEY_FILE.resolve()),
        )
        self.session.verify = False

        url = f"{BASE_URL}/grid"
        print_request_panel(step_name, "GET", url)
        print_prompt("Press Enter to send request...")

        try:
            resp = self.session.get(url, timeout=10)
            resp_body = resp.json() if resp.ok else resp.text[:200]
            summary = "Certificate auth OK" if resp.ok else None
            print_response_panel(
                step_name, resp.status_code, body=resp_body, summary=summary,
            )

            if resp.ok:
                return True
            else:
                return False
        except requests.exceptions.RequestException as exc:
            print_response_panel(
                step_name, 0, error=str(exc)[:200],
            )
            return False

    def _step_basic_auth(self) -> bool:
        """Step 1: Fall back to basic authentication.

        Returns:
            True if basic auth succeeded.
        """
        step_name = "Auth (basic)"

        print_arrow()
        console.print()
        console.print(
            "[bold yellow]  Certificate auth failed"
            " — falling back to basic auth[/bold yellow]"
        )
        console.print()
        username = input("  Username: ")
        password = getpass("  Password: ")
        console.print()

        self.session.cert = None
        self.session.auth = (username, password)
        self.session.verify = False

        url = f"{BASE_URL}/grid"
        print_request_panel(
            step_name, "GET", url, body={"auth": f"{username}:****"},
        )
        print_prompt("Press Enter to send request...")

        try:
            resp = self.session.get(url, timeout=10)

            if resp.ok:
                print_response_panel(
                    step_name,
                    resp.status_code,
                    body=resp.json(),
                    summary=f"Authenticated as {username}",
                )
                return True
            else:
                print_response_panel(
                    step_name,
                    resp.status_code,
                    error=resp.text[:200],
                )
                return False
        except requests.exceptions.RequestException as exc:
            print_response_panel(step_name, 0, error=str(exc)[:200])
            return False

    def _step_list_all_subnets(self) -> None:
        """Step: Retrieve all subnets and display a summary table.

        Fetches all networks with a broad set of return fields,
        displays the raw response data, then prints a formatted
        table showing network, location, and support group.
        """
        step_name = "List All Subnets"

        url = f"{BASE_URL}/network"
        params = {
            "_return_fields+": (
                "extattrs,comment,network_view,members,"
                "options,zone_associations"
            ),
            "_return_as_object": 1,
        }
        display_url = (
            f"{url}?_return_fields+=extattrs,comment,network_view,"
            f"members,options,zone_associations&_return_as_object=1"
        )
        print_request_panel(step_name, "GET", display_url)
        print_prompt("Press Enter to send request...")

        resp = self.session.get(url, params=params, timeout=30)

        if not resp.ok:
            print_response_panel(
                step_name, resp.status_code, error=resp.text[:200],
            )
            return

        data = resp.json()
        networks = data.get("result", [])

        # Show full raw response in the panel
        print_response_panel(
            step_name, resp.status_code, body=networks,
            summary=f"{len(networks)} subnets returned",
        )

        # Print a summary table of subnet data
        if networks:
            table = Table(
                title="Subnet Summary",
                border_style="blue",
                width=PANEL_WIDTH,
                show_lines=True,
            )
            table.add_column("Network", style="white", no_wrap=True)
            table.add_column("Location", style="cyan")
            table.add_column("Support Group", style="cyan")
            table.add_column("_ref", style="dim", no_wrap=False)

            for net in networks:
                extattrs = net.get("extattrs", {})
                location = extattrs.get("Location", {}).get("value", "—")
                support_group = extattrs.get(
                    "Support Group", {}
                ).get("value", "—")
                table.add_row(
                    net.get("network", "unknown"),
                    location,
                    support_group,
                    net.get("_ref", "—"),
                )

            print_arrow()
            console.print()
            console.print(table)

    def _step_ensure_ea(self) -> bool:
        """Step 2: Ensure ServiceNow_Reference EA exists.

        Returns:
            True if the EA exists or was created.
        """
        step_name = "Ensure EA"

        url = f"{BASE_URL}/extensibleattributedef"
        body = {
            "name": "ServiceNow_Reference",
            "type": "STRING",
            "comment": "Created by Infoblox workflow demo",
        }
        print_request_panel(step_name, "POST", url, body=body)
        print_prompt("Press Enter to send request...")

        resp = self.session.post(url, json=body, timeout=10)

        if resp.status_code == 201:
            print_response_panel(
                step_name, resp.status_code, body=resp.json(),
                summary="EA created",
            )
            return True
        elif resp.status_code == 400 and "already exists" in resp.text.lower():
            print_response_panel(
                step_name, resp.status_code, body=resp.json(),
                summary="EA already exists",
            )
            return True
        else:
            print_response_panel(
                step_name, resp.status_code, error=resp.text[:200],
            )
            return False

    def _step_get_subnets(self) -> Optional[List[Dict[str, Any]]]:
        """Step 3: Retrieve the target subnet with Extensible Attributes.

        Returns:
            List of network objects, or None on failure.
        """
        step_name = "Get Subnet"

        url = f"{BASE_URL}/network"
        params = {
            "network": TARGET_NETWORK,
            "_return_fields+": "extattrs",
            "_return_as_object": 1,
        }
        display_url = (
            f"{url}?network={TARGET_NETWORK}"
            f"&_return_fields+=extattrs&_return_as_object=1"
        )
        print_request_panel(step_name, "GET", display_url)
        print_prompt("Press Enter to send request...")

        resp = self.session.get(url, params=params, timeout=30)

        if not resp.ok:
            print_response_panel(
                step_name, resp.status_code, error=resp.text[:200],
            )
            return None

        data = resp.json()
        networks = data.get("result", [])

        if not networks:
            print_response_panel(
                step_name, resp.status_code, body=data,
                error=f"Subnet {TARGET_NETWORK} not found",
            )
            return None

        # Build a summarised response for display
        net = networks[0]
        ea_names = list(net.get("extattrs", {}).keys()) or ["(none)"]
        display_body: Dict[str, Any] = {
            "network": net.get("network"),
            "extattrs": ea_names,
        }

        print_response_panel(
            step_name, resp.status_code, body=display_body,
            summary=f"Subnet {TARGET_NETWORK} found",
        )
        return networks

    def _step_next_available_ip(
        self, network_ref: str, network_cidr: str
    ) -> Optional[str]:
        """Step 4: Get next available IP from a subnet.

        Args:
            network_ref: The _ref of the network object.
            network_cidr: The CIDR notation for display.

        Returns:
            The next available IP address, or None on failure.
        """
        step_name = "Next Avail IP"

        url = f"{BASE_URL}/{network_ref}"
        params = {"_function": "next_available_ip"}
        body = {"num": 1}
        display_url = f"{url}?_function=next_available_ip"
        print_request_panel(step_name, "POST", display_url, body=body)
        print_prompt("Press Enter to send request...")

        resp = self.session.post(url, params=params, json=body, timeout=10)

        if not resp.ok:
            print_response_panel(
                step_name, resp.status_code, error=resp.text[:200],
            )
            return None

        data = resp.json()
        ips = data.get("ips", [])

        if not ips:
            print_response_panel(
                step_name, resp.status_code, body=data,
                error="No IPs returned",
            )
            return None

        print_response_panel(
            step_name, resp.status_code, body=data,
            summary=f"IP: {ips[0]}",
        )
        return ips[0]

    def _step_reserve_ip(self, ip_address: str, snow_ref: str) -> Optional[str]:
        """Step 5: Reserve an IP address with a ServiceNow reference EA.

        Args:
            ip_address: The IP address to reserve.
            snow_ref: The ServiceNow reference value.

        Returns:
            The _ref of the created fixedaddress, or None on failure.
        """
        step_name = "Reserve IP"

        # Generate a random locally-administered MAC address
        random_mac: str = "02:00:00:{:02X}:{:02X}:{:02X}".format(
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
        )

        url = f"{BASE_URL}/fixedaddress"
        body = {
            "ipv4addr": ip_address,
            "mac": random_mac,
            "match_client": "MAC_ADDRESS",
            "comment": f"Reserved by ServiceNow - {snow_ref}",
            "extattrs": {
                "ServiceNow_Reference": {"value": snow_ref},
            },
        }
        print_request_panel(step_name, "POST", url, body=body)
        print_prompt("Press Enter to send request...")

        resp = self.session.post(url, json=body, timeout=10)

        if not resp.ok:
            print_response_panel(
                step_name, resp.status_code, error=resp.text[:200],
            )
            return None

        fixed_ref = resp.json()
        print_response_panel(
            step_name, resp.status_code, body={"_ref": fixed_ref},
            summary=f"Reserved {ip_address}",
        )
        return fixed_ref

    # -------------------------------------------------------------------------
    # Main runner
    # -------------------------------------------------------------------------

    def run(self) -> None:
        """Run the complete workflow with sequential display."""
        console.print()
        console.print(Panel(
            "[bold white]Infoblox IP Provisioning Workflow[/bold white]\n"
            f"[dim]Target: {BASE_URL}[/dim]",
            border_style="blue",
            padding=(1, 2),
            width=PANEL_WIDTH,
        ))

        # Auth: cert first, then basic fallback
        print_prompt("Press Enter to start workflow...")

        cert_ok = self._step_cert_auth()

        if not cert_ok:
            print_prompt("Press Enter to continue...")
            basic_ok = self._step_basic_auth()
            if not basic_ok:
                return
        print_prompt("Press Enter to continue...")

        # List all subnets (field discovery)
        self._step_list_all_subnets()
        print_prompt("Press Enter to continue...")

        # Step 2: Ensure EA
        if not self._step_ensure_ea():
            return
        print_prompt("Press Enter to continue...")

        # Step 3: Get target subnet
        networks = self._step_get_subnets()
        if not networks:
            return
        print_prompt("Press Enter to continue...")

        # Use the target subnet
        first_network = networks[0]
        network_ref = first_network["_ref"]
        network_cidr = first_network.get("network", "unknown")

        # Step 4: Next available IP
        ip_address = self._step_next_available_ip(network_ref, network_cidr)
        if ip_address is None:
            return
        print_prompt("Press Enter to continue...")

        # Step 5: Reserve IP
        fixed_ref = self._step_reserve_ip(ip_address, DEMO_SNOW_REFERENCE)
        if fixed_ref is None:
            return

        # Final summary
        print_arrow()
        console.print()
        console.print(Panel(
            f"[bold green]Workflow Complete[/bold green]\n\n"
            f"  Subnet:     [white]{network_cidr}[/white]\n"
            f"  IP Address: [white]{ip_address}[/white]\n"
            f"  SNOW Ref:   [white]{DEMO_SNOW_REFERENCE}[/white]\n"
            f"  Fixed Ref:  [dim]{fixed_ref}[/dim]",
            border_style="green",
            padding=(1, 2),
            width=PANEL_WIDTH,
        ))
        console.print()


# =============================================================================
# MAIN
# =============================================================================


def main() -> None:
    """Entry point for the workflow demo."""
    runner = WorkflowRunner()
    runner.run()


if __name__ == "__main__":
    main()
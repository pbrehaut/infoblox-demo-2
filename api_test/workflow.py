"""
Infoblox WAPI workflow demonstration with animated terminal UI.

Demonstrates the ServiceNow-to-Infoblox IP provisioning flow
with a two-panel rich terminal display showing workflow progress
and live HTTP request/response detail.

Steps:
    0. Authenticate (cert-first, basic auth fallback)
    1. Ensure ServiceNow_Reference EA exists
    2. Retrieve IP subnets with Extensible Attributes
    3. Get next available IP from a subnet
    4. Reserve the IP with a ServiceNow reference EA
"""

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

requests.packages.urllib3.disable_warnings()

# =============================================================================
# CONFIGURATION
# =============================================================================

INFOBLOX_HOST: str = "10.10.10.213"
WAPI_VERSION: str = "v2.13.7"
BASE_URL: str = f"https://{INFOBLOX_HOST}/wapi/{WAPI_VERSION}"

CLIENT_CERT_FILE: Path = Path("client.cert.pem")
CLIENT_KEY_FILE: Path = Path("client.key.pem")

DEMO_SNOW_REFERENCE: str = "SNOW-INC0012345"

STEP_DELAY: float = 2.0
RESPONSE_DELAY: float = 1.5

# =============================================================================
# LOGGING (minimal — rich handles the display)
# =============================================================================

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

console = Console()


# =============================================================================
# WORKFLOW STEP TRACKING
# =============================================================================


class StepStatus(Enum):
    """Status of a workflow step."""

    PENDING = "pending"
    ACTIVE = "active"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class HttpDetail:
    """Captures HTTP request/response detail for display."""

    method: str = ""
    url: str = ""
    request_body: Optional[Dict[str, Any]] = None
    response_status: Optional[int] = None
    response_body: Optional[Any] = None
    error_message: Optional[str] = None


@dataclass
class WorkflowStep:
    """A single step in the workflow."""

    name: str
    description: str
    status: StepStatus = StepStatus.PENDING
    http_detail: Optional[HttpDetail] = None
    result_summary: Optional[str] = None


@dataclass
class WorkflowState:
    """Tracks the overall workflow state for rendering."""

    steps: List[WorkflowStep] = field(default_factory=list)
    active_step_index: int = -1
    title: str = "Infoblox IP Provisioning Workflow"


# =============================================================================
# RENDERING
# =============================================================================

STATUS_ICONS: Dict[StepStatus, str] = {
    StepStatus.PENDING: "[dim]○[/dim]",
    StepStatus.ACTIVE: "[bold green]●[/bold green]",
    StepStatus.SUCCESS: "[green]✓[/green]",
    StepStatus.FAILED: "[red]✗[/red]",
    StepStatus.SKIPPED: "[yellow]–[/yellow]",
}


def render_workflow_panel(state: WorkflowState) -> Panel:
    """Render the left-hand workflow progress panel.

    Args:
        state: Current workflow state.

    Returns:
        A rich Panel showing step status.
    """
    lines = Text()
    lines.append("\n")

    for i, step in enumerate(state.steps):
        icon = STATUS_ICONS[step.status]
        if step.status == StepStatus.ACTIVE:
            lines.append(f"  {icon} ", style="bold green")
            lines.append(f"{step.name}\n", style="bold green")
            lines.append(f"    {step.description}\n", style="dim green")
        elif step.status == StepStatus.SUCCESS:
            lines.append(f"  {icon} ", style="green")
            lines.append(f"{step.name}\n", style="green")
            if step.result_summary:
                lines.append(f"    {step.result_summary}\n", style="dim")
        elif step.status == StepStatus.FAILED:
            lines.append(f"  {icon} ", style="red")
            lines.append(f"{step.name}\n", style="red")
        elif step.status == StepStatus.SKIPPED:
            lines.append(f"  {icon} ", style="yellow")
            lines.append(f"{step.name}\n", style="dim yellow")
        else:
            lines.append(f"  {icon} ", style="dim")
            lines.append(f"{step.name}\n", style="dim")

        lines.append("\n")

    return Panel(
        lines,
        title="[bold]Workflow[/bold]",
        border_style="blue",
        width=30,
    )


def render_detail_panel(state: WorkflowState) -> Panel:
    """Render the right-hand HTTP detail panel.

    Args:
        state: Current workflow state.

    Returns:
        A rich Panel showing HTTP request/response details.
    """
    if state.active_step_index < 0:
        content = Text("\n  Waiting to start...\n", style="dim")
        return Panel(content, title="[bold]Detail[/bold]", border_style="blue")

    step = state.steps[state.active_step_index]
    lines = Text()
    lines.append("\n")

    if step.http_detail is None:
        lines.append(f"  {step.description}\n", style="dim")
        return Panel(
            lines,
            title=f"[bold]{step.name}[/bold]",
            border_style="green" if step.status == StepStatus.ACTIVE else "blue",
        )

    detail = step.http_detail

    # Request
    if detail.method and detail.url:
        lines.append("  REQUEST\n", style="bold cyan")
        lines.append(f"  {detail.method} ", style="bold yellow")
        lines.append(f"{detail.url}\n\n", style="white")

    if detail.request_body is not None:
        lines.append("  Request Body:\n", style="bold cyan")
        body_json = json.dumps(detail.request_body, indent=2)
        for line in body_json.split("\n"):
            lines.append(f"  {line}\n", style="white")
        lines.append("\n")

    # Response
    if detail.response_status is not None:
        status = detail.response_status
        status_style = "bold green" if 200 <= status < 300 else "bold red"
        lines.append("  RESPONSE\n", style="bold cyan")
        lines.append(f"  Status: ", style="bold cyan")
        lines.append(f"{status}\n\n", style=status_style)

        if detail.response_body is not None:
            lines.append("  Response Body:\n", style="bold cyan")
            if isinstance(detail.response_body, (dict, list)):
                body_json = json.dumps(detail.response_body, indent=2)
                # Truncate long responses for display
                body_lines = body_json.split("\n")
                if len(body_lines) > 20:
                    body_lines = body_lines[:18] + ["  ...", f"  ({len(body_lines) - 18} more lines)"]
                for line in body_lines:
                    lines.append(f"  {line}\n", style="white")
            else:
                lines.append(f"  {detail.response_body}\n", style="white")

    if detail.error_message:
        lines.append(f"\n  Error: {detail.error_message}\n", style="bold red")

    lines.append("\n")

    border = "green" if step.status == StepStatus.SUCCESS else (
        "red" if step.status == StepStatus.FAILED else "yellow"
    )

    return Panel(
        lines,
        title=f"[bold]{step.name}[/bold]",
        border_style=border,
    )


def build_layout(state: WorkflowState) -> Layout:
    """Build the two-panel layout.

    Args:
        state: Current workflow state.

    Returns:
        A rich Layout with workflow and detail panels.
    """
    layout = Layout()
    layout.split_row(
        Layout(render_workflow_panel(state), name="workflow", ratio=1),
        Layout(render_detail_panel(state), name="detail", ratio=3),
    )
    return layout


# =============================================================================
# WORKFLOW RUNNER
# =============================================================================


class WorkflowRunner:
    """Runs the Infoblox workflow with animated terminal display.

    Attributes:
        state: The current workflow state for rendering.
        session: The authenticated requests session.
        live: The rich Live display context.
    """

    def __init__(self) -> None:
        self.state = WorkflowState()
        self.session: Optional[requests.Session] = None
        self.live: Optional[Live] = None

        # Define all workflow steps
        self.state.steps = [
            WorkflowStep("Auth (cert)", "Attempting certificate authentication"),
            WorkflowStep("Auth (basic)", "Basic authentication fallback"),
            WorkflowStep("Ensure EA", "Create ServiceNow_Reference EA"),
            WorkflowStep("Get Subnets", "Retrieve IP subnets with EAs"),
            WorkflowStep("Next Avail IP", "Get next available IP address"),
            WorkflowStep("Reserve IP", "Reserve IP with ServiceNow reference"),
        ]

    def _refresh(self) -> None:
        """Refresh the live display."""
        if self.live:
            self.live.update(build_layout(self.state))

    def _activate_step(self, index: int) -> None:
        """Mark a step as active and update the display.

        Args:
            index: The step index to activate.
        """
        self.state.active_step_index = index
        self.state.steps[index].status = StepStatus.ACTIVE
        self._refresh()
        time.sleep(STEP_DELAY)

    def _complete_step(self, index: int, summary: Optional[str] = None) -> None:
        """Mark a step as successful.

        Args:
            index: The step index to complete.
            summary: Optional summary text to display.
        """
        self.state.steps[index].status = StepStatus.SUCCESS
        if summary:
            self.state.steps[index].result_summary = summary
        self._refresh()
        time.sleep(RESPONSE_DELAY)

    def _fail_step(self, index: int) -> None:
        """Mark a step as failed.

        Args:
            index: The step index to mark as failed.
        """
        self.state.steps[index].status = StepStatus.FAILED
        self._refresh()
        time.sleep(RESPONSE_DELAY)

    def _skip_step(self, index: int) -> None:
        """Mark a step as skipped.

        Args:
            index: The step index to skip.
        """
        self.state.steps[index].status = StepStatus.SKIPPED
        self._refresh()

    def _show_request(
        self, index: int, method: str, url: str, body: Optional[Dict[str, Any]] = None
    ) -> None:
        """Display the HTTP request details for a step.

        Args:
            index: The step index.
            method: HTTP method (GET, POST, etc.).
            url: The request URL.
            body: Optional request body dict.
        """
        step = self.state.steps[index]
        step.http_detail = HttpDetail(method=method, url=url, request_body=body)
        self._refresh()
        time.sleep(STEP_DELAY)

    def _show_response(
        self, index: int, status: int, body: Optional[Any] = None, error: Optional[str] = None
    ) -> None:
        """Display the HTTP response details for a step.

        Args:
            index: The step index.
            status: HTTP response status code.
            body: Optional response body.
            error: Optional error message.
        """
        step = self.state.steps[index]
        if step.http_detail:
            step.http_detail.response_status = status
            step.http_detail.response_body = body
            step.http_detail.error_message = error
        self._refresh()
        time.sleep(RESPONSE_DELAY)

    # -------------------------------------------------------------------------
    # Step implementations
    # -------------------------------------------------------------------------

    def _step_cert_auth(self) -> bool:
        """Step 0: Attempt certificate authentication.

        Returns:
            True if cert auth succeeded.
        """
        index = 0
        self._activate_step(index)

        self.session = requests.Session()

        if not CLIENT_CERT_FILE.exists() or not CLIENT_KEY_FILE.exists():
            detail = HttpDetail(error_message="Certificate files not found")
            self.state.steps[index].http_detail = detail
            self._fail_step(index)
            return False

        self.session.cert = (
            str(CLIENT_CERT_FILE.resolve()),
            str(CLIENT_KEY_FILE.resolve()),
        )
        self.session.verify = False

        url = f"{BASE_URL}/grid"
        self._show_request(index, "GET", url)

        try:
            resp = self.session.get(url, timeout=10)
            self._show_response(index, resp.status_code, resp.json() if resp.ok else resp.text[:200])

            if resp.ok:
                self._complete_step(index, "Certificate auth OK")
                return True
            else:
                self._fail_step(index)
                return False
        except requests.exceptions.RequestException as exc:
            self._show_response(index, 0, error=str(exc)[:200])
            self._fail_step(index)
            return False

    def _step_basic_auth(self) -> bool:
        """Step 1: Fall back to basic authentication.

        Pauses the live display to prompt for credentials.

        Returns:
            True if basic auth succeeded.
        """
        index = 1
        self._activate_step(index)

        # Pause live display for input
        if self.live:
            self.live.stop()

        console.print()
        console.print("[bold yellow]  Certificate auth failed — falling back to basic auth[/bold yellow]")
        console.print()
        username = input("  Username: ")
        # TODO: Switch back to getpass.getpass() for terminal use
        password = input("  Password: ")
        console.print()

        # Resume live display
        if self.live:
            self.live.start()

        self.session.cert = None
        self.session.auth = (username, password)
        self.session.verify = False

        url = f"{BASE_URL}/grid"
        self._show_request(index, "GET", url, body={"auth": f"{username}:****"})

        try:
            resp = self.session.get(url, timeout=10)

            if resp.ok:
                self._show_response(index, resp.status_code, resp.json())
                self._complete_step(index, f"Authenticated as {username}")
                return True
            else:
                self._show_response(
                    index, resp.status_code, error=resp.text[:200]
                )
                self._fail_step(index)
                return False
        except requests.exceptions.RequestException as exc:
            self._show_response(index, 0, error=str(exc)[:200])
            self._fail_step(index)
            return False

    def _step_ensure_ea(self) -> bool:
        """Step 2: Ensure ServiceNow_Reference EA exists.

        Returns:
            True if the EA exists or was created.
        """
        index = 2
        self._activate_step(index)

        url = f"{BASE_URL}/extensibleattributedef"
        body = {
            "name": "ServiceNow_Reference",
            "type": "STRING",
            "comment": "Created by Infoblox workflow demo",
        }
        self._show_request(index, "POST", url, body=body)

        resp = self.session.post(url, json=body, timeout=10)

        if resp.status_code == 201:
            self._show_response(index, resp.status_code, resp.json())
            self._complete_step(index, "EA created")
            return True
        elif resp.status_code == 400 and "already exists" in resp.text.lower():
            self._show_response(index, resp.status_code, resp.json())
            self._complete_step(index, "EA already exists")
            return True
        else:
            self._show_response(
                index, resp.status_code, error=resp.text[:200]
            )
            self._fail_step(index)
            return False

    def _step_get_subnets(self) -> Optional[List[Dict[str, Any]]]:
        """Step 3: Retrieve IP subnets with Extensible Attributes.

        Returns:
            List of network objects, or None on failure.
        """
        index = 3
        self._activate_step(index)

        url = f"{BASE_URL}/network"
        params = {"_return_fields+": "extattrs", "_return_as_object": 1}
        display_url = f"{url}?_return_fields+=extattrs&_return_as_object=1"
        self._show_request(index, "GET", display_url)

        resp = self.session.get(url, params=params, timeout=30)

        if not resp.ok:
            self._show_response(index, resp.status_code, error=resp.text[:200])
            self._fail_step(index)
            return None

        data = resp.json()
        networks = data.get("result", [])

        # Build a summarised response for display
        summary_list = []
        for net in networks[:6]:
            ea_names = list(net.get("extattrs", {}).keys()) or ["(none)"]
            summary_list.append({
                "network": net.get("network"),
                "extattrs": ea_names,
            })

        display_body = {
            "count": len(networks),
            "networks": summary_list,
        }
        if len(networks) > 6:
            display_body["note"] = f"... and {len(networks) - 6} more"

        self._show_response(index, resp.status_code, display_body)
        self._complete_step(index, f"{len(networks)} subnets found")
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
        index = 4
        self._activate_step(index)

        url = f"{BASE_URL}/{network_ref}"
        params = {"_function": "next_available_ip"}
        body = {"num": 1}
        display_url = f"{url}?_function=next_available_ip"
        self._show_request(index, "POST", display_url, body=body)

        resp = self.session.post(url, params=params, json=body, timeout=10)

        if not resp.ok:
            self._show_response(index, resp.status_code, error=resp.text[:200])
            self._fail_step(index)
            return None

        data = resp.json()
        ips = data.get("ips", [])

        self._show_response(index, resp.status_code, data)

        if not ips:
            self.state.steps[index].http_detail.error_message = "No IPs returned"
            self._fail_step(index)
            return None

        self._complete_step(index, f"IP: {ips[0]}")
        return ips[0]

    def _step_reserve_ip(self, ip_address: str, snow_ref: str) -> Optional[str]:
        """Step 5: Reserve an IP address with a ServiceNow reference EA.

        Args:
            ip_address: The IP address to reserve.
            snow_ref: The ServiceNow reference value.

        Returns:
            The _ref of the created fixedaddress, or None on failure.
        """
        index = 5
        self._activate_step(index)

        url = f"{BASE_URL}/fixedaddress"
        body = {
            "ipv4addr": ip_address,
            "mac": "00:00:00:00:00:00",
            "match_client": "RESERVED",
            "comment": f"Reserved by ServiceNow - {snow_ref}",
            "extattrs": {
                "ServiceNow_Reference": {"value": snow_ref},
            },
        }
        self._show_request(index, "POST", url, body=body)

        resp = self.session.post(url, json=body, timeout=10)

        if not resp.ok:
            self._show_response(
                index, resp.status_code, error=resp.text[:200]
            )
            self._fail_step(index)
            return None

        fixed_ref = resp.json()
        self._show_response(index, resp.status_code, {"_ref": fixed_ref})
        self._complete_step(index, f"Reserved {ip_address}")
        return fixed_ref

    # -------------------------------------------------------------------------
    # Main runner
    # -------------------------------------------------------------------------

    def run(self) -> None:
        """Run the complete workflow with animated display."""
        console.print()
        console.print(
            Panel(
                "[bold white]Infoblox IP Provisioning Workflow[/bold white]\n"
                f"[dim]Target: {BASE_URL}[/dim]",
                border_style="blue",
                padding=(1, 2),
            )
        )
        console.print()
        time.sleep(1)

        with Live(
            build_layout(self.state),
            console=console,
            refresh_per_second=4,
            screen=False,
        ) as live:
            self.live = live

            # Auth: cert first, then basic fallback
            cert_ok = self._step_cert_auth()

            if cert_ok:
                self._skip_step(1)
            else:
                basic_ok = self._step_basic_auth()
                if not basic_ok:
                    return

            # Step 2: Ensure EA
            if not self._step_ensure_ea():
                return

            # Step 3: Get subnets
            networks = self._step_get_subnets()
            if not networks:
                return

            # Pick first subnet
            first_network = networks[0]
            network_ref = first_network["_ref"]
            network_cidr = first_network.get("network", "unknown")

            # Step 4: Next available IP
            ip_address = self._step_next_available_ip(network_ref, network_cidr)
            if ip_address is None:
                return

            # Step 5: Reserve IP
            fixed_ref = self._step_reserve_ip(ip_address, DEMO_SNOW_REFERENCE)
            if fixed_ref is None:
                return

            self.live = None

        # Final summary
        console.print()
        console.print(
            Panel(
                f"[bold green]Workflow Complete[/bold green]\n\n"
                f"  Subnet:     [white]{network_cidr}[/white]\n"
                f"  IP Address: [white]{ip_address}[/white]\n"
                f"  SNOW Ref:   [white]{DEMO_SNOW_REFERENCE}[/white]\n"
                f"  Fixed Ref:  [dim]{fixed_ref}[/dim]",
                border_style="green",
                padding=(1, 2),
            )
        )
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
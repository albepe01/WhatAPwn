import os

from textual.app import ComposeResult
from textual.screen import Screen
from textual.containers import Container, Horizontal, Vertical
from dashboard.utils.data_loader import get_available_programs
from textual.widgets import Button, Select, Static, Log, ListView, ListItem, RichLog
from textual.message import Message
from dashboard.utils.crash_metadata import load_crash_metadata
from dashboard.utils.crash_loader import list_crashes_for_program, find_crash_dir


class VulnsView(Screen):
    """
    Screen responsible for displaying vulnerability-related information.

    Layout:
        - Header with controls (EXEC, TRIAGE, selectors, etc.)
        - Left side: 3 log panels (Payload, Exploitable, ASAN/QASAN)
        - Right side: crash list with metadata

    Each crash selection updates the three log panels dynamically.
    """

    CSS_PATH = "style.tcss"

    def __init__(self, program: str, mode: str, name: str | None = None):
        super().__init__(name=name)

        # Currently selected program and execution mode
        self.program = program
        self.mode = mode

        # Stores metadata for crashes currently displayed in the UI
        # This list is aligned with ListView items (excluding header)
        self.crash_metadata: list[dict] = []

    def compose(self) -> ComposeResult:
        """
        Builds the UI layout of the screen.
        """

        # --- HEADER (same structure as main app) ---
        yield Container(
            Static("🧬 WhatAPwn Dashboard", classes="header"),

            Container(
                Horizontal(
                    Button("EXEC", id="exec_btn", variant="success", classes="menu-btn"),
                    Button("TRIAGE", id="triage_btn", variant="warning", classes="menu-btn"),

                    # Mode selector (GrayBox / BlackBox)
                    Select(
                        id="mode_select",
                        options=[("GrayBox", "GrayBox"), ("BlackBox", "BlackBox")],
                        value=self.mode,
                        classes="menu",
                    ),

                    # Program selector
                    Select(
                        id="program_select",
                        options=[(p, p) for p in get_available_programs()],
                        value=self.program,
                        classes="menu",
                    ),

                    # Input type selector
                    Select(
                        id="input_select",
                        options=[("Input->STDIN", "stdin"), ("Input->FILE", "file")],
                        value="stdin",
                        classes="menu"
                    ),

                    Button("LOGS", id="logs_btn", variant="primary", classes="menu-btn"),
                    Button("METRICS", id="metrics_btn", variant="primary", classes="menu-btn"),

                    classes="controls",
                ),
                classes="controls-box",
            ),

            # --- MAIN CONTAINER: 4 AREAS ---
            Container(
                Horizontal(
                    # LEFT SIDE: 3 stacked log panels
                    Vertical(
                        Container(
                            RichLog(id="vuln_log1", classes="vuln-log", markup=True),
                            id="area1_box",
                            classes="vuln-subbox",
                        ),
                        Container(
                            RichLog(id="vuln_log2", classes="vuln-log", markup=True),
                            id="area2_box",
                            classes="vuln-subbox",
                        ),
                        Container(
                            RichLog(id="vuln_log3", classes="vuln-log", markup=True),
                            id="area3_box",
                            classes="vuln-subbox",
                        ),
                        id="vuln_left_column",
                    ),

                    # RIGHT SIDE: crash list
                    Container(
                        ListView(id="crash_list"),
                        id="area4_box",
                        classes="vuln-subbox",
                    ),

                    id="vuln_split",
                ),
                id="vuln_outer_box",
            ),
        )

    # ------------------------------------------------------------------ UTILITIES

    def _read_text_file(self, path: str) -> str | None:
        """
        Safely reads a text file.

        Returns:
            - File content if readable
            - None if file does not exist
            - Error string if reading fails
        """
        if not path or not os.path.isfile(path):
            return None

        try:
            with open(path, "r", errors="replace") as f:
                return f.read()
        except Exception as e:
            return f"[!] Error reading {path}: {e}"

    def _show_crash_contents(self, meta_index: int) -> None:
        """
        Displays crash-related data in the three log panels:

            Area 1 → Payload (xxd dump)
            Area 2 → exploitable*.log
            Area 3 → asan*/qasan*.log

        Expected directory structure:
            results/<program>/<fuzzer>/<variant>/<crash_name>/
        """

        # Validate index
        if meta_index < 0 or meta_index >= len(self.crash_metadata):
            return

        meta = self.crash_metadata[meta_index]

        # Example: "aflpp_default/aflpp_default/crash-001"
        full_name = meta["name"]

        crash_dir = find_crash_dir(self.program, full_name, "results")

        # Retrieve log widgets
        log1 = self.query_one("#vuln_log1", RichLog)
        log2 = self.query_one("#vuln_log2", RichLog)
        log3 = self.query_one("#vuln_log3", RichLog)

        # Clear previous content
        log1.clear()
        log2.clear()
        log3.clear()

        # Validate crash directory
        if not os.path.isdir(crash_dir):
            msg = f"[!] Crash directory not found:\n{crash_dir}"
            log1.write(msg)
            log2.write(msg)
            log3.write(msg)
            return

        # Collect files inside crash directory
        files = [
            f for f in os.listdir(crash_dir)
            if os.path.isfile(os.path.join(crash_dir, f))
        ]

        # --- Identify relevant files ---

        # Payload (xxd dump)
        xxd_file = None
        for fname in files:
            lower = fname.lower()
            if lower.startswith("xxd") and lower.endswith(".log"):
                xxd_file = os.path.join(crash_dir, fname)
                break

        # Exploitable log
        exploitable_log = None
        for fname in files:
            lower = fname.lower()
            if lower.startswith("exploitable") and lower.endswith(".log"):
                exploitable_log = os.path.join(crash_dir, fname)
                break

        # ASAN / QASAN log
        asan_log = None
        for fname in files:
            lower = fname.lower()
            if (lower.startswith("asan") or lower.startswith("qasan")) and lower.endswith(".log"):
                asan_log = os.path.join(crash_dir, fname)
                break

        # --- Populate UI ---

        # Area 1: payload
        xxd_text = self._read_text_file(xxd_file) if xxd_file else None
        log1.write(xxd_text or f"[yellow]No payload file found in:\n{crash_dir}[/]")

        # Area 2: exploitable
        exp_text = self._read_text_file(exploitable_log) if exploitable_log else None
        log2.write(exp_text or f"[yellow]No exploitable log found in:\n{crash_dir}[/]")

        # Area 3: ASAN / QASAN
        asan_text = self._read_text_file(asan_log) if asan_log else None
        log3.write(asan_text or "[yellow]No ASAN/QASAN log found[/]")

    # ------------------------------------------------------------------ LIFECYCLE

    def on_mount(self) -> None:
        """
        Called when the screen is mounted.
        Initializes UI titles and populates the crash list.
        """

        # Set box titles
        self.query_one("#area1_box").border_title = "Payload"
        self.query_one("#area2_box").border_title = "Exploitable"
        self.query_one("#area3_box").border_title = "ASAN/QASAN"
        self.query_one("#area4_box").border_title = "Crashes"

        crash_list = self.query_one("#crash_list", ListView)

        crashes_raw = list_crashes_for_program(self.program)

        # --- Header ---
        header_text = (
            f"Analyzed crashes: {len(crashes_raw)}"
            if crashes_raw else
            "No crashes found"
        )

        header = ListItem(
            Static(header_text, classes="crash-label"),
            classes="crash-item crash-header-item",
        )
        header.can_focus = False
        crash_list.append(header)

        # --- Load metadata ---
        self.crash_metadata = load_crash_metadata(self.program)

        # Populate crash list
        for cr in self.crash_metadata:

            # Filter based on execution mode
            if self.mode == "BlackBox" and "-qemu" not in cr["name"]:
                continue
            if self.mode == "GrayBox" and "-qemu" in cr["name"]:
                continue

            # Build styled label
            title = (
                f"[{cr['classification_color']}]{cr['classification']}[/{cr['classification_color']}]"
                f"    "
                f"[{cr['vuln_color']}]{cr['vuln_abbr']}[/{cr['vuln_color']}]"
            )
            path = f"[#bbbbbb]{cr['name']}[/#bbbbbb]"
            text = f"{title}\n{path}"

            crash_list.append(
                ListItem(
                    Static(text, classes="crash-label"),
                    classes="crash-item",
                )
            )

    def on_select_changed(self, event: Select.Changed):
        """
        Handles changes in dropdown selectors (program / mode).
        Triggers full reload of crash list with updated filters.
        """

        # --- Update local state ---
        if event.select.id == "program_select":
            self.program = event.value
        elif event.select.id == "mode_select":
            self.mode = event.value
        else:
            return

        # Sync with main app state
        self.app.program = self.program
        self.app.mode = self.mode

        # Try updating main screen selectors
        try:
            self.app.query_one("#program_select").value = self.program
            self.app.query_one("#mode_select").value = self.mode
        except:
            pass

        # --- Reload crash list ---
        crash_list = self.query_one("#crash_list", ListView)
        crash_list.clear()

        all_meta = load_crash_metadata(self.program)

        # Apply filtering
        filtered = []
        for cr in all_meta:
            name = cr["name"]

            if self.mode == "BlackBox" and "-qemu" not in name:
                continue
            if self.mode == "GrayBox" and "-qemu" in name:
                continue

            filtered.append(cr)

        # --- Header ---
        header_text = (
            f"Analyzed crashes: {len(filtered)}"
            if filtered else
            "No crashes found"
        )

        header = ListItem(
            Static(header_text, classes="crash-label"),
            classes="crash-item crash-header-item",
        )
        header.can_focus = False
        crash_list.append(header)

        # Store filtered metadata
        self.crash_metadata = filtered

        # Populate list
        for cr in filtered:

            title = (
                f"[{cr['classification_color']}]{cr['classification']}[/{cr['classification_color']}]"
                f"    "
                f"[{cr['vuln_color']}]{cr['vuln_abbr']}[/{cr['vuln_color']}]"
            )
            path = f"[#bbbbbb]{cr['name']}[/#bbbbbb]"
            text = f"{title}\n{path}"

            crash_list.append(
                ListItem(
                    Static(text, classes="crash-label"),
                    classes="crash-item",
                )
            )

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """
        Handles selection inside the crash list.
        Updates UI highlighting and loads crash details.
        """

        if event.list_view.id != "crash_list":
            return

        items = list(event.list_view.children)
        index = items.index(event.item)

        # Prevent selecting header
        if index == 0:
            return

        # Reset previous highlighting
        for item in items:
            item.remove_class("crash-selected")
            item.remove_class("crash-previous")

        # Highlight current selection
        event.item.add_class("crash-selected")

        # Mark previous item (used for visual grouping)
        if index == 1:
            items[0].add_class("crash-previous")
        elif index > 1:
            items[index - 1].add_class("crash-previous")

        # Load crash data into panels
        meta_index = index - 1  # exclude header
        self._show_crash_contents(meta_index)

    # ------------------------------------------------------------------ BUTTONS

    def on_button_pressed(self, event) -> None:
        """
        Handles button interactions within the VULNS view.
        """

        if event.button.id == "metrics_btn":
            self.app.pop_screen()
            self.app.show_logs_view(False)
            return

        if event.button.id == "logs_btn":
            self.app.pop_screen()
            self.set_timer(0.001, lambda: self.app.show_logs_view(True))
            return

        # Delegate EXEC / TRIAGE handling to main app
        if event.button.id in {"exec_btn", "triage_btn"}:
            self.app.on_button_pressed(event)
            return
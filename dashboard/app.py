from textual.app import App, ComposeResult
from textual.containers import Horizontal, Container
from textual.widgets import Select, Button, DataTable, Static, Log
from textual.reactive import reactive
from dashboard.utils.fuzzer_stats_reader import get_latest_metrics
from dashboard.utils.data_loader import get_available_programs, get_fuzzer_columns
from dashboard.utils.fuzzer_stats_reader import DEFAULT_METRICS
from dashboard.vulns_view import VulnsView
import asyncio
import subprocess
from datetime import datetime
import textwrap


class WhatAPwnDashboard(App):
    """
    Main TUI application for the WhatAPwn dashboard.

    Responsibilities:
        - Manage UI layout and navigation (metrics, logs, vulns)
        - Launch fuzzing and triage processes
        - Periodically update metrics table
        - Stream subprocess output into the log console
    """

    CSS_PATH = "style.tcss"

    # Key bindings
    BINDINGS = [("q", "quit", "Quit")]

    # Reactive state variables (automatically trigger UI updates)
    mode = reactive("GrayBox")
    program = reactive("")
    showing_logs = reactive(False)
    input_mode = reactive("stdin")  # Determines input delivery mode (stdin vs file)

    def compose(self) -> ComposeResult:
        """
        Builds the main layout of the dashboard.
        """

        yield Container(
            Static("WhatAPwn Dashboard", classes="header"),

            # --- CONTROL BAR ---
            Container(
                Horizontal(
                    Button("EXEC", id="exec_btn", variant="success", classes="menu-btn"),
                    Button("TRIAGE", id="triage_btn", variant="warning", classes="menu-btn"),

                    # Mode selector (GrayBox / BlackBox)
                    Select(
                        id="mode_select",
                        options=[("GrayBox", "GrayBox"), ("BlackBox", "BlackBox")],
                        value="GrayBox",
                        classes="menu"
                    ),

                    # Program selector
                    Select(
                        id="program_select",
                        options=[("— Select a program —", "")] +
                                [(p, p) for p in get_available_programs()],
                        value="",
                        classes="menu"
                    ),

                    # Input mode selector (stdin vs file)
                    Select(
                        id="input_select",
                        options=[("Input->STDIN", "stdin"), ("Input->FILE", "file")],
                        value="stdin",
                        classes="menu"
                    ),

                    Button("LOGS", id="logs_btn", variant="primary", classes="menu-btn"),
                    Button("VULNS", id="vulns_btn", variant="primary", classes="menu-btn"),

                    classes="controls"
                ),
                classes="controls-box",
            ),

            # --- MAIN CONTENT AREA ---
            Container(
                # Left: splash screen or metrics table
                Container(
                    Container(
                        Static(self._load_ascii_art(), id="ascii_art"),
                        Static("Welcome to WhatAPwn!", id="welcome_line1"),
                        Static("To start, select a program to pwn!", id="welcome_line2"),
                        id="splash_wrapper",
                    ),
                    DataTable(id="metrics_table"),
                    id="table_wrapper",
                ),

                # Right: log console
                Container(
                    Log(id="log_console"),
                    id="log_wrapper",
                ),

                id="content_box",
                classes="table-box"
            ),
        )

    def _load_ascii_art(self) -> str:
        """
        Returns embedded ASCII art.
        Using inline text avoids filesystem dependencies.
        """
        return textwrap.dedent(r"""                                                                                                                                      
 __      __ __            __     _____ __________              
/  \    /  \  |__ _____ _/  |_  /  _  \\______   \__  _  ______  
\   \/\/   /  |  \\__  \\   __\/  /_\  \|     ___/\ \/ \/ /    \ 
 \        /|   Y  \/ __ \|  | /    |    \    |     \     /   |  \
  \__/\  / |___|  (____  /__| \____|__  /____|      \/\_/|___|  /
       \/       \/     \/             \/                      \/ 
            """).strip("\n")

    def _update_dashboard_view(self):
        """
        Controls visibility of splash screen, table, and logs.

        Priority:
            1. Logs view (if enabled)
            2. Splash screen (if no program selected)
            3. Metrics table
        """

        splash = self.query_one("#splash_wrapper")
        table = self.query_one("#metrics_table")
        log_wrapper = self.query_one("#log_wrapper")
        table_wrapper = self.query_one("#table_wrapper")

        if self.showing_logs:
            # Show logs only
            try:
                splash.display = False
                table.display = False
            except Exception:
                pass

            table_wrapper.display = False
            log_wrapper.display = True
            return

        # Normal view
        log_wrapper.display = False
        table_wrapper.display = True

        if not self.program:
            splash.display = True
            table.display = False
        else:
            splash.display = False
            table.display = True

    async def live_update(self):
        """
        Periodically refresh metrics every 10 seconds.
        Runs as a background worker.
        """
        while True:
            if (not self.showing_logs) and self.program:
                self.update_metrics_table()
            await asyncio.sleep(10)

    async def stream_to_log(self, process):
        """
        Streams stdout of a subprocess into the log console in real time.
        """
        log_console = self.query_one("#log_console", Log)

        while True:
            line = await asyncio.to_thread(process.stdout.readline)
            if not line:
                break

            if not line.endswith("\n"):
                line += "\n"

            log_console.write(line)

    def on_mount(self):
        """
        Called when the app starts.
        Initializes UI and launches background workers.
        """
        self.query_one("#log_wrapper").display = False
        self._update_dashboard_view()

        if self.program:
            self.refresh_table()

        self.run_worker(self.live_update(), exclusive=True)

    def show_logs_view(self, value: bool = True):
        """
        Toggles log view visibility.
        """
        self.showing_logs = value
        self._update_dashboard_view()

        if self.showing_logs:
            self.notify("🪵 Log console opened")
        else:
            self.notify("📊 Back to table")

    def on_select_changed(self, event: Select.Changed):
        """
        Handles dropdown changes (mode, program, input mode).
        """

        if event.select.id == "mode_select":
            self.mode = event.value

        elif event.select.id == "program_select":
            self.program = event.value

        elif event.select.id == "input_select":
            self.input_mode = event.value

        self._update_dashboard_view()

        if self.program and not self.showing_logs:
            self.refresh_table()

    def apply_input_mode(self, cmd):
        """
        Modifies command arguments depending on input mode.
        Adds '--file' if file-based input is selected.
        """
        if self.input_mode == "file":
            cmd.append("--file")
        return cmd

    def on_button_pressed(self, event):
        """
        Handles all button actions (EXEC, TRIAGE, LOGS, VULNS).
        """

        log_console = self.query_one("#log_console", Log)

        if event.button.id == "exec_btn":
            if not self.program:
                self.notify("⚠️ Select a program first")
                return

            cmd = ["python3", "run_fuzzers.py", self.program]

            if self.mode == "BlackBox":
                cmd.append("--qemu")

            cmd = self.apply_input_mode(cmd)

            mode_label = "GrayBox" if self.mode == "GrayBox" else "BlackBox (QEMU)"
            self.notify(f"🚀 Running fuzzers for {self.program} in {mode_label} mode...")

            log_console.write(f"[EXEC] {' '.join(cmd)}")

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )

            asyncio.create_task(self.stream_to_log(process))

        elif event.button.id == "triage_btn":
            if not self.program:
                self.notify("⚠️ Select a program first")
                return

            cmd = ["python3", "triaging/run_triage.py", self.program, "--dedup"]

            if self.mode == "BlackBox":
                cmd.append("--qemu")

            cmd = self.apply_input_mode(cmd)

            self.notify(f"🧪 Running triage for {self.program}...")
            log_console.write(f"[TRIAGE] {' '.join(cmd)}")

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )

            asyncio.create_task(self.stream_to_log(process))

        elif event.button.id == "logs_btn":
            self.show_logs_view(not self.showing_logs)

        elif event.button.id == "vulns_btn":
            self.push_screen(VulnsView(program=self.program, mode=self.mode))

    def refresh_table(self):
        """
        Initializes the metrics table structure (columns + empty rows).
        """
        if not self.program:
            return

        table = self.query_one("#metrics_table", DataTable)
        table.clear(columns=True)

        fuzzers = get_fuzzer_columns(self.program, self.mode)
        table.add_columns("Metric", *fuzzers)

        for m in DEFAULT_METRICS:
            table.add_row(m, *["-" for _ in fuzzers])

    def update_metrics_table(self):
        """
        Updates metrics table with latest data from fuzzers.
        Also logs update events in the console.
        """
        if not self.program:
            return

        table = self.query_one("#metrics_table", DataTable)
        log_console = self.query_one("#log_console", Log)

        data = get_latest_metrics(self.program, self.mode)

        try:
            width = log_console.size.width or 100
        except Exception:
            width = 100

        column_map = {
            col_key: col.label.plain.strip()
            for col_key, col in table.columns.items()
            if col_key != list(table.columns.keys())[0]
        }

        log_console.write(
            textwrap.fill(
                f"[{datetime.now().strftime('%H:%M:%S')}] Update metrics: {list(data.keys())}",
                width=width,
            )
        )

        for row_key in table.rows.keys():
            row_data = table.get_row(row_key)
            if not row_data:
                continue

            metric_name = row_data[0]

            for col_key, fuzzer_name in column_map.items():
                value = data.get(fuzzer_name, {}).get(metric_name, "-")

                try:
                    table.update_cell(row_key, col_key, value)
                except Exception as e:
                    err_line = f"[!] Error updating ({metric_name}, {fuzzer_name}): {e}"
                    log_console.write(textwrap.fill(err_line, width=width))

        self.query_one(".header", Static).update(
            f"WhatAPwn Dashboard (last update: {datetime.now().strftime('%H:%M:%S')})"
        )


if __name__ == "__main__":
    app = WhatAPwnDashboard()
    app.run()
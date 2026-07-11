import os
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from webbrowser import open as open_browser

from alert import alert_user
from cloud import upload_scan_result
from scan_engine import scan_files
from security_suite import build_security_summary
from vpn_manager import VPNManager


SOURCE_DIR = Path(__file__).resolve().parent
BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", SOURCE_DIR))
APP_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else SOURCE_DIR
PAGES_DIR = BUNDLE_DIR / "pages"
RESOURCES_DIR = BUNDLE_DIR / "resources"
BEDROCK_TEXTURE = RESOURCES_DIR / "bedrock_texture.png"
VPN_MANAGER = VPNManager(APP_DIR)


COLORS = {
    "bg": "#090b0f",
    "panel": "#11151c",
    "panel_alt": "#161b24",
    "panel_soft": "#1d2430",
    "border": "#2b3442",
    "text": "#f4f7fb",
    "muted": "#aab6c5",
    "dim": "#6f7d8d",
    "blue": "#3b82f6",
    "green": "#24c081",
    "amber": "#f0b429",
    "red": "#ef5b5b",
}


def get_app_sections() -> list[str]:
    return ["Dashboard", "Scan", "VPN", "Hardening", "Report"]


def get_whole_pc_scan_roots() -> list[str]:
    if os.name != "nt":
        return ["/"]

    roots = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        if os.path.exists(root):
            roots.append(root)
    return roots or [os.path.expanduser("~")]


def run_scan() -> None:
    target_path = os.path.expanduser("~")
    results = scan_files(target_path)
    threats = [item for item in results if item[1] == "Threat Detected"]
    if threats:
        for file_path, status, _ in threats:
            alert_user(file_path)
            upload_scan_result(file_path, status)
        messagebox.showwarning("Scan complete", f"Detected {len(threats)} suspicious file(s).")
    else:
        messagebox.showinfo("Scan complete", "No suspicious files detected.")


def open_dashboard_page(page_name: str) -> None:
    page_path = PAGES_DIR / page_name
    if page_path.exists():
        open_browser(page_path.as_uri())
    else:
        messagebox.showerror("Missing page", f"The page {page_name} could not be found.")


def launch_vpn() -> None:
    VPN_MANAGER.connect()


class BedrockWallApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("BEDROCK WALL")
        self.geometry("1080x700")
        self.minsize(980, 640)
        self.configure(bg=COLORS["bg"])

        self.active_section = ""
        self.nav_buttons: dict[str, tk.Button] = {}
        self.section_frames: dict[str, tk.Frame] = {}
        self.animation_tick = 0
        self.scan_running = False
        self.vpn_busy = False

        self._configure_styles()
        self._build_background()
        self._build_shell()
        self._build_dashboard()
        self._build_scan_page()
        self._build_vpn_page()
        self._build_hardening_page()
        self._build_report_page()

        self._show_section("Dashboard")
        self._append_history("Workspace ready")
        self._start_live_updates()
        self._animate()

    def _configure_styles(self) -> None:
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure(
            "BW.Horizontal.TProgressbar",
            troughcolor=COLORS["panel_soft"],
            background=COLORS["green"],
            bordercolor=COLORS["border"],
            lightcolor=COLORS["green"],
            darkcolor=COLORS["green"],
        )

    def _build_background(self) -> None:
        self.bedrock_texture = None
        if BEDROCK_TEXTURE.exists():
            try:
                self.bedrock_texture = tk.PhotoImage(file=str(BEDROCK_TEXTURE))
            except tk.TclError:
                self.bedrock_texture = None
        self.backdrop = tk.Canvas(self, bg=COLORS["bg"], highlightthickness=0)
        self.backdrop.place(x=0, y=0, relwidth=1, relheight=1)
        self.backdrop.bind("<Configure>", lambda _event: self._draw_backdrop())

    def _draw_backdrop(self) -> None:
        self.backdrop.delete("backdrop")
        width = max(self.backdrop.winfo_width(), 1)
        height = max(self.backdrop.winfo_height(), 1)
        self._paint_bedrock_texture(self.backdrop, width, height, "backdrop")
        for x in range(0, width, 64):
            self.backdrop.create_line(x, 0, x, height, fill="#10141b", tags="backdrop")
        for y in range(0, height, 64):
            self.backdrop.create_line(0, y, width, y, fill="#10141b", tags="backdrop")
        self.backdrop.create_rectangle(0, 0, width, 90, fill="#0d1118", outline="", stipple="gray50", tags="backdrop")

    def _paint_bedrock_texture(self, canvas: tk.Canvas, width: int, height: int, tag: str) -> None:
        if not self.bedrock_texture:
            canvas.create_rectangle(0, 0, width, height, fill=COLORS["bg"], outline="", tags=tag)
            return

        tile_width = max(self.bedrock_texture.width(), 1)
        tile_height = max(self.bedrock_texture.height(), 1)
        for y in range(0, height, tile_height):
            for x in range(0, width, tile_width):
                canvas.create_image(x, y, image=self.bedrock_texture, anchor="nw", tags=tag)
        canvas.create_rectangle(0, 0, width, height, fill="#05070d", outline="", stipple="gray75", tags=tag)

    def _build_shell(self) -> None:
        self.shell = tk.Frame(self, bg=COLORS["bg"])
        self.shell.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.shell.grid_columnconfigure(0, weight=1)
        self.shell.grid_rowconfigure(1, weight=1)

        top = tk.Frame(self.shell, bg=COLORS["bg"])
        top.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 10))
        top.grid_columnconfigure(1, weight=1)

        brand = tk.Frame(top, bg=COLORS["bg"])
        brand.grid(row=0, column=0, sticky="w")
        tk.Label(
            brand,
            text="BEDROCK WALL",
            fg=COLORS["text"],
            bg=COLORS["bg"],
            font=("Segoe UI", 24, "bold"),
        ).pack(anchor="w")
        tk.Label(
            brand,
            text="Security operations console",
            fg=COLORS["muted"],
            bg=COLORS["bg"],
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(2, 0))

        self.status_var = tk.StringVar(value="Ready")
        self.status_pill = tk.Label(
            top,
            textvariable=self.status_var,
            fg=COLORS["green"],
            bg=COLORS["panel"],
            font=("Segoe UI", 10, "bold"),
            padx=16,
            pady=8,
            highlightthickness=1,
            highlightbackground=COLORS["border"],
        )
        self.status_pill.grid(row=0, column=2, sticky="e")

        self.activity_canvas = tk.Canvas(top, height=6, bg=COLORS["bg"], highlightthickness=0)
        self.activity_canvas.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(16, 0))

        body = tk.Frame(self.shell, bg=COLORS["bg"])
        body.grid(row=1, column=0, sticky="nsew", padx=24, pady=(0, 24))
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self.nav_frame = tk.Frame(
            body,
            bg=COLORS["panel"],
            width=188,
            highlightthickness=1,
            highlightbackground=COLORS["border"],
        )
        self.nav_frame.grid(row=0, column=0, sticky="nsw", padx=(0, 14))
        self.nav_frame.grid_propagate(False)

        tk.Label(
            self.nav_frame,
            text="SECTIONS",
            fg=COLORS["dim"],
            bg=COLORS["panel"],
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", padx=16, pady=(18, 8))

        for section in get_app_sections():
            button = tk.Button(
                self.nav_frame,
                text=section,
                anchor="w",
                fg=COLORS["muted"],
                bg=COLORS["panel"],
                activeforeground=COLORS["text"],
                activebackground=COLORS["panel_soft"],
                bd=0,
                padx=16,
                pady=12,
                font=("Segoe UI", 10, "bold"),
                command=lambda name=section: self._show_section(name),
            )
            button.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[section] = button

        tk.Frame(self.nav_frame, bg=COLORS["border"], height=1).pack(fill="x", padx=16, pady=16)
        self.nav_vpn_label = tk.Label(
            self.nav_frame,
            text="VPN: checking",
            fg=COLORS["muted"],
            bg=COLORS["panel"],
            font=("Segoe UI", 9),
            justify="left",
        )
        self.nav_vpn_label.pack(anchor="w", padx=16)

        self.nav_texture_canvas = tk.Canvas(
            self.nav_frame,
            height=104,
            bg=COLORS["panel"],
            highlightthickness=0,
        )
        self.nav_texture_canvas.pack(side="bottom", fill="x", padx=10, pady=(0, 10))
        self.nav_texture_canvas.bind("<Configure>", lambda _event: self._draw_nav_texture())

        self.content = tk.Frame(
            body,
            bg=COLORS["panel"],
            highlightthickness=1,
            highlightbackground=COLORS["border"],
        )
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        for section in get_app_sections():
            frame = tk.Frame(self.content, bg=COLORS["panel"])
            frame.grid(row=0, column=0, sticky="nsew")
            frame.grid_columnconfigure(0, weight=1)
            self.section_frames[section] = frame

    def _build_dashboard(self) -> None:
        frame = self.section_frames["Dashboard"]
        self._section_title(frame, "Dashboard", "Live posture, VPN readiness, and recent activity.")

        actions = tk.Frame(frame, bg=COLORS["panel"])
        actions.grid(row=1, column=0, sticky="ew", padx=22, pady=(4, 14))
        self._action_button(actions, "Open Site", lambda: open_dashboard_page("index.html"), COLORS["green"]).pack(side="left")
        self._action_button(actions, "Security Site", lambda: open_dashboard_page("security.html"), COLORS["blue"]).pack(side="left", padx=(10, 0))
        self._action_button(actions, "VPN Site", lambda: open_dashboard_page("vpn.html"), COLORS["amber"]).pack(side="left", padx=(10, 0))

        metrics = tk.Frame(frame, bg=COLORS["panel"])
        metrics.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 16))
        for column in range(3):
            metrics.grid_columnconfigure(column, weight=1)

        self.risk_value = self._metric_card(metrics, 0, "Risk Score", "0/100", COLORS["green"])
        self.threat_value = self._metric_card(metrics, 1, "Threats", "0", COLORS["blue"])
        self.vpn_value = self._metric_card(metrics, 2, "VPN", "Checking", COLORS["amber"])

        main = tk.Frame(frame, bg=COLORS["panel"])
        main.grid(row=3, column=0, sticky="nsew", padx=22, pady=(0, 22))
        main.grid_columnconfigure(0, weight=2)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)

        history_panel = self._panel(main)
        history_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        tk.Label(
            history_panel,
            text="Activity",
            fg=COLORS["text"],
            bg=COLORS["panel_alt"],
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", padx=16, pady=(14, 8))
        self.dashboard_history = tk.Text(
            history_panel,
            height=10,
            bg="#0b0f15",
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            bd=0,
            padx=12,
            pady=10,
            font=("Consolas", 10),
        )
        self.dashboard_history.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        pulse_panel = self._panel(main)
        pulse_panel.grid(row=0, column=1, sticky="nsew")
        tk.Label(
            pulse_panel,
            text="Signal",
            fg=COLORS["text"],
            bg=COLORS["panel_alt"],
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", padx=16, pady=(14, 8))
        self.signal_canvas = tk.Canvas(pulse_panel, height=220, bg=COLORS["panel_alt"], highlightthickness=0)
        self.signal_canvas.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    def _build_scan_page(self) -> None:
        frame = self.section_frames["Scan"]
        self._section_title(frame, "Threat Scan", "Scan the current user profile, or approve a whole-PC scan.")

        controls = tk.Frame(frame, bg=COLORS["panel"])
        controls.grid(row=1, column=0, sticky="ew", padx=22, pady=(8, 12))
        self.scan_button = self._action_button(controls, "Scan User Profile", self.start_scan, COLORS["blue"])
        self.scan_button.pack(side="left")
        self.full_scan_button = self._action_button(controls, "Scan Whole PC", self.start_whole_pc_scan, COLORS["amber"])
        self.full_scan_button.pack(side="left", padx=(10, 0))
        self.scan_status = tk.Label(
            controls,
            text="Ready",
            fg=COLORS["green"],
            bg=COLORS["panel"],
            font=("Segoe UI", 10, "bold"),
        )
        self.scan_status.pack(side="left", padx=14)

        self.scan_progress = ttk.Progressbar(
            frame,
            mode="indeterminate",
            style="BW.Horizontal.TProgressbar",
        )
        self.scan_progress.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 14))

        scan_body = tk.Frame(frame, bg=COLORS["panel"])
        scan_body.grid(row=3, column=0, sticky="nsew", padx=22, pady=(0, 22))
        scan_body.grid_columnconfigure(0, weight=1)
        scan_body.grid_rowconfigure(1, weight=1)
        frame.grid_rowconfigure(3, weight=1)

        self.scan_canvas = tk.Canvas(scan_body, height=96, bg="#0b0f15", highlightthickness=1, highlightbackground=COLORS["border"])
        self.scan_canvas.grid(row=0, column=0, sticky="ew", pady=(0, 12))

        self.scan_output = tk.Text(
            scan_body,
            bg="#0b0f15",
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            bd=0,
            padx=12,
            pady=10,
            font=("Consolas", 10),
        )
        self.scan_output.grid(row=1, column=0, sticky="nsew")
        self.scan_output.insert(tk.END, "No scan has run in this session.\n")

    def _build_vpn_page(self) -> None:
        frame = self.section_frames["VPN"]
        self._section_title(frame, "VPN Gateway", "Use a local profile or fetch a public relay with available network.")

        controls = tk.Frame(frame, bg=COLORS["panel"])
        controls.grid(row=1, column=0, sticky="ew", padx=22, pady=(8, 14))
        self.fetch_vpn_button = self._action_button(controls, "Fetch Available Profile", self.fetch_vpn_profile, COLORS["blue"])
        self.fetch_vpn_button.pack(side="left")
        self.connect_vpn_button = self._action_button(controls, "Connect with VPN", self.connect_vpn, COLORS["green"])
        self.connect_vpn_button.pack(side="left", padx=(10, 0))

        vpn_panel = self._panel(frame)
        vpn_panel.grid(row=2, column=0, sticky="nsew", padx=22, pady=(0, 22))
        frame.grid_rowconfigure(2, weight=1)

        self.vpn_status_label = tk.Label(
            vpn_panel,
            text="VPN status: idle",
            fg=COLORS["text"],
            bg=COLORS["panel_alt"],
            font=("Segoe UI", 13, "bold"),
        )
        self.vpn_status_label.pack(anchor="w", padx=16, pady=(16, 8))

        self.vpn_info = tk.Text(
            vpn_panel,
            height=12,
            bg="#0b0f15",
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            bd=0,
            padx=12,
            pady=10,
            font=("Consolas", 10),
        )
        self.vpn_info.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _build_hardening_page(self) -> None:
        frame = self.section_frames["Hardening"]
        self._section_title(frame, "Hardening", "Core Windows protections to keep BEDROCK WALL effective.")

        grid = tk.Frame(frame, bg=COLORS["panel"])
        grid.grid(row=1, column=0, sticky="nsew", padx=22, pady=(8, 22))
        grid.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        items = [
            ("Windows Update", "Keep security updates enabled and current.", COLORS["green"]),
            ("Microsoft Defender", "Real-time protection should stay enabled.", COLORS["blue"]),
            ("Firewall Profiles", "Domain, private, and public profiles should be on.", COLORS["amber"]),
            ("Account Hygiene", "Use a strong password or Windows Hello.", COLORS["green"]),
            ("VPN Profile", "Keep a trusted local or fetched OpenVPN profile available.", COLORS["blue"]),
        ]

        for row, (name, detail, accent) in enumerate(items):
            item = self._panel(grid)
            item.grid(row=row, column=0, sticky="ew", pady=(0, 10))
            item.grid_columnconfigure(1, weight=1)
            tk.Frame(item, bg=accent, width=4).grid(row=0, column=0, rowspan=2, sticky="nsw")
            tk.Label(
                item,
                text=name,
                fg=COLORS["text"],
                bg=COLORS["panel_alt"],
                font=("Segoe UI", 11, "bold"),
            ).grid(row=0, column=1, sticky="w", padx=14, pady=(12, 2))
            tk.Label(
                item,
                text=detail,
                fg=COLORS["muted"],
                bg=COLORS["panel_alt"],
                font=("Segoe UI", 10),
            ).grid(row=1, column=1, sticky="w", padx=14, pady=(0, 12))

    def _build_report_page(self) -> None:
        frame = self.section_frames["Report"]
        self._section_title(frame, "Report", "Latest scan summary and hardening signals.")
        self.report_box = tk.Text(
            frame,
            bg="#0b0f15",
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            bd=0,
            padx=14,
            pady=12,
            font=("Consolas", 10),
            highlightthickness=1,
            highlightbackground=COLORS["border"],
        )
        self.report_box.grid(row=1, column=0, sticky="nsew", padx=22, pady=(8, 22))
        frame.grid_rowconfigure(1, weight=1)
        self.report_box.insert(tk.END, "Run a security scan to generate a report.\n")

    def _section_title(self, parent: tk.Frame, title: str, subtitle: str) -> None:
        header = tk.Frame(parent, bg=COLORS["panel"])
        header.grid(row=0, column=0, sticky="ew", padx=22, pady=(22, 6))
        header.grid_columnconfigure(0, weight=1)
        tk.Label(
            header,
            text=title,
            fg=COLORS["text"],
            bg=COLORS["panel"],
            font=("Segoe UI", 18, "bold"),
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            header,
            text=subtitle,
            fg=COLORS["muted"],
            bg=COLORS["panel"],
            font=("Segoe UI", 10),
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

    def _panel(self, parent: tk.Misc) -> tk.Frame:
        return tk.Frame(
            parent,
            bg=COLORS["panel_alt"],
            highlightthickness=1,
            highlightbackground=COLORS["border"],
        )

    def _metric_card(self, parent: tk.Frame, column: int, title: str, value: str, accent: str) -> tk.Label:
        card = self._panel(parent)
        card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0 if column == 2 else 8))
        tk.Frame(card, bg=accent, height=3).pack(fill="x")
        tk.Label(
            card,
            text=title.upper(),
            fg=COLORS["dim"],
            bg=COLORS["panel_alt"],
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", padx=14, pady=(12, 2))
        value_label = tk.Label(
            card,
            text=value,
            fg=COLORS["text"],
            bg=COLORS["panel_alt"],
            font=("Segoe UI", 20, "bold"),
        )
        value_label.pack(anchor="w", padx=14, pady=(0, 14))
        return value_label

    def _action_button(self, parent: tk.Misc, text: str, command, color: str) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            fg="#ffffff",
            bg=color,
            activeforeground="#ffffff",
            activebackground=color,
            bd=0,
            padx=16,
            pady=10,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
        )

    def _show_section(self, section: str) -> None:
        self.active_section = section
        self.section_frames[section].tkraise()
        for name, button in self.nav_buttons.items():
            if name == section:
                button.configure(bg=COLORS["panel_soft"], fg=COLORS["text"])
            else:
                button.configure(bg=COLORS["panel"], fg=COLORS["muted"])

    def _draw_nav_texture(self) -> None:
        canvas = self.nav_texture_canvas
        canvas.delete("all")
        width = max(canvas.winfo_width(), 1)
        height = max(canvas.winfo_height(), 1)
        self._paint_bedrock_texture(canvas, width, height, "nav_texture")
        canvas.create_rectangle(0, 0, width, height, outline=COLORS["border"])
        canvas.create_text(
            width // 2,
            height // 2,
            text="BEDROCK",
            fill=COLORS["text"],
            font=("Segoe UI", 13, "bold"),
        )

    def start_scan(self) -> None:
        self._start_scan_for_targets("User profile", [os.path.expanduser("~")])

    def start_whole_pc_scan(self) -> None:
        roots = get_whole_pc_scan_roots()
        if not roots:
            messagebox.showwarning("Scan", "No local drives were found to scan.")
            return
        if not self._confirm_whole_pc_scan(roots):
            self.scan_status.configure(text="Whole-PC scan cancelled", fg=COLORS["muted"])
            self._append_history("Whole-PC scan cancelled")
            return
        self._start_scan_for_targets("Whole PC", roots)

    def _confirm_whole_pc_scan(self, roots: list[str]) -> bool:
        drive_list = "\n".join(f"- {root}" for root in roots)
        return messagebox.askyesno(
            "Permission required",
            "BEDROCK WALL needs your permission to scan the whole PC.\n\n"
            "The scan will inspect file names and read files to calculate hashes on:\n"
            f"{drive_list}\n\n"
            "This can take a long time. Files and folders blocked by Windows permissions will be skipped.\n\n"
            "Allow whole-PC scan?",
            parent=self,
        )

    def _start_scan_for_targets(self, label: str, targets: list[str]) -> None:
        if self.scan_running:
            return
        self.scan_running = True
        self.scan_button.configure(state="disabled")
        self.full_scan_button.configure(state="disabled")
        self.scan_status.configure(text=f"Scanning {label.lower()}...", fg=COLORS["amber"])
        self.status_var.set("Scanning")
        self.scan_progress.start(12)
        self.scan_output.delete("1.0", tk.END)
        self.scan_output.insert(tk.END, f"Scope: {label}\n")
        self.scan_output.insert(tk.END, f"Targets: {'; '.join(targets)}\n")
        self.scan_output.insert(tk.END, "Scan started. Whole-PC scans can take a long time.\n")
        self._append_history(f"{label} scan started")
        threading.Thread(target=self._run_scan_worker, args=(targets,), daemon=True).start()

    def _run_scan_worker(self, targets: list[str]) -> None:
        try:
            summary = build_security_summary(targets)
            for item in summary["threats"]:
                alert_user(item["path"])
                upload_scan_result(item["path"], item["status"])
            self.after(0, lambda result=summary: self._finish_scan(result, None))
        except Exception as exc:
            self.after(0, lambda error=exc: self._finish_scan(None, error))

    def _finish_scan(self, summary: dict | None, error: Exception | None) -> None:
        self.scan_running = False
        self.scan_progress.stop()
        self.scan_button.configure(state="normal")
        self.full_scan_button.configure(state="normal")
        self.status_var.set("Ready")

        if error:
            self.scan_status.configure(text="Scan failed", fg=COLORS["red"])
            self.scan_output.insert(tk.END, f"\nError: {error}\n")
            self._append_history("Scan failed")
            messagebox.showerror("Scan failed", str(error))
            return

        if summary is None:
            return

        self.report_box.delete("1.0", tk.END)
        self.report_box.insert(tk.END, f"Target: {summary['target']}\n")
        self.report_box.insert(tk.END, f"Threats found: {summary['threat_count']}\n")
        self.report_box.insert(tk.END, f"Risk level: {summary['risk_level']}\n")
        self.report_box.insert(tk.END, f"Risk score: {summary['risk_score']}/100\n\n")
        self.report_box.insert(tk.END, "Hardening checks:\n")
        for check in summary["hardening_checks"]:
            self.report_box.insert(tk.END, f"- {check['name']}: {check['status']}\n")
        if summary["threats"]:
            self.report_box.insert(tk.END, "\nSuspicious files:\n")
            for item in summary["threats"][:12]:
                self.report_box.insert(tk.END, f"- {item['path']}\n")

        self.scan_output.delete("1.0", tk.END)
        self.scan_output.insert(tk.END, f"Threats found: {summary['threat_count']}\n")
        self.scan_output.insert(tk.END, f"Risk level: {summary['risk_level']}\n")
        self.scan_output.insert(tk.END, f"Risk score: {summary['risk_score']}/100\n")
        self.scan_status.configure(text="Scan complete", fg=COLORS["green"])
        self._append_history(f"Scan complete: {summary['threat_count']} threats, risk {summary['risk_score']}/100")
        self._update_security_score(summary["risk_score"], summary["threat_count"])

        if summary["threat_count"]:
            messagebox.showwarning("Scan complete", f"Detected {summary['threat_count']} suspicious file(s).")
        else:
            messagebox.showinfo("Scan complete", "No suspicious files detected.")

    def fetch_vpn_profile(self) -> None:
        if self.vpn_busy:
            return
        self.vpn_busy = True
        self.fetch_vpn_button.configure(state="disabled")
        self.connect_vpn_button.configure(state="disabled")
        self.status_var.set("Fetching VPN")
        self.vpn_status_label.configure(text="VPN status: fetching public relay", fg=COLORS["amber"])
        self.vpn_info.delete("1.0", tk.END)
        self.vpn_info.insert(tk.END, "Fetching provider connections...\n")
        threading.Thread(target=self._fetch_vpn_worker, daemon=True).start()

    def _fetch_vpn_worker(self) -> None:
        try:
            profile = VPN_MANAGER.fetch_profile_for_network_user()
            self.after(0, lambda fetched_profile=profile: self._finish_vpn_fetch(fetched_profile, None))
        except Exception as exc:
            self.after(0, lambda error=exc: self._finish_vpn_fetch(None, error))

    def _finish_vpn_fetch(self, profile: str | None, error: Exception | None) -> None:
        self.vpn_busy = False
        self.fetch_vpn_button.configure(state="normal")
        self.connect_vpn_button.configure(state="normal")
        self.status_var.set("Ready")

        if error:
            self.vpn_status_label.configure(text="VPN status: fetch failed", fg=COLORS["red"])
            self.vpn_info.insert(tk.END, f"Unable to fetch profile: {error}\n")
            self._append_history("VPN profile fetch failed")
            messagebox.showwarning("VPN", f"Unable to fetch a public VPN connection: {error}")
            self._update_vpn_status()
            return

        if not profile:
            self.vpn_status_label.configure(text="VPN status: no relay available", fg=COLORS["red"])
            self.vpn_info.insert(tk.END, "No public VPN connection with network access was available.\n")
            self._append_history("VPN fetch returned no relay")
            messagebox.showwarning("VPN", "No public VPN connection with network access was available.")
            self._update_vpn_status()
            return

        connection = VPN_MANAGER.last_provider_connection
        if connection:
            self.vpn_info.insert(tk.END, f"Fetched: {connection.display_name}\n")
            self.vpn_info.insert(tk.END, f"Cached profile: {profile}\n")
            self.vpn_info.insert(tk.END, f"{VPN_MANAGER.last_github_status}\n")
            messagebox.showinfo("VPN", f"Fetched VPN profile from {connection.display_name}.")
        else:
            self.vpn_info.insert(tk.END, f"Cached profile: {profile}\n")
            self.vpn_info.insert(tk.END, f"{VPN_MANAGER.last_github_status}\n")
            messagebox.showinfo("VPN", f"Fetched VPN profile: {profile}")
        self._append_history("VPN profile fetched")
        self._update_vpn_status()

    def connect_vpn(self) -> None:
        if self.vpn_busy:
            return

        openvpn = VPN_MANAGER.find_openvpn_executable()
        profile = VPN_MANAGER.find_profile()
        if openvpn and not profile:
            self.status_var.set("Fetching VPN")
            self.fetch_vpn_profile()
            self.after(400, self._connect_when_profile_ready)
            return

        self.status_var.set("Launching VPN")
        if VPN_MANAGER.connect():
            self._append_history("VPN connection launched")
        self.status_var.set("Ready")
        self._update_vpn_status()

    def _connect_when_profile_ready(self) -> None:
        if self.vpn_busy:
            self.after(400, self._connect_when_profile_ready)
            return
        if VPN_MANAGER.find_profile():
            self.connect_vpn()

    def _append_history(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        self.dashboard_history.insert(tk.END, f"[{timestamp}] {message}\n")
        self.dashboard_history.see(tk.END)

    def _update_security_score(self, score: int, threat_count: int | None = None) -> None:
        color = COLORS["green"]
        if score >= 70:
            color = COLORS["red"]
        elif score >= 30:
            color = COLORS["amber"]
        self.risk_value.configure(text=f"{score}/100", fg=color)
        if threat_count is not None:
            threat_color = COLORS["red"] if threat_count else COLORS["green"]
            self.threat_value.configure(text=str(threat_count), fg=threat_color)

    def _start_live_updates(self) -> None:
        self._update_vpn_status()
        self.after(3000, self._start_live_updates)

    def _update_vpn_status(self) -> None:
        openvpn = VPN_MANAGER.find_openvpn_executable()
        profile = VPN_MANAGER.find_profile()

        if openvpn and profile:
            label = "VPN status: ready"
            nav = "VPN: ready"
            color = COLORS["green"]
            profile_source = "fetched public relay" if profile == str(VPN_MANAGER.fetched_profile) else "local profile"
            body = [
                f"OpenVPN found: {openvpn}",
                f"Profile found: {profile}",
                f"Profile source: {profile_source}",
                VPN_MANAGER.last_github_status,
            ]
        elif openvpn:
            label = "VPN status: ready to fetch"
            nav = "VPN: fetch needed"
            color = COLORS["amber"]
            body = [
                f"OpenVPN found: {openvpn}",
                "No local or cached profile found.",
                "Fetch an available profile, or connect to fetch automatically.",
            ]
        else:
            label = "VPN status: OpenVPN missing"
            nav = "VPN: OpenVPN missing"
            color = COLORS["red"]
            body = [
                "OpenVPN was not found.",
                "Install OpenVPN or set OPENVPN_BIN to the executable path.",
                "Local profiles can be named vpn.ovpn, config.ovpn, or openvpn.ovpn.",
            ]

        if not self.vpn_busy:
            self.vpn_status_label.configure(text=label, fg=color)
            self.vpn_info.delete("1.0", tk.END)
            self.vpn_info.insert(tk.END, "\n".join(body) + "\n")

        self.nav_vpn_label.configure(text=nav, fg=color)
        self.vpn_value.configure(text=nav.replace("VPN: ", ""), fg=color)

    def _animate(self) -> None:
        self.animation_tick += 1
        self._animate_activity_bar()
        self._animate_signal()
        self._animate_scan_canvas()
        self.after(80, self._animate)

    def _animate_activity_bar(self) -> None:
        canvas = self.activity_canvas
        width = max(canvas.winfo_width(), 1)
        canvas.delete("all")
        canvas.create_rectangle(0, 2, width, 4, fill=COLORS["panel_soft"], outline="")
        span = 180
        x = (self.animation_tick * 9) % (width + span) - span
        canvas.create_rectangle(x, 1, x + span, 5, fill=COLORS["green"], outline="")
        canvas.create_rectangle(x + span + 18, 1, x + span + 64, 5, fill=COLORS["blue"], outline="")

    def _animate_signal(self) -> None:
        canvas = self.signal_canvas
        width = max(canvas.winfo_width(), 1)
        height = max(canvas.winfo_height(), 1)
        canvas.delete("all")
        self._paint_bedrock_texture(canvas, width, height, "signal_texture")
        mid = height // 2
        canvas.create_line(12, mid, width - 12, mid, fill=COLORS["border"])
        step = 18
        points = []
        for x in range(12, width - 12, step):
            phase = (x // step + self.animation_tick) % 8
            offset = [0, -18, -26, -10, 16, 24, 8, -6][phase]
            points.extend([x, mid + offset])
        if len(points) >= 4:
            canvas.create_line(*points, fill=COLORS["green"], width=2, smooth=True)
        canvas.create_text(16, 18, text="Monitoring", anchor="w", fill=COLORS["muted"], font=("Segoe UI", 9, "bold"))

    def _animate_scan_canvas(self) -> None:
        canvas = self.scan_canvas
        width = max(canvas.winfo_width(), 1)
        height = max(canvas.winfo_height(), 1)
        canvas.delete("all")
        self._paint_bedrock_texture(canvas, width, height, "scan_texture")
        for x in range(0, width, 48):
            canvas.create_line(x, 0, x, height, fill="#141a23")
        for y in range(0, height, 24):
            canvas.create_line(0, y, width, y, fill="#141a23")

        if self.scan_running:
            x = (self.animation_tick * 11) % max(width, 1)
            canvas.create_rectangle(x - 14, 0, x + 14, height, fill=COLORS["blue"], outline="")
            canvas.create_text(14, 14, text="Scanning", anchor="w", fill=COLORS["amber"], font=("Segoe UI", 9, "bold"))
        else:
            canvas.create_text(14, 14, text="Idle", anchor="w", fill=COLORS["muted"], font=("Segoe UI", 9, "bold"))


def main() -> None:
    app = BedrockWallApp()
    app.mainloop()


if __name__ == "__main__":
    main()

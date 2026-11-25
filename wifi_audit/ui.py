"""Tkinter-интерфейс: таблица инвентаризации с цветовыми статусами и журналом."""

from __future__ import annotations

import csv
import os
import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

from .engine import STATUS_ORDER, AuditEngine
from .inventory import InventoryError

_STATUS_COLORS = {
    "ok": {"background": "#C6EFCE", "foreground": "#0B5A1E"},
    "presence": {"background": "#FFEB9C", "foreground": "#6B5300"},
    "checking": {"background": "#FFEB9C", "foreground": "#6B5300"},
    "no_password": {"background": "#FFEB9C", "foreground": "#6B5300"},
    "fail": {"background": "#FFC7CE", "foreground": "#8A0010"},
    "absent": {"background": "#F2F2F2", "foreground": "#808080"},
    "unsupported": {"background": "#DDEBF7", "foreground": "#1F3F66"},
    "open": {"background": "#DDEBF7", "foreground": "#1F3F66"},
}

class AuditApp:
    def __init__(self, root: tk.Tk, engine: AuditEngine, monitor_wlan=None):
        self.root = root
        self.engine = engine
        self.monitor_wlan = monitor_wlan or engine.wlan
        self._monitor_shared = self.monitor_wlan is engine.wlan
        self._headers: list[str] = []
        self._password_idx: int | None = None
        self._columns_gen = -1
        self._cache: dict[str, tuple] = {}
        self._visible: set[str] = set()

        self._show_passwords = tk.BooleanVar(value=False)
        self._verify = tk.BooleanVar(value=engine.config.verify_passwords)
        self._interval = tk.StringVar(value=f"{engine.config.interval:g}")
        self._filter = tk.StringVar(value="Все")
        self._sort_signal = tk.BooleanVar(value=True)
        self._scan_queue: queue.Queue = queue.Queue()
        self._scan_busy = False
        self._scan_stage = ""
        self._monitor_on = False
        self._monitor_after = None
        self._monitor_interval = tk.StringVar(value="2")
        self._scan_entries: list = []
        self._scan_count = 0
        self._copy_after = None
        self._flash_until = 0.0
        self._flash_text = ""
        self._ok_seen: set[str] = set()
        self._found_cache: dict[str, tuple] = {}
        self._scan_found: dict[str, tuple] = {}
        self._scan_seen: dict[str, float] = {}
        self._scan_history_file: str | None = None

        self.root.title(f"Wi-Fi Inventory Audit — {os.path.basename(engine.inventory.path)}")
        root.geometry("1320x820")
        root.minsize(940, 520)
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._build_menu()
        self._build_widgets()
        self._rebuild_columns()
        self._ensure_scan_history()
        self.engine.log(f"Инвентаризация: {self.engine.inventory.path}")
        self._poll()

    # -- построение UI -----------------------------------------------------
    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Открыть CSV…", command=self.reload_csv)
        file_menu.add_command(label="Экспорт результата…", command=self.export_results)
        file_menu.add_command(label="Экспорт только подтверждённых…", command=self.export_confirmed)
        file_menu.add_command(label="Открыть папку с результатом", command=self._open_result_folder)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self._on_close)
        menubar.add_cascade(label="Файл", menu=file_menu)

        audit_menu = tk.Menu(menubar, tearoff=False)
        audit_menu.add_command(label="Запуск", command=self.start)
        audit_menu.add_command(label="Стоп", command=self.stop)
        audit_menu.add_separator()
        audit_menu.add_command(label="Перепроверить пароли", command=self.reset_checks)
        menubar.add_cascade(label="Аудит", menu=audit_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="О программе", command=self._about)
        menubar.add_cascade(label="Справка", menu=help_menu)

        self.root.config(menu=menubar)

    def _build_widgets(self) -> None:
        style = ttk.Style()
        style.configure("Treeview", rowheight=24, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

        outer = ttk.Frame(self.root, padding=(8, 6, 8, 6))
        outer.pack(fill="both", expand=True)

        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)

        inv_tab = ttk.Frame(self.notebook, padding=4)
        self.notebook.add(inv_tab, text="Инвентаризация")

        toolbar = ttk.Frame(inv_tab)
        toolbar.pack(fill="x", pady=(0, 4))

        self.btn_start = ttk.Button(toolbar, text="▶ Запуск", command=self.start, width=11)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(toolbar, text="■ Стоп", command=self.stop, width=9, state="disabled")
        self.btn_stop.pack(side="left", padx=(6, 12))

        ttk.Label(toolbar, text="Интервал, с:").pack(side="left")
        self.spin_interval = ttk.Spinbox(
            toolbar, from_=2, to=3600, width=5, textvariable=self._interval, command=self._apply_interval
        )
        self.spin_interval.pack(side="left", padx=(4, 14))
        self.spin_interval.bind("<Return>", lambda _e: self._apply_interval())
        self.spin_interval.bind("<FocusOut>", lambda _e: self._apply_interval())

        ttk.Checkbutton(
            toolbar, text="Проверять пароли", variable=self._verify, command=self._apply_verify
        ).pack(side="left", padx=(0, 10))
        ttk.Checkbutton(
            toolbar,
            text="Показывать пароли",
            variable=self._show_passwords,
            command=self._redraw_all,
        ).pack(side="left", padx=(0, 10))

        ttk.Button(toolbar, text="Перечитать CSV", command=self.reload_csv).pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="Сбросить проверки", command=self.reset_checks).pack(side="left", padx=(6, 0))

        ttk.Label(toolbar, text="Показывать:").pack(side="left", padx=(18, 4))
        self.cmb_filter = ttk.Combobox(
            toolbar,
            values=["Все", "Только подтверждённые", "Проблемы"],
            textvariable=self._filter,
            state="readonly",
            width=22,
        )
        self.cmb_filter.pack(side="left")
        self.cmb_filter.bind("<<ComboboxSelected>>", lambda _e: self._redraw_all())

        self.warning = tk.Label(
            outer,
            text="",
            anchor="w",
            justify="left",
            background="#FFC7CE",
            foreground="#8A0010",
            padx=8,
            pady=5,
            wraplength=1260,
        )

        table = ttk.Frame(inv_tab)
        table.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(table, show="headings", selectmode="browse")
        vsb = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)

        for key, colors in _STATUS_COLORS.items():
            self.tree.tag_configure(key, **colors)
        self.tree.bind("<ButtonRelease-1>", self._on_inventory_click)

        scan_tab = ttk.Frame(self.notebook, padding=4)
        self.notebook.add(scan_tab, text="Поиск сетей")
        self._build_scanner(scan_tab)

        self.found_tab = ttk.Frame(self.notebook, padding=4)
        self.notebook.add(self.found_tab, text="Найденные")
        self._build_found(self.found_tab)

        log_frame = ttk.LabelFrame(outer, text="Журнал", padding=4)
        log_frame.pack(fill="x", pady=(6, 0))
        self.log_text = tk.Text(log_frame, height=6, state="disabled", wrap="none", font=("Consolas", 9))
        log_vsb = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_vsb.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_vsb.pack(side="right", fill="y")

        self.status = ttk.Label(outer, text="", anchor="w")
        self.status.pack(fill="x", pady=(4, 0))
        self.results_hint = ttk.Label(
            outer, text=f"Результаты: {self.engine.results_dir}", foreground="#666666", anchor="w"
        )
        self.results_hint.pack(fill="x")

        self.root.bind("<F5>", lambda _e: self.start())
        self.root.bind("<Escape>", lambda _e: self.stop())

    def _build_scanner(self, parent: ttk.Frame) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill="x", pady=(0, 4))
        self.btn_scan = ttk.Button(bar, text="Сканировать", command=self.scan_networks, width=16)
        self.btn_scan.pack(side="left")
        self.btn_monitor = ttk.Button(
            bar, text="▶ Мониторинг", command=self.toggle_monitor, width=16
        )
        self.btn_monitor.pack(side="left", padx=(6, 0))
        ttk.Label(bar, text="Интервал, с:").pack(side="left", padx=(10, 2))
        ttk.Spinbox(
            bar, from_=2, to=300, width=4, textvariable=self._monitor_interval
        ).pack(side="left")
        self.btn_scan_export = ttk.Button(
            bar, text="Экспорт…", command=self.export_scan, width=12, state="disabled"
        )
        self.btn_scan_export.pack(side="left", padx=(10, 0))
        self.copy_status = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.copy_status, foreground="#0B5A1E").pack(side="right")
        ttk.Checkbutton(
            bar,
            text="Сначала сильные",
            variable=self._sort_signal,
            command=self._render_scan,
        ).pack(side="left", padx=(12, 0))
        self.scan_status = tk.StringVar(value="Нажмите «Сканировать» или включите мониторинг")
        ttk.Label(parent, textvariable=self.scan_status, anchor="w").pack(
            fill="x", pady=(0, 4)
        )

        table = ttk.Frame(parent)
        table.pack(fill="both", expand=True)
        self.scan_tree = ttk.Treeview(table, show="headings", selectmode="browse")
        vsb = ttk.Scrollbar(table, orient="vertical", command=self.scan_tree.yview)
        hsb = ttk.Scrollbar(table, orient="horizontal", command=self.scan_tree.xview)
        self.scan_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.scan_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)

        self._scan_columns = [
            ("ssid", "SSID", 200, "w"),
            ("bssid", "BSSID", 160, "w"),
            ("first_seen", "Обнаружена", 150, "center"),
            ("rssi", "RSSI", 60, "center"),
            ("dbm", "dBm", 65, "center"),
            ("channel", "Канал", 60, "center"),
            ("freq", "Частота, МГц", 95, "center"),
            ("band", "Диапазон", 80, "center"),
            ("security", "Защита", 140, "w"),
            ("phy", "Стандарт", 90, "center"),
            ("rate", "Макс. скорость", 100, "center"),
            ("beacon", "Beacon, мс", 85, "center"),
            ("bss", "Тип", 115, "w"),
            ("caps", "Возможности", 240, "w"),
        ]
        self.scan_tree.configure(columns=[c[0] for c in self._scan_columns])
        for key, title, width, anchor in self._scan_columns:
            self.scan_tree.heading(key, text=title)
            self.scan_tree.column(key, width=width, anchor=anchor, stretch=key in ("ssid", "caps"))
        self.scan_tree.bind("<ButtonRelease-1>", self._on_scan_click)

    def _build_found(self, parent: ttk.Frame) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill="x", pady=(0, 4))
        self.found_counts = tk.StringVar(value="Найдено за сеанс: 0")
        ttk.Label(bar, textvariable=self.found_counts).pack(side="left")
        ttk.Label(
            bar,
            text="зелёные — пароль подтверждён, красные — не подтверждён",
            foreground="#666666",
        ).pack(side="left", padx=(14, 0))
        self.found_file_var = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.found_file_var, foreground="#666666").pack(side="right")

        table = ttk.Frame(parent)
        table.pack(fill="both", expand=True)
        self.found_tree = ttk.Treeview(table, show="headings", selectmode="browse")
        vsb = ttk.Scrollbar(table, orient="vertical", command=self.found_tree.yview)
        hsb = ttk.Scrollbar(table, orient="horizontal", command=self.found_tree.xview)
        self.found_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.found_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)

        self._found_columns = [
            ("status", "Статус", 250, "w"),
            ("bssid", "BSSID", 160, "w"),
            ("ssid", "SSID", 200, "w"),
            ("password", "Пароль", 140, "w"),
            ("rssi", "RSSI", 60, "center"),
            ("first", "Обнаружена", 150, "center"),
            ("checked", "Проверено", 150, "center"),
            ("note", "Примечание", 220, "w"),
        ]
        self.found_tree.configure(columns=[c[0] for c in self._found_columns])
        for key, title, width, anchor in self._found_columns:
            self.found_tree.heading(key, text=title)
            self.found_tree.column(key, width=width, anchor=anchor, stretch=key in ("status", "note"))
        for key, colors in _STATUS_COLORS.items():
            self.found_tree.tag_configure(key, **colors)
        self.found_tree.bind("<ButtonRelease-1>", self._on_found_click)

    # -- колонки -----------------------------------------------------------
    def _rebuild_columns(self) -> None:
        self._ok_seen.clear()
        inventory = self.engine.inventory
        self._headers = list(inventory.headers)
        self._password_idx = (
            self._headers.index(inventory.password_column) if inventory.password_column in self._headers else None
        )
        columns = [f"c{i}" for i in range(len(self._headers))]
        columns += ["presence", "password", "status", "rssi", "first_seen", "last_seen", "note", "checked"]
        self.tree.configure(columns=columns)
        for i, header in enumerate(self._headers):
            self.tree.heading(f"c{i}", text=header)
            self.tree.column(f"c{i}", width=self._guess_width(header), anchor="w", stretch=False)
        extra = [
            ("presence", "Наличие", 80, "center"),
            ("password", "Проверка пароля", 150, "center"),
            ("status", "Статус", 260, "w"),
            ("rssi", "RSSI", 60, "center"),
            ("first_seen", "Обнаружена", 150, "center"),
            ("last_seen", "Последний раз", 150, "center"),
            ("note", "Примечание", 220, "w"),
            ("checked", "Проверено", 140, "center"),
        ]
        for key, title, width, anchor in extra:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor=anchor, stretch=key in ("status", "note"))
        self._columns_gen = self.engine.inventory_generation
        self._redraw_all()

    @staticmethod
    def _guess_width(header: str) -> int:
        h = header.lower()
        if "bssid" in h or "mac" in h or "мак" in h:
            return 170
        if "ssid" in h:
            return 210
        if "парол" in h or "pass" in h or "psk" in h:
            return 150
        if "инв" in h:
            return 80
        if "место" in h or "локац" in h:
            return 190
        return 130

    # -- обновление --------------------------------------------------------
    def _poll(self) -> None:
        try:
            self._drain_logs()
            self._drain_scan_queue()
            if self._scan_busy:
                prefix = "Мониторинг: " if self._monitor_on else ""
                self.scan_status.set(
                    prefix
                    + ("ожидание Wi-Fi адаптера…" if self._scan_stage == "waiting" else "сканирование…")
                )
            stats = self.engine.stats()
            if self.engine.inventory_generation != self._columns_gen:
                self._rebuild_columns()
            snapshot = self.engine.snapshot()
            self._apply_snapshot(snapshot)
            self._apply_found_snapshot()
            self._update_status(stats)
            self._update_warning(stats)
            self._sync_buttons(stats["running"])
        finally:
            self.root.after(100, self._poll)

    def _row_values(self, st: dict) -> tuple:
        values = []
        for i, header in enumerate(self._headers):
            value = st["values"].get(header, "")
            if i == self._password_idx and not self._show_passwords.get() and value:
                value = "•" * min(12, max(6, len(str(value))))
            values.append(value)
        presence = "да" if st["present"] else "нет"
        key = st["status_key"]
        if key == "ok":
            password = "подтверждён"
        elif key == "fail":
            password = "не подтверждён"
        elif key == "unsupported":
            password = "не проверяется"
        elif key == "open":
            password = "не требуется"
        elif key == "no_password":
            password = "нет в CSV"
        elif key == "checking":
            password = "проверяется…"
        else:
            password = "не проверялся"
        checked = ""
        if st.get("checked_at"):
            checked = datetime.fromtimestamp(st["checked_at"]).strftime("%d.%m.%Y %H:%M:%S")
        first_seen = ""
        if st.get("first_seen"):
            first_seen = datetime.fromtimestamp(st["first_seen"]).strftime("%d.%m.%Y %H:%M:%S")
        last_seen = ""
        if st.get("last_seen"):
            last_seen = datetime.fromtimestamp(st["last_seen"]).strftime("%d.%m.%Y %H:%M:%S")
        values += [
            presence,
            password,
            st["status_text"],
            "" if st.get("rssi") is None else st["rssi"],
            first_seen,
            last_seen,
            st.get("note", ""),
            checked,
        ]
        return tuple(values)

    def _apply_snapshot(self, snapshot: list[dict]) -> None:
        ordered = sorted(
            snapshot,
            key=lambda st: (STATUS_ORDER.get(st["status_key"], 9), st["index"]),
        )
        new_ok: list[str] = []
        for st in ordered:
            iid = str(st["index"])
            visible = self._matches_filter(st)
            values = self._row_values(st)
            tag = st["status_key"]
            cached = self._cache.get(iid)
            if cached is not None:
                if visible:
                    if iid not in self._visible:
                        self.tree.move(iid, "", "end")
                        self._visible.add(iid)
                    if cached != (values, tag):
                        self.tree.item(iid, values=values, tags=(tag,))
                        self._cache[iid] = (values, tag)
                elif iid in self._visible:
                    self.tree.detach(iid)
                    self._visible.discard(iid)
            elif visible:
                self.tree.insert("", "end", iid=iid, values=values, tags=(tag,))
                self._cache[iid] = (values, tag)
                self._visible.add(iid)
            if tag == "ok" and iid not in self._ok_seen:
                self._ok_seen.add(iid)
                if visible:
                    new_ok.append(iid)

        desired = [str(st["index"]) for st in ordered if self._matches_filter(st)]
        current = list(self.tree.get_children(""))
        if desired != current:
            for position, iid in enumerate(desired):
                if self.tree.exists(iid):
                    self.tree.move(iid, "", position)
        if new_ok:
            first = new_ok[0]
            if self.tree.exists(first) and first in self.tree.get_children(""):
                self.tree.see(first)

    def _matches_filter(self, st: dict) -> bool:
        mode = self._filter.get()
        key = st["status_key"]
        if mode == "Только подтверждённые":
            return key == "ok"
        if mode == "Проблемы":
            return key in ("fail", "absent", "no_password", "unsupported")
        return True

    def _redraw_all(self) -> None:
        for iid in list(self._cache):
            try:
                self.tree.delete(iid)
            except tk.TclError:
                pass
        self._cache.clear()
        self._visible.clear()
        if hasattr(self, "found_tree"):
            for iid in self.found_tree.get_children():
                self.found_tree.delete(iid)
            self._found_cache.clear()
        if self.engine.inventory_generation != self._columns_gen:
            self._rebuild_columns()

    # -- поиск сетей -------------------------------------------------------
    def toggle_monitor(self) -> None:
        if self._monitor_on:
            self._stop_monitor()
        else:
            self._start_monitor()

    def _start_monitor(self) -> None:
        if self._monitor_on:
            return
        self._monitor_on = True
        self.btn_monitor.configure(text="■ Стоп")
        self.scan_status.set("Мониторинг: запуск…")
        self._monitor_tick()

    def _stop_monitor(self) -> None:
        self._monitor_on = False
        self.btn_monitor.configure(text="▶ Мониторинг")
        if self._monitor_after is not None:
            try:
                self.root.after_cancel(self._monitor_after)
            except tk.TclError:
                pass
            self._monitor_after = None
        self.scan_status.set("Мониторинг остановлен")

    def _monitor_tick(self) -> None:
        self._monitor_after = None
        if not self._monitor_on:
            return
        if self._scan_busy:
            self._monitor_after = self.root.after(500, self._monitor_tick)
            return
        self.scan_networks()

    def _schedule_monitor_next(self) -> None:
        if not self._monitor_on:
            return
        try:
            interval = float(str(self._monitor_interval.get()).replace(",", "."))
        except ValueError:
            interval = 2.0
        interval = max(2.0, min(300.0, interval))
        if self._monitor_after is not None:
            try:
                self.root.after_cancel(self._monitor_after)
            except tk.TclError:
                pass
        self._monitor_after = self.root.after(int(interval * 1000), self._monitor_tick)

    def scan_networks(self) -> None:
        if self._scan_busy:
            return
        self._scan_busy = True
        self._scan_stage = "waiting"
        self.btn_scan.configure(state="disabled")
        prefix = "Мониторинг: " if self._monitor_on else ""
        self.scan_status.set(
            prefix + ("ожидание Wi-Fi адаптера…" if self._monitor_shared else "сканирование…")
        )
        wlan = self.monitor_wlan

        def work() -> None:
            try:
                if self._monitor_shared:
                    # Один адаптер: ждём паузы аудита.
                    with self.engine.wlan_lock:
                        self._scan_stage = "scanning"
                        wlan.scan(timeout=8.0)
                        entries = wlan.bss_list()
                else:
                    # Отдельный адаптер мониторинга: работаем независимо.
                    self._scan_stage = "scanning"
                    wlan.scan(timeout=8.0)
                    entries = wlan.bss_list()
                self._scan_queue.put((entries, None))
            except Exception as exc:  # noqa: BLE001 — результат уйдёт в UI
                self._scan_queue.put(([], exc))

        threading.Thread(target=work, name="wifi-scan", daemon=True).start()

    def _drain_scan_queue(self) -> None:
        try:
            entries, error = self._scan_queue.get_nowait()
        except queue.Empty:
            return
        self._scan_busy = False
        prefix = "Мониторинг: " if self._monitor_on else ""
        if error is not None:
            self.scan_status.set(prefix + f"ошибка: {error}")
            self.engine.log(f"Поиск сетей: {error}")
            self._schedule_monitor_next()
            return
        self._scan_entries = entries
        self._scan_count += 1
        new_count = self._remember_scan(entries)
        self._render_scan()
        self.scan_status.set(
            prefix + f"найдено: {len(entries)} (новых: {new_count})   "
            f"скан #{self._scan_count} в {datetime.now().strftime('%H:%M:%S')}"
        )
        self.engine.log(f"Поиск сетей: найдено {len(entries)}, новых {new_count}")
        self._schedule_monitor_next()
        self._sync_buttons(self.engine.running)

    def _ensure_scan_history(self) -> None:
        path = os.path.join(self.engine.results_dir, "scan_found.csv")
        if path != self._scan_history_file:
            self._scan_history_file = path
            self._scan_found = {}
            self._scan_seen = {}
            self._write_scan_found()

    def _write_scan_found(self) -> None:
        if not self._scan_history_file:
            return
        headers = [title for _key, title, _width, _anchor in self._scan_columns]
        try:
            os.makedirs(self.engine.results_dir, exist_ok=True)
            with open(self._scan_history_file, "w", encoding="utf-8-sig", newline="") as fh:
                writer = csv.writer(fh, delimiter=";")
                writer.writerow(headers)
                for values in self._scan_found.values():
                    writer.writerow(values)
        except OSError as exc:
            self.engine.log(f"Не удалось записать scan_found.csv: {exc}")

    def _remember_scan(self, entries: list) -> int:
        self._ensure_scan_history()
        now = time.time()
        new_count = 0
        for entry in entries:
            seen = self._scan_seen.get(entry.bssid)
            if seen is None:
                seen = now
                self._scan_seen[entry.bssid] = seen
            if entry.bssid in self._scan_found:
                continue
            self._scan_found[entry.bssid] = self._scan_values(entry, seen)
            new_count += 1
        if new_count:
            self._write_scan_found()
        return new_count

    def _apply_found_snapshot(self) -> None:
        snapshot = self.engine.found_snapshot()
        order = {"ok": 0, "fail": 1}
        snapshot.sort(key=lambda item: (order.get(item["status_key"], 2), item["first_seen"]))
        for item in snapshot:
            iid = item["bssid"]
            password = item["password"]
            if password and not self._show_passwords.get():
                password = "•" * min(12, max(6, len(password)))
            first_seen = datetime.fromtimestamp(item["first_seen"]).strftime("%d.%m.%Y %H:%M:%S")
            checked = (
                datetime.fromtimestamp(item["checked_at"]).strftime("%d.%m.%Y %H:%M:%S")
                if item["checked_at"]
                else ""
            )
            values = (
                item["status_text"],
                item["bssid"],
                item["ssid"],
                password,
                "" if item["rssi"] is None else item["rssi"],
                first_seen,
                checked,
                item["note"],
            )
            tag = item["status_key"]
            cached = self._found_cache.get(iid)
            if cached is None:
                self.found_tree.insert("", "end", iid=iid, values=values, tags=(tag,))
                self._found_cache[iid] = (values, tag)
            elif cached != (values, tag):
                self.found_tree.item(iid, values=values, tags=(tag,))
                self._found_cache[iid] = (values, tag)
        desired = [item["bssid"] for item in snapshot]
        current = list(self.found_tree.get_children(""))
        if desired != current:
            for position, iid in enumerate(desired):
                if self.found_tree.exists(iid):
                    self.found_tree.move(iid, "", position)
        ok = sum(1 for item in snapshot if item["status_key"] == "ok")
        fail = sum(1 for item in snapshot if item["status_key"] == "fail")
        self.found_counts.set(
            f"Найдено за сеанс: {len(snapshot)}   подтверждено: {ok}   не подтверждено: {fail}"
        )
        self.found_file_var.set(f"файл: {self.engine.found_path}")
        self.notebook.tab(self.found_tab, text=f"Найденные ({len(snapshot)})")

    def _on_found_click(self, event) -> None:
        if self.found_tree.identify_region(event.x, event.y) != "cell":
            return
        row = self.found_tree.identify_row(event.y)
        column = self.found_tree.identify_column(event.x)
        if not row or not column:
            return
        try:
            index = int(column.lstrip("#")) - 1
        except ValueError:
            return
        values = self.found_tree.item(row, "values")
        if 0 <= index < len(values):
            self._copy_text(str(values[index]))

    def _sorted_scan_entries(self) -> list:
        entries = list(self._scan_entries)
        if self._sort_signal.get():
            entries.sort(key=lambda entry: entry.rssi, reverse=True)
        return entries

    @staticmethod
    def _scan_values(entry, first_seen: float = 0.0) -> tuple:
        seen_text = (
            datetime.fromtimestamp(first_seen).strftime("%d.%m.%Y %H:%M:%S")
            if first_seen
            else ""
        )
        return (
            entry.ssid or "(скрытая)",
            entry.bssid,
            seen_text,
            entry.rssi,
            entry.dbm,
            entry.channel or "—",
            entry.frequency_mhz,
            entry.band,
            entry.security.label,
            entry.phy_type or "—",
            f"{entry.max_rate_mbps:g}" if entry.max_rate_mbps else "—",
            round(entry.beacon_period * 1.024) if entry.beacon_period else "—",
            entry.bss_type,
            entry.capabilities,
        )

    def _render_scan(self) -> None:
        if not hasattr(self, "scan_tree"):
            return
        for iid in self.scan_tree.get_children():
            self.scan_tree.delete(iid)
        entries = self._sorted_scan_entries()
        now = time.time()
        for entry in entries:
            seen = self._scan_seen.get(entry.bssid, now)
            self.scan_tree.insert("", "end", values=self._scan_values(entry, seen))
        self.btn_scan_export.configure(state="normal" if entries else "disabled")

    def export_scan(self) -> None:
        if not self._scan_entries:
            messagebox.showinfo(
                "Экспорт сетей", "Сначала выполните сканирование.", parent=self.root
            )
            return
        path = filedialog.asksaveasfilename(
            title="Экспорт результатов поиска сетей",
            defaultextension=".csv",
            initialfile=f"wifi_scan_{datetime.now():%Y%m%d_%H%M%S}.csv",
            filetypes=[("CSV", "*.csv"), ("Все файлы", "*.*")],
            initialdir=self.engine.results_dir,
            parent=self.root,
        )
        if not path:
            return
        entries = self._sorted_scan_entries()
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as fh:
                writer = csv.writer(fh, delimiter=";")
                writer.writerow([title for _key, title, _width, _anchor in self._scan_columns])
                now = time.time()
                for entry in entries:
                    seen = self._scan_seen.get(entry.bssid, now)
                    writer.writerow(self._scan_values(entry, seen))
        except OSError as exc:
            messagebox.showerror("Экспорт сетей", str(exc), parent=self.root)
            return
        self.scan_status.set(f"Сохранено: {len(entries)} → {os.path.basename(path)}")
        self.engine.log(f"Экспорт поиска сетей: {len(entries)} строк → {path}")

    def _on_inventory_click(self, event) -> None:
        if self.tree.identify_region(event.x, event.y) != "cell":
            return
        row = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)
        if not row or not column:
            return
        try:
            index = int(column.lstrip("#")) - 1
        except ValueError:
            return
        values = self.tree.item(row, "values")
        if index < 0 or index >= len(values):
            return
        self._copy_text(str(values[index]))

    def _on_scan_click(self, event) -> None:
        if self.scan_tree.identify_region(event.x, event.y) != "cell":
            return
        row = self.scan_tree.identify_row(event.y)
        column = self.scan_tree.identify_column(event.x)
        if not row or not column:
            return
        try:
            index = int(column.lstrip("#")) - 1
        except ValueError:
            return
        values = self.scan_tree.item(row, "values")
        if index < 0 or index >= len(values):
            return
        self._copy_text(str(values[index]))

    def _copy_text(self, text: str) -> None:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
        except tk.TclError:
            return
        self._flash_copy(f"Скопировано: {text[:60]}")

    def _flash_copy(self, text: str) -> None:
        self.copy_status.set(text)
        self._flash_text = text
        self._flash_until = time.monotonic() + 2.5
        if self._copy_after is not None:
            try:
                self.root.after_cancel(self._copy_after)
            except tk.TclError:
                pass
        self._copy_after = self.root.after(2500, lambda: self.copy_status.set(""))

    def _sync_buttons(self, running: bool) -> None:
        self.btn_start.configure(state="disabled" if running else "normal")
        self.btn_stop.configure(state="normal" if running else "disabled")
        self.btn_scan.configure(state="disabled" if self._scan_busy else "normal")

    def _update_status(self, stats: dict) -> None:
        if self._flash_text and time.monotonic() < self._flash_until:
            self.status.configure(text=self._flash_text)
            return
        audit_name = getattr(self.engine.wlan, "description", "")
        if self._monitor_shared:
            adapter = f"Адаптер: {audit_name} (аудит + мониторинг)"
        else:
            monitor_name = getattr(self.monitor_wlan, "description", "")
            adapter = f"Аудит: {audit_name}   |   Монитор: {monitor_name}"
        scanned = ""
        if stats["last_scan_at"]:
            scanned = datetime.fromtimestamp(stats["last_scan_at"]).strftime("%H:%M:%S")
        self.status.configure(
            text=(
                f"{adapter}   |   Всего: {stats['total']}   "
                f"В эфире: {stats['present']}   Подтверждено: {stats['ok']}   "
                f"Не подошли: {stats['fail']}   Ожидают: {stats['unchecked']}   |   "
                f"Последний скан: {scanned or '—'} ({stats['last_scan_count']} AP)"
            )
        )

    def _update_warning(self, stats: dict) -> None:
        text = ""
        if stats["scan_empty_streak"] >= 2:
            text = (
                "Сети не видны. Проверьте: включён ли Wi-Fi и антенна; включены ли «Службы "
                "определения местоположения» (Параметры → Конфиденциальность → Местоположение); "
                "при необходимости запустите программу от имени администратора."
            )
        elif stats.get("found_write_error"):
            text = (
                f"Не удалось записать results/audit_found.csv: {stats['found_write_error']}. "
                "Закройте файл в Excel и проверьте права на папку results."
            )
        elif stats.get("last_write_error"):
            text = (
                f"Не удалось записать results/wifi_result.csv: {stats['last_write_error']}. "
                "Закройте файл в Excel и проверьте права на папку results."
            )
        elif stats["last_error"]:
            text = f"Ошибка: {stats['last_error']}"
        if text:
            self.warning.configure(text=text)
            if not self.warning.winfo_ismapped():
                self.warning.pack(fill="x", pady=(0, 4), before=self.notebook)
        elif self.warning.winfo_ismapped():
            self.warning.pack_forget()

    def _drain_logs(self) -> None:
        logs = self.engine.drain_logs()
        if not logs:
            return
        self.log_text.configure(state="normal")
        for ts, message in logs:
            self.log_text.insert("end", f"[{ts}] {message}\n")
        lines = int(self.log_text.index("end-1c").split(".")[0])
        if lines > 800:
            self.log_text.delete("1.0", f"{lines - 600}.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # -- действия ----------------------------------------------------------
    def start(self) -> None:
        if self.engine.running:
            return
        self._apply_interval()
        self._apply_verify()
        self.engine.start()
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")

    def stop(self) -> None:
        if not self.engine.running:
            return
        self.btn_stop.configure(state="disabled")
        self.root.configure(cursor="watch")
        try:
            self.engine.stop(timeout=15)
        finally:
            self.root.configure(cursor="")
        self._sync_buttons(self.engine.running)

    def reset_checks(self) -> None:
        self.engine.reset_checks()
        self._redraw_all()

    def _apply_interval(self) -> None:
        try:
            value = float(str(self._interval.get()).replace(",", "."))
        except ValueError:
            value = self.engine.config.interval
        value = max(2.0, min(3600.0, value))
        self.engine.config.interval = value
        self._interval.set(f"{value:g}")

    def _apply_verify(self) -> None:
        self.engine.config.verify_passwords = bool(self._verify.get())

    def reload_csv(self) -> None:
        path = filedialog.askopenfilename(
            title="Выберите CSV инвентаризации",
            filetypes=[("CSV", "*.csv"), ("Все файлы", "*.*")],
            initialdir=os.path.dirname(os.path.abspath(self.engine.inventory.path)),
        )
        if not path:
            return
        was_running = self.engine.running
        if was_running:
            self.stop()
        try:
            self.engine.reload_inventory(path)
        except (InventoryError, OSError) as exc:
            messagebox.showerror("Не удалось прочитать CSV", str(exc), parent=self.root)
            return
        self._columns_gen = -1
        self._rebuild_columns()
        self.root.title(f"Wi-Fi Inventory Audit — {os.path.basename(path)}")
        self.results_hint.configure(text=f"Результаты: {self.engine.results_dir}")
        if was_running:
            self.start()

    def export_results(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Экспорт результата аудита",
            defaultextension=".csv",
            initialfile=f"wifi_result_{datetime.now():%Y%m%d_%H%M%S}.csv",
            filetypes=[("CSV", "*.csv"), ("Все файлы", "*.*")],
            initialdir=self.engine.results_dir,
            parent=self.root,
        )
        if not path:
            return
        try:
            count = self.engine.export_results(path)
        except OSError as exc:
            messagebox.showerror("Экспорт", str(exc), parent=self.root)
            return
        self.engine.log(f"Экспортировано строк: {count} (подтверждённые сверху)")
        messagebox.showinfo("Экспорт", f"Сохранено строк: {count}\n{path}", parent=self.root)

    def export_confirmed(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Экспорт подтверждённых точек",
            defaultextension=".csv",
            initialfile="wifi_confirmed.csv",
            filetypes=[("CSV", "*.csv"), ("Все файлы", "*.*")],
            initialdir=self.engine.results_dir,
            parent=self.root,
        )
        if not path:
            return
        try:
            count = self.engine.export_confirmed(path)
        except OSError as exc:
            messagebox.showerror("Экспорт", str(exc), parent=self.root)
            return
        self.engine.log(f"Экспортировано подтверждённых строк: {count}")
        messagebox.showinfo("Экспорт", f"Сохранено строк: {count}\n{path}", parent=self.root)

    def _open_result_folder(self) -> None:
        folder = self.engine.results_dir
        try:
            os.makedirs(folder, exist_ok=True)
            os.startfile(folder)  # noqa: S606 — намеренное открытие проводника
        except OSError as exc:
            messagebox.showerror("Проводник", str(exc), parent=self.root)

    def _about(self) -> None:
        messagebox.showinfo(
            "О программе",
            "Аудит Wi-Fi инвентаризации.\n\n"
            "• сверка видимых точек с CSV по BSSID;\n"
            "• проверка пароля подключением к конкретной точке;\n"
            "• непрерывный скан до «Стоп»;\n"
            "• вкладка «Поиск сетей» — разовый скан или непрерывный мониторинг;\n"
            "• при двух адаптерах: аудит на первом, мониторинг на втором;\n"
            "• вкладка «Найденные» — история найденных точек за сеанс;\n"
            "• экспорт поиска в CSV и копирование ячейки по клику;\n"
            "• результаты: подпапка results рядом с инвентаризацией.\n\n"
            "Требуется включённая служба определения местоположения "
            "или запуск от администратора.",
            parent=self.root,
        )

    def _on_close(self) -> None:
        try:
            if self._monitor_on:
                self._stop_monitor()
            if self.engine.running:
                self.engine.stop(timeout=5)
        finally:
            self.root.destroy()

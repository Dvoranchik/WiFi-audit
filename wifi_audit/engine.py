"""Движок аудита: непрерывный скан, сверка по BSSID, проверка паролей, выгрузка."""

from __future__ import annotations

import csv
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime

from .inventory import Inventory, InventoryRow, load_inventory
from .wlan import (
    BssEntry,
    ConnectionInfo,
    SecurityType,
    VerifyResult,
    WlanClient,
    WlanError,
)

# Порядок строк в таблице и экспорте: подтверждённые сверху, не найденные снизу.
STATUS_ORDER = {
    "ok": 0,
    "presence": 1,
    "checking": 1,
    "no_password": 1,
    "open": 1,
    "unsupported": 1,
    "fail": 2,
    "absent": 3,
}

_RESULT_EXTRA = [
    "Наличие",
    "Проверка пароля",
    "Статус",
    "RSSI",
    "Обнаружена",
    "Последний раз",
    "Примечание",
    "Проверено",
]


@dataclass
class EngineConfig:
    interval: float = 2.0
    verify_passwords: bool = True
    restore_connection: bool = True
    check_timeout: float = 12.0
    max_checks_per_cycle: int = 0  # 0 — без ограничения
    miss_threshold: int = 2
    scan_timeout: float = 10.0
    output_name: str = "wifi_result.csv"
    results_dir_name: str = "results"
    results_root: str | None = None


@dataclass
class RowStatus:
    row: InventoryRow
    present: bool = False
    miss_count: int = 0
    rssi: int | None = None
    seen_ssid: str = ""
    security: SecurityType | None = None
    password_state: str = "unknown"  # unknown/checking/ok/fail/unsupported/open/no_password
    note: str = ""
    last_seen: float = 0.0
    first_seen: float = 0.0
    checked_at: float = 0.0
    last_security: SecurityType | None = None

    @property
    def status_key(self) -> str:
        if not self.present:
            return "absent"
        state = self.password_state
        if state == "ok":
            return "ok"
        if state == "fail":
            return "fail"
        if state == "checking":
            return "checking"
        if state == "unsupported":
            return "unsupported"
        if state == "open":
            return "open"
        if state == "no_password":
            return "no_password"
        return "presence"

    @property
    def status_text(self) -> str:
        return {
            "ok": "наличие и пароль подтверждены",
            "fail": "пароль не подошёл",
            "checking": "идёт проверка пароля…",
            "unsupported": "только наличие (802.1X)",
            "open": "только наличие (открытая сеть)",
            "no_password": "только наличие (нет пароля в CSV)",
            "presence": "только наличие",
            "absent": "не найдена",
        }[self.status_key]


@dataclass
class FoundItem:
    bssid: str
    ssid: str
    password: str
    values: dict[str, str]
    status_key: str
    status_text: str
    rssi: int | None
    note: str
    security: str
    first_seen: float
    checked_at: float


class AuditEngine:
    def __init__(self, inventory: Inventory, wlan, config: EngineConfig | None = None, log_sink=None):
        self.inventory = inventory
        self.wlan = wlan
        self.config = config or EngineConfig()
        self._log_sink = log_sink
        self._lock = threading.RLock()
        self.wlan_lock = threading.RLock()  # общий с ручным поиском сетей
        self._rows: list[RowStatus] = [RowStatus(row=r) for r in inventory.rows]
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._logs: list[tuple[str, str]] = []
        self._dirty = False
        self._inventory_generation = 0
        self._last_scan_at = 0.0
        self._last_scan_count = 0
        self._scan_empty_streak = 0
        self._last_error = ""
        self._last_write_error = ""
        self._write_at = 0.0
        self._mtime = self._file_mtime(inventory.path)
        self._running = False
        self._found: dict[str, FoundItem] = {}
        self._found_headers, self._found_names = self._found_headers_for(inventory)
        self._found_write_error = ""
        self._write_found()
        self.log(f"Папка результатов: {self.results_dir}")

    # -- результаты на диске ----------------------------------------------
    @property
    def results_dir(self) -> str:
        root = self.config.results_root or os.path.dirname(os.path.abspath(self.inventory.path))
        return os.path.join(root, self.config.results_dir_name)

    @property
    def found_path(self) -> str:
        return os.path.join(self.results_dir, "audit_found.csv")

    @staticmethod
    def _headers_with_extras(base: list[str], extras: list[str]) -> tuple[list[str], dict[str, str]]:
        used = {h.casefold() for h in base}
        names: dict[str, str] = {}
        final: list[str] = []
        for name in extras:
            candidate = name
            while candidate.casefold() in used:
                candidate += " (аудит)"
            used.add(candidate.casefold())
            names[name] = candidate
            final.append(candidate)
        return base + final, names

    def _result_headers(self, inventory: Inventory) -> tuple[list[str], dict[str, str]]:
        return self._headers_with_extras(list(inventory.headers), _RESULT_EXTRA)

    def _found_headers_for(self, inventory: Inventory) -> tuple[list[str], dict[str, str]]:
        # История найденных использует те же колонки, что и полный результат.
        return self._result_headers(inventory)

    @staticmethod
    def _password_text(st: RowStatus) -> str:
        return {
            "ok": "подтверждён",
            "fail": "не подтверждён",
            "unsupported": "не проверяется (802.1X)",
            "open": "не требуется",
            "no_password": "нет в CSV",
        }.get(st.password_state, "не проверялся")

    def found_snapshot(self) -> list[dict]:
        with self._lock:
            items = list(self._found.values())
        return [
            {
                "bssid": item.bssid,
                "ssid": item.ssid,
                "password": item.password,
                "status_key": item.status_key,
                "status_text": item.status_text,
                "rssi": item.rssi,
                "note": item.note,
                "security": item.security,
                "first_seen": item.first_seen,
                "checked_at": item.checked_at,
            }
            for item in items
        ]

    def _sync_found(self) -> None:
        """Добавляет/обновляет найденные точки; каждая точка — один раз (по BSSID)."""
        now = time.time()
        changed = False
        with self._lock:
            headers = self._found_headers
            names = self._found_names
            for st in self._rows:
                if not st.present:
                    continue
                item = self._found.get(st.row.bssid)
                first_seen = item.first_seen if item else now
                values = {h: st.row.values.get(h, "") for h in self.inventory.headers}
                values[names["Наличие"]] = "да"
                values[names["Проверка пароля"]] = self._password_text(st)
                values[names["Статус"]] = st.status_text
                values[names["RSSI"]] = "" if st.rssi is None else str(st.rssi)
                values[names["Примечание"]] = st.note
                values[names["Проверено"]] = (
                    datetime.fromtimestamp(st.checked_at).strftime("%d.%m.%Y %H:%M:%S")
                    if st.checked_at
                    else ""
                )
                values[names["Обнаружена"]] = datetime.fromtimestamp(first_seen).strftime(
                    "%d.%m.%Y %H:%M:%S"
                )
                values[names["Последний раз"]] = (
                    datetime.fromtimestamp(st.last_seen).strftime("%d.%m.%Y %H:%M:%S")
                    if st.last_seen
                    else ""
                )
                security = st.security.label if st.security else ""
                if item is None:
                    item = FoundItem(
                        bssid=st.row.bssid,
                        ssid=st.row.ssid,
                        password=st.row.password,
                        values=values,
                        status_key=st.status_key,
                        status_text=st.status_text,
                        rssi=st.rssi,
                        note=st.note,
                        security=security,
                        first_seen=first_seen,
                        checked_at=st.checked_at,
                    )
                    self._found[st.row.bssid] = item
                    changed = True
                else:
                    if (
                        item.values != values
                        or item.status_key != st.status_key
                        or item.status_text != st.status_text
                        or item.ssid != st.row.ssid
                        or item.password != st.row.password
                        or item.rssi != st.rssi
                        or item.note != st.note
                        or item.security != security
                        or item.checked_at != st.checked_at
                    ):
                        item.values = values
                        item.ssid = st.row.ssid
                        item.password = st.row.password
                        item.status_key = st.status_key
                        item.status_text = st.status_text
                        item.rssi = st.rssi
                        item.note = st.note
                        item.security = security
                        item.checked_at = st.checked_at
                        changed = True
        if changed:
            self._write_found()

    def _write_found(self) -> None:
        try:
            os.makedirs(self.results_dir, exist_ok=True)
            with self._lock:
                headers = list(self._found_headers)
                items = list(self._found.values())
            fd, tmp = tempfile.mkstemp(
                prefix=".audit_found_", suffix=".tmp", dir=self.results_dir
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as fh:
                    writer = csv.writer(fh, delimiter=";")
                    writer.writerow(headers)
                    for item in items:
                        writer.writerow([item.values.get(h, "") for h in headers])
                os.replace(tmp, self.found_path)
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            with self._lock:
                self._found_write_error = ""
        except OSError as exc:
            message = f"{type(exc).__name__}: {exc}"
            with self._lock:
                if message != self._found_write_error:
                    self._found_write_error = message
                    self.log(f"Не удалось записать найденные точки: {message}")

    # -- публичное ---------------------------------------------------------
    @property
    def inventory_generation(self) -> int:
        return self._inventory_generation

    @property
    def last_error(self) -> str:
        with self._lock:
            return self._last_error

    @property
    def scan_empty_streak(self) -> int:
        with self._lock:
            return self._scan_empty_streak

    @property
    def found_write_error(self) -> str:
        with self._lock:
            return self._found_write_error

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._running = True
            self._thread = threading.Thread(target=self._loop, name="audit-engine", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout)
        with self._lock:
            self._running = bool(thread and thread.is_alive())

    @property
    def running(self) -> bool:
        return self._running

    def log(self, message: str) -> None:
        line = (datetime.now().strftime("%H:%M:%S"), message)
        with self._lock:
            self._logs.append(line)
            if len(self._logs) > 500:
                del self._logs[:250]
        if self._log_sink:
            try:
                self._log_sink(message)
            except Exception:
                pass

    def drain_logs(self) -> list[tuple[str, str]]:
        with self._lock:
            logs = self._logs
            self._logs = []
        return logs

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [self._snapshot_row(st) for st in self._rows]

    def stats(self) -> dict:
        with self._lock:
            total = len(self._rows)
            present = sum(1 for r in self._rows if r.present)
            ok = sum(1 for r in self._rows if r.status_key == "ok")
            fail = sum(1 for r in self._rows if r.status_key == "fail")
            unchecked = sum(1 for r in self._rows if r.present and r.status_key in ("presence", "checking"))
            return {
                "total": total,
                "present": present,
                "ok": ok,
                "fail": fail,
                "unchecked": unchecked,
                "last_scan_at": self._last_scan_at,
                "last_scan_count": self._last_scan_count,
                "scan_empty_streak": self._scan_empty_streak,
                "last_error": self._last_error,
                "last_write_error": self._last_write_error,
                "found_write_error": self._found_write_error,
                "running": self._running,
            }

    def reset_checks(self) -> None:
        with self._lock:
            for st in self._rows:
                if st.password_state in ("ok", "fail"):
                    st.password_state = "unknown"
                    st.note = ""
                    st.checked_at = 0.0
            self._dirty = True
        self._sync_found()
        self.log("Результаты проверки паролей сброшены")

    def reload_inventory(self, path: str | None = None) -> None:
        path = path or self.inventory.path
        new_inventory = load_inventory(path)
        with self._lock:
            old = {st.row.bssid: st for st in self._rows}
            rows: list[RowStatus] = []
            for row in new_inventory.rows:
                previous = old.get(row.bssid)
                if previous is None:
                    rows.append(RowStatus(row=row))
                    continue
                previous.row = row
                if previous.password_state in ("ok", "fail") and previous.row.password != row.password:
                    previous.password_state = "unknown"
                    previous.checked_at = 0.0
                rows.append(previous)
            self._rows = rows
            self.inventory = new_inventory
            self._found_headers, self._found_names = self._found_headers_for(new_inventory)
            self._inventory_generation += 1
            self._mtime = self._file_mtime(path)
            self._dirty = True
        self._write_found()
        self.log(f"Инвентаризация перезагружена: {len(new_inventory.rows)} строк")
        for warning in new_inventory.warnings:
            self.log("CSV: " + warning)

    # -- цикл --------------------------------------------------------------
    def _loop(self) -> None:
        cfg = self.config
        self.log(
            f"Старт: {len(self._rows)} строк, интервал {cfg.interval:g} с, "
            f"проверка паролей {'вкл' if cfg.verify_passwords else 'выкл'}"
        )
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self.run_cycle()
            except WlanError as exc:
                with self._lock:
                    self._last_error = str(exc)
                self.log(f"Ошибка Wi-Fi: {exc}")
            except Exception as exc:  # noqa: BLE001 — цикл не должен умирать
                with self._lock:
                    self._last_error = f"{type(exc).__name__}: {exc}"
                self.log(f"Непредвиденная ошибка: {type(exc).__name__}: {exc}")
            elapsed = time.monotonic() - started
            self._stop.wait(max(0.2, cfg.interval - elapsed))
        self._stop.set()
        with self._lock:
            self._running = False
        self.log("Остановлено")

    def run_cycle(self) -> None:
        cfg = self.config
        self._reload_if_changed()
        with self.wlan_lock:
            self.wlan.scan(timeout=cfg.scan_timeout)
            entries = self.wlan.bss_list()
        self._apply_scan(entries)
        with self._lock:
            pending = [st for st in self._rows if self._needs_password_check(st)]
        if cfg.verify_passwords and pending and not self._stop.is_set():
            if cfg.max_checks_per_cycle > 0:
                pending = pending[: cfg.max_checks_per_cycle]
            self._check_passwords(pending)
        self._write_if_dirty(force=True)

    # -- внутреннее --------------------------------------------------------
    @staticmethod
    def _file_mtime(path: str) -> float:
        try:
            return os.path.getmtime(path)
        except OSError:
            return 0.0

    def _reload_if_changed(self) -> None:
        mtime = self._file_mtime(self.inventory.path)
        if mtime and mtime != self._mtime:
            try:
                self.reload_inventory()
            except Exception as exc:  # noqa: BLE001
                self._mtime = mtime  # не долбить файл каждую секунду
                self.log(f"Не удалось перечитать CSV: {exc}")

    def _apply_scan(self, entries: list[BssEntry]) -> None:
        by_bssid = {e.bssid.upper(): e for e in entries}
        now = time.time()
        with self._lock:
            for st in self._rows:
                entry = by_bssid.get(st.row.bssid.upper())
                if entry is not None:
                    appeared = not st.present
                    st.present = True
                    st.miss_count = 0
                    st.rssi = entry.rssi
                    st.seen_ssid = entry.ssid
                    st.last_seen = now
                    if st.last_security is not None and entry.security != st.last_security:
                        st.password_state = "unknown"
                        st.note = "тип защиты изменился"
                    st.last_security = entry.security
                    st.security = entry.security
                    if entry.ssid and st.row.ssid and entry.ssid != st.row.ssid:
                        st.note = f"SSID в эфире: {entry.ssid}"
                    elif st.note.startswith("SSID в эфире"):
                        st.note = ""
                    if appeared:
                        st.first_seen = now
                        self.log(f"В эфире: {st.row.bssid} {entry.ssid or '(без SSID)'}")
                else:
                    st.miss_count += 1
                    if st.present and st.miss_count >= self.config.miss_threshold:
                        st.present = False
                        st.rssi = None
                        self.log(f"Пропала: {st.row.bssid} {st.row.ssid}")
                    if not st.present and st.row.ssid:
                        hint = self._near_bssid(st.row.bssid, st.row.ssid, entries)
                        st.note = f"в эфире похожий BSSID: {hint}" if hint else ""
            for st in self._rows:
                self._refresh_password_state(st)
            self._last_scan_at = now
            self._last_scan_count = len(entries)
            self._scan_empty_streak = self._scan_empty_streak + 1 if not entries else 0
            self._last_error = "" if entries else self._last_error
            self._dirty = True
        self._sync_found()

    @staticmethod
    def _near_bssid(bssid: str, ssid: str, entries: list[BssEntry]) -> str | None:
        """Ищет в эфире BSSID, отличающийся на один hex-символ, при совпадении SSID."""
        target = bssid.replace(":", "").upper()
        for entry in entries:
            if entry.ssid.casefold() != ssid.casefold():
                continue
            other = entry.bssid.replace(":", "").upper()
            if len(other) == len(target) and sum(a != b for a, b in zip(target, other)) == 1:
                return entry.bssid
        return None

    def _refresh_password_state(self, st: RowStatus) -> None:
        if not st.present or st.security is None:
            return
        if st.security in (SecurityType.OPEN, SecurityType.OWE):
            st.password_state = "open"
            return
        if st.security == SecurityType.ENTERPRISE:
            st.password_state = "unsupported"
            return
        if not st.row.password:
            st.password_state = "no_password"
            return
        if st.password_state in ("open", "unsupported", "no_password"):
            st.password_state = "unknown"
        if st.password_state == "unknown" and not st.security.can_check_password:
            st.password_state = "unsupported"

    def _needs_password_check(self, st: RowStatus) -> bool:
        return (
            st.present
            and st.password_state == "unknown"
            and st.security is not None
            and st.security.can_check_password
            and bool(st.row.password)
            and bool(st.seen_ssid or st.row.ssid)
        )

    def _check_passwords(self, pending: list[RowStatus]) -> None:
        previous = self._safe_current_connection()
        previous_profile = previous.profile if previous else ""
        checked = 0
        for st in pending:
            if self._stop.is_set():
                break
            with self._lock:
                st.password_state = "checking"
                self._dirty = True
            ssid = st.seen_ssid or st.row.ssid
            self.log(f"Проверка пароля: {st.row.bssid} {ssid or '(без SSID)'}")
            with self.wlan_lock:
                try:
                    result = self.wlan.verify_password(
                        ssid, st.row.bssid, st.row.password, st.security, timeout=self.config.check_timeout
                    )
                except WlanError as exc:
                    result = VerifyResult.ERROR
                    st.note = str(exc)
                except Exception as exc:  # noqa: BLE001
                    result = VerifyResult.ERROR
                    st.note = f"{type(exc).__name__}: {exc}"
                try:
                    self.wlan.disconnect()
                except Exception:
                    pass
            checked += 1
            with self._lock:
                st.checked_at = time.time()
                if result == VerifyResult.OK:
                    st.password_state = "ok"
                    self.log(f"Пароль верный: {st.row.bssid} {ssid} (audit_found.csv)")
                elif result == VerifyResult.WRONG_PASSWORD:
                    st.password_state = "fail"
                    self.log(f"Пароль не подошёл: {st.row.bssid} {ssid}")
                elif result == VerifyResult.WRONG_BSSID:
                    st.password_state = "fail"
                    st.note = "подключение ушло на другой BSSID"
                    self.log(f"Не удалось попасть именно в {st.row.bssid}: подключились к другому BSSID")
                elif result == VerifyResult.TIMEOUT:
                    st.password_state = "fail"
                    st.note = "таймаут подключения"
                    self.log(f"Таймаут проверки: {st.row.bssid} {ssid}")
                else:
                    st.password_state = "fail"
                    st.note = st.note or "ошибка подключения"
                    self.log(f"Ошибка проверки: {st.row.bssid} {ssid}: {st.note}")
                self._dirty = True
            time.sleep(0.05)  # дать шанс ручному сканированию взять адаптер
            self._write_if_dirty()
            self._sync_found()

        if previous_profile and self.config.restore_connection:
            restored = False
            with self.wlan_lock:
                try:
                    restored = self.wlan.restore(previous_profile)
                except Exception as exc:  # noqa: BLE001
                    self.log(f"Не удалось восстановить подключение: {exc}")
            if restored:
                self.log(f"Исходное подключение восстановлено: {previous_profile}")
            else:
                self.log(f"Не удалось восстановить подключение «{previous_profile}»")
        if checked:
            self.log(f"Проверено за цикл: {checked}")
        self._sync_found()

    def _safe_current_connection(self) -> ConnectionInfo | None:
        try:
            with self.wlan_lock:
                return self.wlan.current_connection()
        except Exception:
            return None

    def _snapshot_row(self, st: RowStatus) -> dict:
        values = dict(st.row.values)
        values[self.inventory.bssid_column] = st.row.bssid
        if self.inventory.ssid_column:
            values.setdefault(self.inventory.ssid_column, st.row.ssid)
        if self.inventory.password_column:
            values[self.inventory.password_column] = st.row.password
        return {
            "index": st.row.index,
            "values": values,
            "present": st.present,
            "status_key": st.status_key,
            "status_text": st.status_text,
            "rssi": st.rssi,
            "first_seen": st.first_seen,
            "last_seen": st.last_seen,
            "checked_at": st.checked_at,
            "note": st.note,
            "security": st.security.label if st.security else "",
            "seen_ssid": st.seen_ssid,
            "password": st.row.password,
        }

    def _write_if_dirty(self, force: bool = False) -> None:
        now = time.monotonic()
        with self._lock:
            if not self._dirty:
                return
            if not force and now - self._write_at < 1.5:
                return
            self._dirty = False
            self._write_at = now
            rows = list(self._rows)
            inventory = self.inventory
        try:
            self._write_results(inventory, rows)
            with self._lock:
                self._last_write_error = ""
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self._dirty = True
                message = f"{type(exc).__name__}: {exc}"
                if message != self._last_write_error:
                    self._last_write_error = message
                    self.log(f"Не удалось записать результат: {message}")

    def export_confirmed(self, path: str) -> int:
        """Сохраняет только строки с подтверждённым наличием и паролем."""
        with self._lock:
            rows = [st for st in self._rows if st.status_key == "ok"]
            inventory = self.inventory
        self._write_rows(path, inventory, rows)
        return len(rows)

    def export_results(self, path: str) -> int:
        """Сохраняет все строки, подтверждённые сверху, неуспешные снизу."""
        with self._lock:
            rows = list(self._rows)
            inventory = self.inventory
        self._write_rows(path, inventory, rows)
        return len(rows)

    def _write_results(self, inventory: Inventory, rows: list[RowStatus]) -> None:
        os.makedirs(self.results_dir, exist_ok=True)
        path = os.path.join(self.results_dir, self.config.output_name)
        self._write_rows(path, inventory, rows)

    def _write_rows(self, path: str, inventory: Inventory, rows: list[RowStatus]) -> None:
        headers, _names = self._result_headers(inventory)
        base_headers = list(inventory.headers)

        directory = os.path.dirname(os.path.abspath(path))
        fd, tmp = tempfile.mkstemp(prefix=".wifi_result_", suffix=".tmp", dir=directory)
        ordered = sorted(rows, key=lambda st: (STATUS_ORDER.get(st.status_key, 9), st.row.index))
        try:
            with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as fh:
                writer = csv.writer(fh, delimiter=";")
                writer.writerow(headers)
                for st in ordered:
                    base = [st.row.values.get(h, "") for h in base_headers]
                    presence = "да" if st.present else "нет"
                    passwords = self._password_text(st)
                    first_seen = (
                        datetime.fromtimestamp(st.first_seen).strftime("%d.%m.%Y %H:%M:%S")
                        if st.first_seen
                        else ""
                    )
                    last_seen = (
                        datetime.fromtimestamp(st.last_seen).strftime("%d.%m.%Y %H:%M:%S")
                        if st.last_seen
                        else ""
                    )
                    checked = (
                        datetime.fromtimestamp(st.checked_at).strftime("%d.%m.%Y %H:%M:%S")
                        if st.checked_at
                        else ""
                    )
                    writer.writerow(
                        base
                        + [
                            presence,
                            passwords,
                            st.status_text,
                            "" if st.rssi is None else st.rssi,
                            first_seen,
                            last_seen,
                            st.note,
                            checked,
                        ]
                    )
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

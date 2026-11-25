"""Точка входа: аудит Wi-Fi инвентаризации (Windows, stdlib)."""

from __future__ import annotations

import argparse
import ctypes
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox

from wifi_audit.demo import DemoWlan
from wifi_audit.engine import AuditEngine, EngineConfig
from wifi_audit.inventory import InventoryError, load_inventory
from wifi_audit.ui import AuditApp
from wifi_audit.wlan import WlanClient, WlanError


def _enable_dpi_awareness() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


def _ask_csv(initial: str) -> str | None:
    return filedialog.askopenfilename(
        title="Выберите CSV инвентаризации",
        filetypes=[("CSV", "*.csv"), ("Все файлы", "*.*")],
        initialdir=os.path.dirname(os.path.abspath(initial)) if initial else os.getcwd(),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Аудит Wi-Fi точек по инвентаризационному CSV")
    parser.add_argument("--csv", help="путь к CSV инвентаризации (по умолчанию wifi.csv рядом)")
    parser.add_argument("--interval", type=float, default=2.0, help="интервал скана, секунды (по умолчанию 2)")
    parser.add_argument("--no-verify", action="store_true", help="не проверять пароли, только наличие")
    parser.add_argument("--output", default="wifi_result.csv", help="имя файла результата")
    parser.add_argument("--interface", type=int, default=0, help="индекс Wi-Fi интерфейса для аудита")
    parser.add_argument(
        "--monitor-interface",
        type=int,
        default=None,
        help="индекс Wi-Fi интерфейса для мониторинга (по умолчанию второй доступный)",
    )
    parser.add_argument(
        "--checks-per-cycle",
        type=int,
        default=0,
        help="сколько паролей проверять за цикл (0 — все ожидающие)",
    )
    parser.add_argument("--demo", action="store_true", help="демо-режим без реального Wi-Fi")
    args = parser.parse_args(argv)

    _enable_dpi_awareness()

    csv_path = args.csv or os.path.join(os.getcwd(), "wifi.csv")
    if args.demo and not args.csv:
        for name in ("wifi.synthetic.csv", "wifi.example.csv"):
            demo_csv = os.path.join(os.getcwd(), name)
            if os.path.isfile(demo_csv):
                csv_path = demo_csv
                break

    root = tk.Tk()
    root.withdraw()

    inventory = None
    while inventory is None:
        try:
            inventory = load_inventory(csv_path)
        except (InventoryError, OSError) as exc:
            if not messagebox.askyesno(
                "Инвентаризация",
                f"{exc}\n\nВыбрать другой CSV-файл?",
                parent=root,
            ):
                root.destroy()
                return 2
            chosen = _ask_csv(csv_path)
            if not chosen:
                root.destroy()
                return 2
            csv_path = chosen

    if args.demo:
        wlan = DemoWlan()
        if args.monitor_interface is not None and args.monitor_interface == args.interface:
            monitor_wlan = wlan
        else:
            monitor_wlan = DemoWlan()
            monitor_wlan.description = "Демо-монитор (реальный Wi-Fi не используется)"
    else:
        try:
            wlan = WlanClient(interface_index=args.interface)
        except WlanError as exc:
            messagebox.showerror(
                "Wi-Fi недоступен",
                f"{exc}\n\n"
                "Проверьте, что Wi-Fi адаптер включён. Посмотреть интерфейс без адаптера можно так:\n"
                "    python app.py --demo",
                parent=root,
            )
            root.destroy()
            return 3

        interfaces: list[tuple[int, str, int]] = []
        try:
            interfaces = WlanClient.list_interfaces()
        except WlanError:
            pass
        if args.monitor_interface is None:
            others = [index for index, _desc, _state in interfaces if index != args.interface]
            monitor_index = others[0] if others else args.interface
        else:
            monitor_index = args.monitor_interface

        if monitor_index == args.interface:
            monitor_wlan = wlan
        else:
            try:
                monitor_wlan = WlanClient(interface_index=monitor_index)
            except WlanError:
                monitor_wlan = wlan

    config = EngineConfig(
        interval=max(2.0, args.interval),
        verify_passwords=not args.no_verify,
        output_name=args.output,
        max_checks_per_cycle=max(0, args.checks_per_cycle),
        results_root=os.path.dirname(os.path.abspath(__file__)),
    )
    engine = AuditEngine(inventory, wlan, config)
    engine.log(f"Адаптер аудита: {wlan.description}")
    if getattr(wlan, "radio_enabled", 0):
        engine.log("Аудит: software radio был выключен — включён автоматически")
    if getattr(wlan, "radio_hardware_off", False):
        engine.log("Аудит: аппаратное радио выключено — проверьте переключатель на адаптере")
    if monitor_wlan is wlan:
        engine.log("Мониторинг: тот же адаптер (последовательный режим)")
    else:
        engine.log(f"Адаптер мониторинга: {monitor_wlan.description}")
        if getattr(monitor_wlan, "radio_enabled", 0):
            engine.log("Мониторинг: software radio был выключен — включён автоматически")
        if getattr(monitor_wlan, "radio_hardware_off", False):
            engine.log("Мониторинг: аппаратное радио выключено — проверьте переключатель")
    for warning in inventory.warnings:
        engine.log("CSV: " + warning)

    root.deiconify()
    AuditApp(root, engine, monitor_wlan)
    try:
        root.mainloop()
    finally:
        try:
            engine.stop(timeout=2)
        except Exception:
            pass
        closed: set[int] = set()
        for client in (wlan, monitor_wlan):
            if id(client) in closed:
                continue
            closed.add(id(client))
            close = getattr(client, "close", None)
            if close:
                try:
                    close()
                except Exception:
                    pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

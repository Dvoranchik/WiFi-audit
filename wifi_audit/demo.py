"""Демо-источник данных: позволяет посмотреть GUI без реального Wi-Fi."""

from __future__ import annotations

import random
import time

from .wlan import BssEntry, SecurityType, VerifyResult

_DEMO = [
    ("AA:11:22:33:44:01", "CORP-WIFI", 82, 2437, SecurityType.WPA2_PSK),
    ("AA:11:22:33:44:02", "CORP-WIFI", 64, 5180, SecurityType.WPA2_PSK),
    ("AA:11:22:33:44:03", "CORP-GUEST", 71, 2412, SecurityType.WPA2_PSK),
    ("AA:11:22:33:44:04", "CORP-VOICE", 55, 5500, SecurityType.WPA3_SAE),
    ("AA:11:22:33:44:05", "CORP-OPEN", 48, 2462, SecurityType.OPEN),
    ("AA:11:22:33:44:06", "CORP-LEGACY", 39, 2417, SecurityType.WPA_PSK),
    ("AA:11:22:33:44:07", "CORP-ENTERPRISE", 67, 5200, SecurityType.ENTERPRISE),
    ("AA:11:22:33:44:08", "CORP-WIFI", 30, 5745, SecurityType.WPA2_PSK),
]


class DemoWlan:
    """Имитация WlanClient с теми же методами, что использует движок."""

    def __init__(self) -> None:
        self.description = "Демо-режим (реальный Wi-Fi не используется)"
        self._cycles = 0

    def scan(self, timeout: float = 10.0, settle: float = 0.25) -> None:
        time.sleep(0.35)
        self._cycles += 1

    def bss_list(self) -> list[BssEntry]:
        entries = []
        for i, (bssid, ssid, rssi, freq, security) in enumerate(_DEMO):
            # Одна точка периодически «пропадает», чтобы показать статус «не найдена».
            if i == 7 and (self._cycles // 3) % 2 == 1:
                continue
            jitter = random.randint(-6, 6)
            entries.append(
                BssEntry(
                    bssid,
                    ssid,
                    max(1, min(99, rssi + jitter)),
                    freq,
                    security,
                    0x0411,
                    phy_type="802.11ac" if freq >= 5000 else "802.11n",
                    beacon_period=100,
                    max_rate_mbps=866.0 if freq >= 5000 else 300.0,
                    bss_type="Инфраструктура",
                )
            )
        return entries

    def current_connection(self):
        return None

    def verify_password(self, ssid, bssid, password, security, timeout: float = 12.0) -> VerifyResult:
        time.sleep(0.6)
        if security in (SecurityType.OPEN, SecurityType.OWE):
            return VerifyResult.OK
        if len(password) >= 8:
            return VerifyResult.OK
        return VerifyResult.WRONG_PASSWORD

    def disconnect(self) -> None:
        pass

    def restore(self, profile_name: str, timeout: float = 15.0) -> bool:
        return True

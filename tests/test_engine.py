from __future__ import annotations

import csv
import os
import tempfile
import unittest

from wifi_audit.engine import AuditEngine, EngineConfig
from wifi_audit.inventory import load_inventory
from wifi_audit.wlan import BssEntry, SecurityType, VerifyResult, security_from_ies


class FakeWlan:
    description = "fake"

    def __init__(self):
        self.entries: list[BssEntry] = []
        self.ok_passwords = {"goodpass"}
        self.verify_calls: list[str] = []

    def scan(self, timeout: float = 10.0, settle: float = 0.25) -> None:
        pass

    def bss_list(self) -> list[BssEntry]:
        return list(self.entries)

    def current_connection(self):
        return None

    def verify_password(self, ssid, bssid, password, security, timeout: float = 12.0) -> VerifyResult:
        self.verify_calls.append(bssid)
        return VerifyResult.OK if password in self.ok_passwords else VerifyResult.WRONG_PASSWORD

    def disconnect(self) -> None:
        pass

    def restore(self, profile_name: str, timeout: float = 15.0) -> bool:
        return True


def rsn_ie(akm_type: int) -> bytes:
    body = (
        b"\x01\x00"  # version
        + b"\x00\x0f\xac\x04"  # group cipher CCMP
        + b"\x01\x00" + b"\x00\x0f\xac\x04"  # pairwise
        + b"\x01\x00" + bytes([0x00, 0x0F, 0xAC, akm_type])  # AKM
        + b"\x00\x00"
    )
    return bytes([48, len(body)]) + body


class SecurityParseTest(unittest.TestCase):
    def test_wpa2_psk(self):
        self.assertEqual(security_from_ies(rsn_ie(2), 0x0411), SecurityType.WPA2_PSK)

    def test_wpa3_sae(self):
        self.assertEqual(security_from_ies(rsn_ie(8), 0x0411), SecurityType.WPA3_SAE)

    def test_enterprise(self):
        self.assertEqual(security_from_ies(rsn_ie(1), 0x0411), SecurityType.ENTERPRISE)

    def test_open(self):
        self.assertEqual(security_from_ies(b"", 0x0401), SecurityType.OPEN)

    def test_wep(self):
        self.assertEqual(security_from_ies(b"", 0x0411), SecurityType.WEP)


class EngineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.csv_path = os.path.join(self.tmp.name, "inv.csv")
        with open(self.csv_path, "w", encoding="utf-8") as fh:
            fh.write(
                "Инв. №;BSSID;SSID;Пароль\n"
                "1;AA:00:00:00:00:01;GOOD;goodpass\n"
                "2;AA:00:00:00:00:02;BAD;badpass\n"
                "3;AA:00:00:00:00:03;OPEN;\n"
                "4;AA:00:00:00:00:04;CORP;whatever\n"
                "5;AA:00:00:00:00:05;GONE;pass\n"
            )

    def _engine(self):
        inventory = load_inventory(self.csv_path)
        fake = FakeWlan()
        fake.entries = [
            BssEntry("AA:00:00:00:00:01", "GOOD", 80, 2412, SecurityType.WPA2_PSK, 0x0411),
            BssEntry("AA:00:00:00:00:02", "BAD", 70, 2412, SecurityType.WPA2_PSK, 0x0411),
            BssEntry("AA:00:00:00:00:03", "OPEN", 60, 2412, SecurityType.OPEN, 0x0401),
            BssEntry("AA:00:00:00:00:04", "CORP", 50, 2412, SecurityType.ENTERPRISE, 0x0411),
        ]
        engine = AuditEngine(inventory, fake, EngineConfig(interval=2, miss_threshold=1))
        return engine, fake

    def test_cycle_sets_statuses(self):
        engine, fake = self._engine()
        engine.run_cycle()
        snapshot = {row["values"]["BSSID"]: row for row in engine.snapshot()}
        self.assertEqual(snapshot["AA:00:00:00:00:01"]["status_key"], "ok")
        self.assertEqual(snapshot["AA:00:00:00:00:02"]["status_key"], "fail")
        self.assertEqual(snapshot["AA:00:00:00:00:03"]["status_key"], "open")
        self.assertEqual(snapshot["AA:00:00:00:00:04"]["status_key"], "unsupported")
        self.assertEqual(snapshot["AA:00:00:00:00:05"]["status_key"], "absent")
        self.assertEqual(sorted(fake.verify_calls), ["AA:00:00:00:00:01", "AA:00:00:00:00:02"])

    def test_result_csv_is_written(self):
        engine, _ = self._engine()
        engine.run_cycle()
        result = os.path.join(self.tmp.name, "results", "wifi_result.csv")
        self.assertTrue(os.path.isfile(result))
        with open(result, encoding="utf-8-sig") as fh:
            content = fh.read()
        self.assertIn("подтверждён", content)
        self.assertIn("не подтверждён", content)

    def test_found_history_is_unique(self):
        engine, _ = self._engine()
        engine.run_cycle()
        engine.run_cycle()
        path = os.path.join(self.tmp.name, "results", "audit_found.csv")
        self.assertTrue(os.path.isfile(path))
        with open(path, encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh, delimiter=";"))
        bssids = [row[1] for row in rows[1:]]
        self.assertEqual(len(bssids), 4)  # 5-я точка не найдена
        self.assertEqual(len(bssids), len(set(bssids)))
        self.assertIn("AA:00:00:00:00:01", bssids)
        self.assertNotIn("AA:00:00:00:00:05", bssids)
        ok_row = next(row for row in rows[1:] if row[1] == "AA:00:00:00:00:01")
        pwd_column = next(i for i, name in enumerate(rows[0]) if name == "Проверка пароля")
        self.assertIn("подтверждён", ok_row[pwd_column])

    def test_no_password_check_when_disabled(self):
        engine, fake = self._engine()
        engine.config.verify_passwords = False
        engine.run_cycle()
        self.assertEqual(fake.verify_calls, [])
        snapshot = engine.snapshot()
        self.assertTrue(all(row["status_key"] != "ok" for row in snapshot))

    def test_typo_hint_for_close_bssid(self):
        path = os.path.join(self.tmp.name, "typo.csv")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("BSSID;SSID;Пароль\nAA:00:00:00:00:0A;S25;pass\n")
        fake = FakeWlan()
        fake.entries = [BssEntry("AA:00:00:00:00:0B", "S25", 70, 2437, SecurityType.WPA2_PSK, 0x0411)]
        engine = AuditEngine(load_inventory(path), fake, EngineConfig(interval=2, miss_threshold=1))
        engine.run_cycle()
        row = engine.snapshot()[0]
        self.assertEqual(row["status_key"], "absent")
        self.assertIn("AA:00:00:00:00:0B", row["note"])

    def test_results_root_override(self):
        engine, _ = self._engine()
        root = os.path.join(self.tmp.name, "out")
        engine.config.results_root = root
        engine.run_cycle()
        self.assertTrue(os.path.isfile(os.path.join(root, "results", "wifi_result.csv")))
        self.assertTrue(os.path.isfile(os.path.join(root, "results", "audit_found.csv")))

    def test_export_results_success_top(self):
        engine, _ = self._engine()
        engine.run_cycle()
        path = os.path.join(self.tmp.name, "all_results.csv")
        self.assertEqual(engine.export_results(path), 5)
        with open(path, encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.reader(fh, delimiter=";"))
        bssids = [row[1] for row in rows[1:]]
        self.assertEqual(bssids[0], "AA:00:00:00:00:01")  # подтверждена
        self.assertEqual(bssids[-1], "AA:00:00:00:00:05")  # не найдена

    def test_export_confirmed_only_green(self):
        engine, _ = self._engine()
        engine.run_cycle()
        path = os.path.join(self.tmp.name, "confirmed.csv")
        self.assertEqual(engine.export_confirmed(path), 1)
        with open(path, encoding="utf-8-sig") as fh:
            content = fh.read()
        self.assertIn("AA:00:00:00:00:01", content)
        self.assertNotIn("AA:00:00:00:00:02", content)


if __name__ == "__main__":
    unittest.main()

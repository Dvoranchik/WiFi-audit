from __future__ import annotations

import os
import tempfile
import unittest

from wifi_audit.inventory import InventoryError, load_inventory, normalize_bssid


class NormalizeBssidTest(unittest.TestCase):
    def test_formats(self):
        for value in (
            "AA:BB:CC:DD:EE:FF",
            "aa-bb-cc-dd-ee-ff",
            "aabbccddeeff",
            "AA.BB.CC.DD.EE.FF",
            " aa bb cc dd ee ff ",
        ):
            self.assertEqual(normalize_bssid(value), "AA:BB:CC:DD:EE:FF")

    def test_invalid(self):
        self.assertIsNone(normalize_bssid(""))
        self.assertIsNone(normalize_bssid("not-a-mac"))
        self.assertIsNone(normalize_bssid("AA:BB:CC:DD:EE"))


class LoadInventoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write(self, name: str, content: bytes) -> str:
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb") as fh:
            fh.write(content)
        return path

    def test_cp1251_semicolon(self):
        text = (
            "Инв. №;BSSID;SSID;Пароль;Место\n"
            "1;AA:11:22:33:44:01;Офис;пароль1;Серверная\n"
            "2;aabbccddeeff;Склад;pass2;Склад\n"
        )
        path = self._write("inv.csv", text.encode("cp1251"))
        inv = load_inventory(path)
        self.assertEqual(inv.encoding, "cp1251")
        self.assertEqual(inv.delimiter, ";")
        self.assertEqual(len(inv.rows), 2)
        self.assertEqual(inv.rows[0].bssid, "AA:11:22:33:44:01")
        self.assertEqual(inv.rows[0].ssid, "Офис")
        self.assertEqual(inv.rows[0].password, "пароль1")
        self.assertEqual(inv.rows[1].bssid, "AA:BB:CC:DD:EE:FF")

    def test_utf8_bom_comma(self):
        text = "BSSID,SSID,Password\nAA:11:22:33:44:02,Net,secret\n"
        path = self._write("inv.csv", b"\xef\xbb\xbf" + text.encode("utf-8"))
        inv = load_inventory(path)
        self.assertEqual(inv.encoding, "utf-8-sig")
        self.assertEqual(inv.delimiter, ",")
        self.assertEqual(inv.rows[0].password, "secret")

    def test_password_keeps_spaces(self):
        text = "BSSID;SSID;Пароль\nAA:11:22:33:44:03;Net; pass with spaces \n"
        path = self._write("inv.csv", text.encode("utf-8"))
        inv = load_inventory(path)
        self.assertEqual(inv.rows[0].password, " pass with spaces ")

    def test_guess_bssid_column(self):
        text = "Точка;Сеть;Секрет\nAA:11:22:33:44:04;Net;secret\n"
        path = self._write("inv.csv", text.encode("utf-8"))
        inv = load_inventory(path)
        self.assertEqual(len(inv.rows), 1)
        self.assertEqual(inv.rows[0].bssid, "AA:11:22:33:44:04")
        self.assertIsNone(inv.password_column)

    def test_cr_only_and_key_essid(self):
        text = (
            "time;bssid;sec;essid;key;city;address\r"
            "01.01.2026;AA:11:22:33:44:09;WPA2;CORP;secret;Москва;Тест\r"
        )
        path = self._write("inv.csv", text.encode("utf-8"))
        inv = load_inventory(path)
        self.assertEqual(inv.password_column, "key")
        self.assertEqual(inv.ssid_column, "essid")
        self.assertEqual(len(inv.rows), 1)
        self.assertEqual(inv.rows[0].ssid, "CORP")
        self.assertEqual(inv.rows[0].password, "secret")

    def test_trailing_empty_columns(self):
        text = (
            "time;bssid;sec;essid;key;city;address;;;;\r"
            "14.08.2020;aa:bb:cc:dd:ee:ff;WPA/WPA2;WiFi-test-01;testPassword;test city;test adress;;;\r"
        )
        path = self._write("inv.csv", text.encode("utf-8"))
        inv = load_inventory(path)
        self.assertEqual(
            inv.headers, ["time", "bssid", "sec", "essid", "key", "city", "address"]
        )
        self.assertEqual(len(inv.rows), 1)
        self.assertEqual(inv.rows[0].bssid, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(inv.rows[0].ssid, "WiFi-test-01")
        self.assertEqual(inv.rows[0].password, "testPassword")
        self.assertEqual(inv.rows[0].values["address"], "test adress")

    def test_duplicates_are_skipped(self):
        text = (
            "BSSID;SSID;Пароль\n"
            "AA:11:22:33:44:05;A;x\n"
            "AA:11:22:33:44:05;A;y\n"
        )
        path = self._write("inv.csv", text.encode("utf-8"))
        inv = load_inventory(path)
        self.assertEqual(len(inv.rows), 1)
        self.assertTrue(any("дубликат" in w for w in inv.warnings))

    def test_xlsx_is_reported(self):
        path = self._write("wifi.csv", b"PK\x03\x04rest-of-zip")
        with self.assertRaises(InventoryError) as ctx:
            load_inventory(path)
        self.assertIn("XLSX", str(ctx.exception))

    def test_empty_file(self):
        path = self._write("empty.csv", b"")
        with self.assertRaises(InventoryError):
            load_inventory(path)


if __name__ == "__main__":
    unittest.main()

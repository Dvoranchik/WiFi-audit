from __future__ import annotations

import unittest
import xml.etree.ElementTree as ET

from wifi_audit.wlan import SecurityType, _profile_xml


class ProfileXmlTest(unittest.TestCase):
    def _parse(self, security: SecurityType, password: str = "Secret123"):
        xml = _profile_xml("Test Net", "AA:BB:CC:DD:EE:FF", password, security)
        return ET.fromstring(xml)

    def test_wpa2_psk_escapes_password(self):
        root = self._parse(SecurityType.WPA2_PSK, 'p<&"12345')
        ns = {"w": "http://www.microsoft.com/networking/WLAN/profile/v1"}
        auth = root.find(".//w:authentication", ns).text
        enc = root.find(".//w:encryption", ns).text
        key = root.find(".//w:keyMaterial", ns).text
        self.assertEqual(auth, "WPA2PSK")
        self.assertEqual(enc, "AES")
        self.assertEqual(key, 'p<&"12345')

    def test_wpa3_sae(self):
        root = self._parse(SecurityType.WPA3_SAE)
        ns = {"w": "http://www.microsoft.com/networking/WLAN/profile/v1"}
        self.assertEqual(root.find(".//w:authentication", ns).text, "WPA3SAE")

    def test_open_has_no_key(self):
        root = self._parse(SecurityType.OPEN, "")
        ns = {"w": "http://www.microsoft.com/networking/WLAN/profile/v1"}
        self.assertEqual(root.find(".//w:authentication", ns).text, "open")
        self.assertIsNone(root.find(".//w:sharedKey", ns))

    def test_ssid_is_hex(self):
        root = self._parse(SecurityType.WPA2_PSK)
        ns = {"w": "http://www.microsoft.com/networking/WLAN/profile/v1"}
        self.assertEqual(root.find(".//w:SSID/w:hex", ns).text, "54657374204E6574")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest

from wifi_audit.wlan import BssEntry, SecurityType, band_from_frequency, channel_from_frequency


class ChannelTest(unittest.TestCase):
    def test_24_ghz(self):
        self.assertEqual(channel_from_frequency(2412), 1)
        self.assertEqual(channel_from_frequency(2437), 6)
        self.assertEqual(channel_from_frequency(2472), 13)
        self.assertEqual(channel_from_frequency(2484), 14)

    def test_5_ghz(self):
        self.assertEqual(channel_from_frequency(5180), 36)
        self.assertEqual(channel_from_frequency(5745), 149)

    def test_6_ghz(self):
        self.assertEqual(channel_from_frequency(5955), 1)
        self.assertEqual(channel_from_frequency(6115), 33)

    def test_bands(self):
        self.assertEqual(band_from_frequency(2437), "2.4 ГГц")
        self.assertEqual(band_from_frequency(5180), "5 ГГц")
        self.assertEqual(band_from_frequency(6115), "6 ГГц")


class BssEntryTest(unittest.TestCase):
    def test_dbm_prefers_driver_value(self):
        entry = BssEntry(
            "AA:BB:CC:DD:EE:FF", "Net", 60, 2437, SecurityType.WPA2_PSK, 0x0411, rssi_dbm=-47
        )
        self.assertEqual(entry.dbm, -47)
        self.assertEqual(entry.channel, 6)
        self.assertEqual(entry.band, "2.4 ГГц")
        self.assertIn("Privacy", entry.capabilities)

    def test_dbm_fallback(self):
        entry = BssEntry("AA:BB:CC:DD:EE:FF", "Net", 60, 2437, SecurityType.OPEN, 0x0401)
        self.assertEqual(entry.dbm, -70)


if __name__ == "__main__":
    unittest.main()

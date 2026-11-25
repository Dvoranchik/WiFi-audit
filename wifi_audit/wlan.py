"""Минимальная обёртка над Windows Native Wi-Fi API (wlanapi.dll).

Только stdlib: ctypes. Умеет:
  * перечислять интерфейсы;
  * запускать скан и получать список BSS (BSSID/SSID/RSSI/защита);
  * подключаться к конкретному BSSID по временному профилю (без мусора в профилях);
  * отключаться и восстанавливать исходное подключение.

Все вызовы — из одного рабочего потока (engine), UI их не трогает.
"""

from __future__ import annotations

import ctypes
import threading
import time
import uuid
from ctypes import wintypes as wt
from dataclasses import dataclass
from enum import Enum
from xml.sax.saxutils import escape as xml_escape

wlanapi = ctypes.WinDLL("wlanapi.dll", use_last_error=True)

ERROR_SUCCESS = 0

WLAN_MAX_NAME_LENGTH = 256
DOT11_SSID_MAX_LENGTH = 32
WLAN_MAX_PHY_INDEX = 64

WLAN_INTERFACE_STATE_CONNECTED = 1
WLAN_INTERFACE_STATE_DISCONNECTING = 3
WLAN_INTERFACE_STATE_DISCONNECTED = 4
WLAN_INTERFACE_STATE_ASSOCIATING = 5
WLAN_INTERFACE_STATE_DISCOVERING = 6
WLAN_INTERFACE_STATE_AUTHENTICATING = 7

DOT11_BSS_TYPE_INFRASTRUCTURE = 1

WLAN_CONNECTION_MODE_PROFILE = 0
WLAN_CONNECTION_MODE_TEMPORARY_PROFILE = 1

WLAN_INTF_OPCODE_CURRENT_CONNECTION = 7
WLAN_INTF_OPCODE_RADIO_STATE = 4

DOT11_RADIO_STATE_ON = 1
DOT11_RADIO_STATE_OFF = 2

WLAN_NOTIFICATION_SOURCE_ACM = 0x00000008
WLAN_NOTIFICATION_ACM_SCAN_COMPLETE = 7
WLAN_NOTIFICATION_ACM_SCAN_FAIL = 8

DOT11_AUTH_ALGO_OPEN = 1
DOT11_AUTH_ALGO_SHARED = 2
DOT11_AUTH_ALGO_WPA_PSK = 4
DOT11_AUTH_ALGO_RSNA_PSK = 7
DOT11_AUTH_ALGO_WPA3_SAE = 9

DOT11_CIPHER_ALGO_NONE = 0
DOT11_CIPHER_ALGO_WEP40 = 1
DOT11_CIPHER_ALGO_TKIP = 2
DOT11_CIPHER_ALGO_CCMP = 4
DOT11_CIPHER_ALGO_WEP104 = 5


class WlanError(RuntimeError):
    def __init__(self, message: str, code: int | None = None):
        self.code = code
        if code is not None:
            message = f"{message} (код 0x{code:08X})"
        super().__init__(message)


# --------------------------------------------------------------------------
# Структуры WinAPI
# --------------------------------------------------------------------------
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_bytes(cls, raw: bytes) -> "GUID":
        return cls.from_buffer_copy(raw)


class DOT11_SSID(ctypes.Structure):
    _fields_ = [
        ("uSSIDLength", ctypes.c_ulong),
        ("ucSSID", ctypes.c_ubyte * DOT11_SSID_MAX_LENGTH),
    ]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [
        ("InterfaceGuid", ctypes.c_ubyte * 16),
        ("strInterfaceDescription", ctypes.c_wchar * WLAN_MAX_NAME_LENGTH),
        ("isState", ctypes.c_uint),
    ]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfItems", wt.DWORD),
        ("dwIndex", wt.DWORD),
        ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),
    ]


class WLAN_RATE_SET(ctypes.Structure):
    _fields_ = [
        ("uRateSetLength", ctypes.c_ulong),
        ("usRateSet", ctypes.c_ushort * 126),
    ]


class WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),
        ("uPhyId", ctypes.c_ulong),
        ("dot11Bssid", ctypes.c_ubyte * 6),
        ("dot11BssType", ctypes.c_int),
        ("dot11PhyType", ctypes.c_int),
        ("lRssi", ctypes.c_long),
        ("uLinkQuality", ctypes.c_ulong),
        ("bInRegDomain", ctypes.c_ubyte),
        ("usBeaconPeriod", ctypes.c_ushort),
        ("ullTimestamp", ctypes.c_ulonglong),
        ("ullHostTimestamp", ctypes.c_ulonglong),
        ("usCapabilityInformation", ctypes.c_ushort),
        ("ulChCenterFrequency", ctypes.c_ulong),
        ("wlanRateSet", WLAN_RATE_SET),
        ("ulIeOffset", ctypes.c_ulong),
        ("ulIeSize", ctypes.c_ulong),
    ]


class WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [
        ("dwTotalSize", wt.DWORD),
        ("dwNumberOfItems", wt.DWORD),
        ("wlanBssEntries", WLAN_BSS_ENTRY * 1),
    ]


class WLAN_ASSOCIATION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),
        ("dot11BssType", ctypes.c_int),
        ("dot11Bssid", ctypes.c_ubyte * 6),
        ("dot11PhyType", ctypes.c_int),
        ("uDot11PhyIndex", ctypes.c_ulong),
        ("wlanSignalQuality", ctypes.c_ulong),
        ("ulRxRate", ctypes.c_ulong),
        ("ulTxRate", ctypes.c_ulong),
    ]


class WLAN_SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("bSecurityEnabled", wt.BOOL),
        ("bOneXEnabled", wt.BOOL),
        ("dot11AuthAlgorithm", ctypes.c_int),
        ("dot11CipherAlgorithm", ctypes.c_int),
    ]


class WLAN_CONNECTION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("isState", ctypes.c_int),
        ("wlanConnectionMode", ctypes.c_int),
        ("strProfileName", ctypes.c_wchar * WLAN_MAX_NAME_LENGTH),
        ("wlanAssociationAttributes", WLAN_ASSOCIATION_ATTRIBUTES),
        ("wlanSecurityAttributes", WLAN_SECURITY_ATTRIBUTES),
    ]


class NDIS_OBJECT_HEADER(ctypes.Structure):
    _fields_ = [
        ("Type", ctypes.c_ubyte),
        ("Revision", ctypes.c_ubyte),
        ("Size", ctypes.c_ushort),
    ]


class DOT11_BSSID_LIST(ctypes.Structure):
    """DOT11_BSSID_LIST из windot11.h (с NDIS-заголовком)."""

    _fields_ = [
        ("Header", NDIS_OBJECT_HEADER),
        ("uNumOfEntries", ctypes.c_ulong),
        ("uTotalNumOfEntries", ctypes.c_ulong),
        ("BSSIDs", (ctypes.c_ubyte * 6) * 1),
    ]


class WLAN_CONNECTION_PARAMETERS(ctypes.Structure):
    _fields_ = [
        ("wlanConnectionMode", ctypes.c_int),
        ("strProfile", ctypes.c_wchar_p),
        ("pDot11Ssid", ctypes.POINTER(DOT11_SSID)),
        ("pDesiredBssidList", ctypes.POINTER(DOT11_BSSID_LIST)),
        ("dot11BssType", ctypes.c_int),
        ("dwFlags", wt.DWORD),
    ]


class WLAN_NOTIFICATION_DATA(ctypes.Structure):
    _fields_ = [
        ("NotificationSource", wt.DWORD),
        ("NotificationCode", wt.DWORD),
        ("InterfaceGuid", ctypes.c_ubyte * 16),
        ("dwDataSize", wt.DWORD),
        ("pData", ctypes.c_void_p),
    ]


class WLAN_PHY_RADIO_STATE(ctypes.Structure):
    _fields_ = [
        ("dwPhyIndex", wt.DWORD),
        ("dot11SoftwareRadioState", ctypes.c_int),
        ("dot11HardwareRadioState", ctypes.c_int),
    ]


class WLAN_RADIO_STATE(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfPhys", wt.DWORD),
        ("PhyRadioState", WLAN_PHY_RADIO_STATE * WLAN_MAX_PHY_INDEX),
    ]


WLAN_NOTIFICATION_CALLBACK = ctypes.WINFUNCTYPE(
    None, ctypes.POINTER(WLAN_NOTIFICATION_DATA), ctypes.c_void_p
)


wlanapi.WlanOpenHandle.argtypes = [
    wt.DWORD, ctypes.c_void_p, ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.HANDLE)
]
wlanapi.WlanOpenHandle.restype = wt.DWORD
wlanapi.WlanCloseHandle.argtypes = [wt.HANDLE, ctypes.c_void_p]
wlanapi.WlanCloseHandle.restype = wt.DWORD
wlanapi.WlanFreeMemory.argtypes = [ctypes.c_void_p]
wlanapi.WlanEnumInterfaces.argtypes = [
    wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(WLAN_INTERFACE_INFO_LIST))
]
wlanapi.WlanEnumInterfaces.restype = wt.DWORD
wlanapi.WlanScan.argtypes = [
    wt.HANDLE, ctypes.POINTER(GUID), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p
]
wlanapi.WlanScan.restype = wt.DWORD
wlanapi.WlanGetNetworkBssList.argtypes = [
    wt.HANDLE,
    ctypes.POINTER(GUID),
    ctypes.c_void_p,
    ctypes.c_int,
    wt.BOOL,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.POINTER(WLAN_BSS_LIST)),
]
wlanapi.WlanGetNetworkBssList.restype = wt.DWORD
wlanapi.WlanQueryInterface.argtypes = [
    wt.HANDLE,
    ctypes.POINTER(GUID),
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.POINTER(wt.DWORD),
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_void_p,
]
wlanapi.WlanQueryInterface.restype = wt.DWORD
wlanapi.WlanConnect.argtypes = [
    wt.HANDLE, ctypes.POINTER(GUID), ctypes.POINTER(WLAN_CONNECTION_PARAMETERS), ctypes.c_void_p
]
wlanapi.WlanConnect.restype = wt.DWORD
wlanapi.WlanSetInterface.argtypes = [
    wt.HANDLE,
    ctypes.POINTER(GUID),
    ctypes.c_int,
    wt.DWORD,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
wlanapi.WlanSetInterface.restype = wt.DWORD
wlanapi.WlanDisconnect.argtypes = [wt.HANDLE, ctypes.POINTER(GUID), ctypes.c_void_p]
wlanapi.WlanDisconnect.restype = wt.DWORD
wlanapi.WlanRegisterNotification.argtypes = [
    wt.HANDLE,
    wt.DWORD,
    wt.BOOL,
    WLAN_NOTIFICATION_CALLBACK,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(wt.DWORD),
]
wlanapi.WlanRegisterNotification.restype = wt.DWORD


# --------------------------------------------------------------------------
# Предметные типы
# --------------------------------------------------------------------------
class SecurityType(str, Enum):
    OPEN = "open"
    WEP = "wep"
    WPA_PSK = "wpa_psk"
    WPA2_PSK = "wpa2_psk"
    WPA3_SAE = "wpa3_sae"
    ENTERPRISE = "enterprise"
    OWE = "owe"
    UNKNOWN = "unknown"

    @property
    def can_check_password(self) -> bool:
        return self in (
            SecurityType.WEP,
            SecurityType.WPA_PSK,
            SecurityType.WPA2_PSK,
            SecurityType.WPA3_SAE,
        )

    @property
    def needs_password(self) -> bool:
        return self not in (SecurityType.OPEN, SecurityType.OWE)

    @property
    def label(self) -> str:
        return {
            SecurityType.OPEN: "Открытая",
            SecurityType.WEP: "WEP",
            SecurityType.WPA_PSK: "WPA-PSK",
            SecurityType.WPA2_PSK: "WPA2-PSK",
            SecurityType.WPA3_SAE: "WPA3-SAE",
            SecurityType.ENTERPRISE: "802.1X (Enterprise)",
            SecurityType.OWE: "OWE",
            SecurityType.UNKNOWN: "Неизвестно",
        }[self]


@dataclass(frozen=True)
class ProfileSpec:
    auth: str
    encryption: str
    conn_auth: int
    conn_cipher: int


_PROFILE_SPECS: dict[SecurityType, ProfileSpec] = {
    SecurityType.OPEN: ProfileSpec("open", "none", DOT11_AUTH_ALGO_OPEN, DOT11_CIPHER_ALGO_NONE),
    SecurityType.OWE: ProfileSpec("OWE", "AES", DOT11_AUTH_ALGO_OPEN, DOT11_CIPHER_ALGO_CCMP),
    SecurityType.WEP: ProfileSpec("open", "WEP", DOT11_AUTH_ALGO_OPEN, DOT11_CIPHER_ALGO_WEP104),
    SecurityType.WPA_PSK: ProfileSpec("WPAPSK", "TKIP", DOT11_AUTH_ALGO_WPA_PSK, DOT11_CIPHER_ALGO_TKIP),
    SecurityType.WPA2_PSK: ProfileSpec("WPA2PSK", "AES", DOT11_AUTH_ALGO_RSNA_PSK, DOT11_CIPHER_ALGO_CCMP),
    SecurityType.WPA3_SAE: ProfileSpec("WPA3SAE", "AES", DOT11_AUTH_ALGO_WPA3_SAE, DOT11_CIPHER_ALGO_CCMP),
}


_PHY_TYPE_NAMES = {
    0: "—",
    1: "FHSS",
    2: "DSSS",
    3: "IR",
    4: "802.11a",
    5: "802.11b",
    6: "802.11g",
    7: "802.11n",
    8: "802.11ac",
    9: "802.11ad",
    10: "802.11ax",
}

_BSS_TYPE_NAMES = {1: "Инфраструктура", 2: "Ad-hoc", 3: "Любой"}

_CAPABILITY_BITS = (
    (0x0001, "ESS"),
    (0x0002, "IBSS"),
    (0x0004, "CF-Poll"),
    (0x0008, "CF-PollReq"),
    (0x0010, "Privacy"),
    (0x0020, "ShortPreamble"),
    (0x0040, "PBCC"),
    (0x0080, "Agility"),
    (0x0100, "SpectrumMgmt"),
    (0x0200, "QoS"),
    (0x0400, "ShortSlot"),
    (0x0800, "APSD"),
    (0x1000, "RadioMeasure"),
    (0x2000, "DSSS-OFDM"),
    (0x4000, "DelayedBlockAck"),
    (0x8000, "ImmediateBlockAck"),
)


def channel_from_frequency(freq_mhz: int) -> int:
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    if freq_mhz == 2484:
        return 14
    if 5000 <= freq_mhz < 5925:
        return (freq_mhz - 5000) // 5
    if 5950 <= freq_mhz <= 7125:
        return (freq_mhz - 5950) // 5
    return 0


def band_from_frequency(freq_mhz: int) -> str:
    if 2400 <= freq_mhz < 2500:
        return "2.4 ГГц"
    if 4900 <= freq_mhz < 5925:
        return "5 ГГц"
    if 5925 <= freq_mhz <= 7125:
        return "6 ГГц"
    return f"{freq_mhz} МГц"


def capability_text(capability: int) -> str:
    names = [name for bit, name in _CAPABILITY_BITS if capability & bit]
    return ", ".join(names) if names else f"0x{capability:04X}"


@dataclass
class BssEntry:
    bssid: str
    ssid: str
    rssi: int
    frequency_mhz: int
    security: SecurityType
    capability: int
    phy_type: str = ""
    beacon_period: int = 0
    max_rate_mbps: float = 0.0
    bss_type: str = "infrastructure"
    rssi_dbm: int | None = None

    @property
    def channel(self) -> int:
        return channel_from_frequency(self.frequency_mhz)

    @property
    def band(self) -> str:
        return band_from_frequency(self.frequency_mhz)

    @property
    def dbm(self) -> int:
        if self.rssi_dbm is not None:
            return self.rssi_dbm
        # Приблизительная оценка по шкале Windows 0..100.
        return int(self.rssi / 2) - 100

    @property
    def capabilities(self) -> str:
        return capability_text(self.capability)


@dataclass
class ConnectionInfo:
    ssid: str
    bssid: str
    profile: str
    state: int
    signal: int


class VerifyResult(str, Enum):
    OK = "ok"
    WRONG_PASSWORD = "wrong_password"
    TIMEOUT = "timeout"
    WRONG_BSSID = "wrong_bssid"
    ERROR = "error"


def _bssid_text(raw) -> str:
    return ":".join(f"{b:02X}" for b in raw)


def _ssid_text(ssid: DOT11_SSID) -> str:
    raw = bytes(ssid.ucSSID[: min(ssid.uSSIDLength, DOT11_SSID_MAX_LENGTH)])
    return raw.decode("utf-8", "replace").rstrip("\x00")


def _iter_ies(blob: bytes):
    i = 0
    while i + 2 <= len(blob):
        eid = blob[i]
        length = blob[i + 1]
        data = blob[i + 2 : i + 2 + length]
        if len(data) < length:
            break
        yield eid, data
        i += 2 + length


def _rsn_akms(body: bytes) -> set[int]:
    """AKM-типы из RSN-подобного IE (без OUI/type для WPA)."""
    if len(body) < 2:
        return set()
    pos = 2  # version
    if pos + 4 > len(body):
        return set()
    pos += 4  # group cipher
    if pos + 2 > len(body):
        return set()
    pairwise = int.from_bytes(body[pos : pos + 2], "little")
    pos += 2 + 4 * pairwise
    if pos + 2 > len(body):
        return set()
    akm_count = int.from_bytes(body[pos : pos + 2], "little")
    pos += 2
    akms: set[int] = set()
    for _ in range(akm_count):
        if pos + 4 > len(body):
            break
        oui = body[pos : pos + 3]
        akm_type = body[pos + 3]
        pos += 4
        if oui == b"\x00\x0f\xac":
            akms.add(akm_type)
    return akms


def security_from_ies(ies: bytes, capability: int) -> SecurityType:
    rsn_akms: set[int] | None = None
    wpa_akms: set[int] | None = None
    for eid, body in _iter_ies(ies):
        if eid == 48 and len(body) >= 2:  # RSN
            rsn_akms = _rsn_akms(body)
        elif eid == 221 and len(body) >= 6 and body[:4] == b"\x00\x50\xf2\x01":  # WPA
            wpa_akms = _rsn_akms(body[4:])

    if rsn_akms:
        if rsn_akms & {18}:
            return SecurityType.OWE
        psk = bool(rsn_akms & {2, 4, 6})
        sae = bool(rsn_akms & {8, 9})
        ent = bool(rsn_akms & {1, 3, 5})
        if sae and psk:
            return SecurityType.WPA2_PSK  # переходный режим: WPA2-профиль работает
        if sae:
            return SecurityType.WPA3_SAE
        if psk:
            return SecurityType.WPA2_PSK
        if ent:
            return SecurityType.ENTERPRISE
        return SecurityType.ENTERPRISE

    if wpa_akms:
        if wpa_akms & {2, 4}:
            return SecurityType.WPA_PSK
        return SecurityType.ENTERPRISE

    if capability & 0x10:  # privacy bit без RSN/WPA — обычно WEP
        return SecurityType.WEP
    return SecurityType.OPEN


def _profile_xml(ssid: str, bssid: str, password: str, security: SecurityType) -> str:
    spec = _PROFILE_SPECS[security]
    ssid_bytes = ssid.encode("utf-8")[:DOT11_SSID_MAX_LENGTH]
    ssid_hex = ssid_bytes.hex().upper()
    profile_name = xml_escape(f"AUDIT {bssid}")
    shared_key = ""
    if security in (SecurityType.WPA_PSK, SecurityType.WPA2_PSK, SecurityType.WPA3_SAE):
        shared_key = (
            "<sharedKey>"
            "<keyType>passPhrase</keyType>"
            "<protected>false</protected>"
            f"<keyMaterial>{xml_escape(password)}</keyMaterial>"
            "</sharedKey>"
        )
    elif security == SecurityType.WEP:
        shared_key = (
            "<sharedKey>"
            "<keyType>networkKey</keyType>"
            "<protected>false</protected>"
            f"<keyMaterial>{xml_escape(password)}</keyMaterial>"
            "<keyIndex>1</keyIndex>"
            "</sharedKey>"
        )
    return (
        '<?xml version="1.0"?>'
        '<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">'
        f"<name>{profile_name}</name>"
        "<SSIDConfig><SSID>"
        f"<hex>{ssid_hex}</hex>"
        "</SSID></SSIDConfig>"
        "<connectionType>ESS</connectionType>"
        "<connectionMode>manual</connectionMode>"
        "<MSM><security>"
        "<authEncryption>"
        f"<authentication>{spec.auth}</authentication>"
        f"<encryption>{spec.encryption}</encryption>"
        "<useOneX>false</useOneX>"
        "</authEncryption>"
        f"{shared_key}"
        "</security></MSM>"
        "</WLANProfile>"
    )


class WlanClient:
    @classmethod
    def list_interfaces(cls) -> list[tuple[int, str, int]]:
        """Список Wi-Fi интерфейсов: (индекс, описание, состояние)."""
        handle = wt.HANDLE()
        negotiated = wt.DWORD()
        rc = wlanapi.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(handle))
        if rc != ERROR_SUCCESS:
            raise WlanError("Не удалось открыть WLAN API", rc)
        try:
            plist = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
            rc = wlanapi.WlanEnumInterfaces(handle, None, ctypes.byref(plist))
            if rc != ERROR_SUCCESS:
                raise WlanError("WlanEnumInterfaces", rc)
            try:
                count = plist.contents.dwNumberOfItems
                base = ctypes.addressof(plist.contents) + WLAN_INTERFACE_INFO_LIST.InterfaceInfo.offset
                items = (WLAN_INTERFACE_INFO * count).from_address(base)
                return [
                    (i, items[i].strInterfaceDescription, int(items[i].isState))
                    for i in range(count)
                ]
            finally:
                wlanapi.WlanFreeMemory(plist)
        finally:
            wlanapi.WlanCloseHandle(handle, None)

    def __init__(self, interface_index: int = 0):
        self._handle = wt.HANDLE()
        self._negotiated = wt.DWORD()
        self._interface_index = interface_index
        self._guid: GUID | None = None
        self._description = ""
        self._lock = threading.Lock()
        self._closed = False
        self._scan_event = threading.Event()
        self._scan_failed = False
        self._callback = WLAN_NOTIFICATION_CALLBACK(self._on_notification)

        rc = wlanapi.WlanOpenHandle(2, None, ctypes.byref(self._negotiated), ctypes.byref(self._handle))
        if rc != ERROR_SUCCESS:
            raise WlanError("Не удалось открыть WLAN API", rc)

        interfaces = self._enum_interfaces()
        if not interfaces:
            self.close()
            raise WlanError("В системе нет Wi-Fi интерфейсов")
        index = min(interface_index, len(interfaces) - 1)
        self._guid, self._description = interfaces[index]

        self.radio_enabled = 0
        self.radio_hardware_off = False
        self._ensure_software_radio_on()

        previous = wt.DWORD()
        rc = wlanapi.WlanRegisterNotification(
            self._handle,
            WLAN_NOTIFICATION_SOURCE_ACM,
            False,
            self._callback,
            None,
            None,
            ctypes.byref(previous),
        )
        self._notifications_ok = rc == ERROR_SUCCESS

    # -- служебное ---------------------------------------------------------
    def _enum_interfaces(self) -> list[tuple[GUID, str]]:
        plist = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        rc = wlanapi.WlanEnumInterfaces(self._handle, None, ctypes.byref(plist))
        if rc != ERROR_SUCCESS:
            raise WlanError("WlanEnumInterfaces", rc)
        try:
            count = plist.contents.dwNumberOfItems
            base = ctypes.addressof(plist.contents) + WLAN_INTERFACE_INFO_LIST.InterfaceInfo.offset
            items = (WLAN_INTERFACE_INFO * count).from_address(base)
            result = []
            for i in range(count):
                info = items[i]
                result.append((GUID.from_bytes(bytes(info.InterfaceGuid)), info.strInterfaceDescription))
            return result
        finally:
            wlanapi.WlanFreeMemory(plist)

    def _ensure_software_radio_on(self) -> None:
        """Включает software radio, если адаптер был выключен (частый случай для USB)."""
        size = wt.DWORD()
        data = ctypes.c_void_p()
        rc = wlanapi.WlanQueryInterface(
            self._handle,
            ctypes.byref(self.interface_guid),
            WLAN_INTF_OPCODE_RADIO_STATE,
            None,
            ctypes.byref(size),
            ctypes.byref(data),
            None,
        )
        if rc != ERROR_SUCCESS or not data:
            return
        try:
            radio = ctypes.cast(data, ctypes.POINTER(WLAN_RADIO_STATE)).contents
            count = min(int(radio.dwNumberOfPhys), WLAN_MAX_PHY_INDEX)
            phys = [
                (
                    int(radio.PhyRadioState[i].dwPhyIndex),
                    int(radio.PhyRadioState[i].dot11SoftwareRadioState),
                    int(radio.PhyRadioState[i].dot11HardwareRadioState),
                )
                for i in range(count)
            ]
        finally:
            wlanapi.WlanFreeMemory(data)

        if any(hw == DOT11_RADIO_STATE_OFF for _idx, _sw, hw in phys):
            self.radio_hardware_off = True
        for phy_index, software, _hardware in phys:
            if software == DOT11_RADIO_STATE_ON:
                continue
            state = WLAN_PHY_RADIO_STATE()
            state.dwPhyIndex = phy_index
            state.dot11SoftwareRadioState = DOT11_RADIO_STATE_ON
            rc = wlanapi.WlanSetInterface(
                self._handle,
                ctypes.byref(self.interface_guid),
                WLAN_INTF_OPCODE_RADIO_STATE,
                ctypes.sizeof(WLAN_PHY_RADIO_STATE),
                ctypes.byref(state),
                None,
            )
            if rc == ERROR_SUCCESS:
                self.radio_enabled += 1
        if self.radio_enabled:
            time.sleep(0.4)

    def _on_notification(self, data_ptr, _context) -> None:
        try:
            data = data_ptr.contents
            if data.NotificationSource & WLAN_NOTIFICATION_SOURCE_ACM:
                if data.NotificationCode == WLAN_NOTIFICATION_ACM_SCAN_COMPLETE:
                    self._scan_failed = False
                    self._scan_event.set()
                elif data.NotificationCode == WLAN_NOTIFICATION_ACM_SCAN_FAIL:
                    self._scan_failed = True
                    self._scan_event.set()
        except Exception:
            pass

    @property
    def description(self) -> str:
        return self._description

    @property
    def interface_guid(self) -> GUID:
        assert self._guid is not None
        return self._guid

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            wlanapi.WlanCloseHandle(self._handle, None)
        except Exception:
            pass

    # -- сканирование ------------------------------------------------------
    def scan(self, timeout: float = 10.0, settle: float = 0.25) -> None:
        if self._closed:
            raise WlanError("WLAN API уже закрыт")
        self._scan_event.clear()
        self._scan_failed = False
        rc = wlanapi.WlanScan(self._handle, ctypes.byref(self.interface_guid), None, None, None)
        if rc != ERROR_SUCCESS:
            raise WlanError("WlanScan", rc)
        if self._notifications_ok:
            if not self._scan_event.wait(timeout):
                # Уведомление могло не прийти — не считаем это фатальным.
                time.sleep(1.0)
        else:
            time.sleep(min(timeout, 4.0))
        time.sleep(settle)

    def bss_list(self) -> list[BssEntry]:
        plist = ctypes.POINTER(WLAN_BSS_LIST)()
        rc = wlanapi.WlanGetNetworkBssList(
            self._handle,
            ctypes.byref(self.interface_guid),
            None,
            DOT11_BSS_TYPE_INFRASTRUCTURE,
            False,
            None,
            ctypes.byref(plist),
        )
        if rc != ERROR_SUCCESS:
            raise WlanError("WlanGetNetworkBssList", rc)
        try:
            count = plist.contents.dwNumberOfItems
            if not count:
                return []
            base = ctypes.addressof(plist.contents) + WLAN_BSS_LIST.wlanBssEntries.offset
            entries = (WLAN_BSS_ENTRY * count).from_address(base)
            result: list[BssEntry] = []
            for entry in entries:
                addr = ctypes.addressof(entry)
                ies = b""
                if 0 < entry.ulIeSize <= 4096 and entry.ulIeOffset > 0:
                    try:
                        ies = ctypes.string_at(addr + entry.ulIeOffset, entry.ulIeSize)
                    except Exception:
                        ies = b""
                rate_len = min(int(entry.wlanRateSet.uRateSetLength), 126)
                rate_values = [
                    (int(entry.wlanRateSet.usRateSet[i]) & 0x7FFF)
                    for i in range(rate_len)
                    if entry.wlanRateSet.usRateSet[i] & 0x7FFF
                ]
                max_rate = max(rate_values) * 0.5 if rate_values else 0.0
                freq_raw = int(entry.ulChCenterFrequency)
                # ulChCenterFrequency — в кГц; на всякий случай поддержим и МГц.
                freq_mhz = freq_raw // 1000 if freq_raw > 100000 else freq_raw
                quality = int(entry.uLinkQuality)
                rssi_dbm = int(entry.lRssi)
                if rssi_dbm == 0 and quality:
                    rssi_dbm = quality // 2 - 100
                if quality == 0 and rssi_dbm:
                    quality = max(0, min(100, 2 * (rssi_dbm + 100)))
                result.append(
                    BssEntry(
                        bssid=_bssid_text(entry.dot11Bssid),
                        ssid=_ssid_text(entry.dot11Ssid),
                        rssi=quality,
                        frequency_mhz=freq_mhz,
                        security=security_from_ies(ies, int(entry.usCapabilityInformation)),
                        capability=int(entry.usCapabilityInformation),
                        phy_type=_PHY_TYPE_NAMES.get(
                            int(entry.dot11PhyType), f"type {int(entry.dot11PhyType)}"
                        ),
                        beacon_period=int(entry.usBeaconPeriod),
                        max_rate_mbps=max_rate,
                        bss_type=_BSS_TYPE_NAMES.get(int(entry.dot11BssType), str(int(entry.dot11BssType))),
                        rssi_dbm=rssi_dbm,
                    )
                )
            return result
        finally:
            wlanapi.WlanFreeMemory(plist)

    # -- текущее подключение ----------------------------------------------
    def current_connection(self) -> ConnectionInfo | None:
        size = wt.DWORD()
        data = ctypes.c_void_p()
        rc = wlanapi.WlanQueryInterface(
            self._handle,
            ctypes.byref(self.interface_guid),
            WLAN_INTF_OPCODE_CURRENT_CONNECTION,
            None,
            ctypes.byref(size),
            ctypes.byref(data),
            None,
        )
        if rc != ERROR_SUCCESS or not data:
            return None
        try:
            attrs = ctypes.cast(data, ctypes.POINTER(WLAN_CONNECTION_ATTRIBUTES)).contents
            assoc = attrs.wlanAssociationAttributes
            return ConnectionInfo(
                ssid=_ssid_text(assoc.dot11Ssid),
                bssid=_bssid_text(assoc.dot11Bssid),
                profile=str(attrs.strProfileName),
                state=int(attrs.isState),
                signal=int(assoc.wlanSignalQuality),
            )
        finally:
            wlanapi.WlanFreeMemory(data)

    def disconnect(self, timeout: float = 2.0) -> None:
        wlanapi.WlanDisconnect(self._handle, ctypes.byref(self.interface_guid), None)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            conn = self.current_connection()
            if not conn or conn.state != WLAN_INTERFACE_STATE_CONNECTED:
                break
            time.sleep(0.1)
        time.sleep(0.1)

    # -- подключение -------------------------------------------------------
    def _make_connection_params(
        self,
        ssid: str,
        bssid: str,
        xml: str | None,
        profile_name: str | None,
    ) -> tuple[WLAN_CONNECTION_PARAMETERS, list]:
        ssid_struct = DOT11_SSID()
        raw = ssid.encode("utf-8")[:DOT11_SSID_MAX_LENGTH]
        ssid_struct.uSSIDLength = len(raw)
        for i, b in enumerate(raw):
            ssid_struct.ucSSID[i] = b

        params = WLAN_CONNECTION_PARAMETERS()
        params.wlanConnectionMode = (
            WLAN_CONNECTION_MODE_TEMPORARY_PROFILE if xml is not None else WLAN_CONNECTION_MODE_PROFILE
        )
        params.strProfile = xml if xml is not None else profile_name
        params.pDot11Ssid = ctypes.pointer(ssid_struct) if xml is not None else None
        params.pDesiredBssidList = None
        params.dot11BssType = DOT11_BSS_TYPE_INFRASTRUCTURE
        params.dwFlags = 0

        keepalive: list = [ssid_struct]
        if xml is not None and bssid:
            bssid_list = DOT11_BSSID_LIST()
            bssid_list.Header.Type = 0x80  # NDIS_OBJECT_TYPE_DEFAULT
            bssid_list.Header.Revision = 1  # DOT11_BSSID_LIST_REVISION_1
            bssid_list.Header.Size = ctypes.sizeof(DOT11_BSSID_LIST)
            bssid_list.uNumOfEntries = 1
            bssid_list.uTotalNumOfEntries = 1
            for i, b in enumerate(bytes.fromhex(bssid.replace(":", ""))[:6]):
                bssid_list.BSSIDs[0][i] = b
            params.pDesiredBssidList = ctypes.pointer(bssid_list)
            keepalive.append(bssid_list)
        return params, keepalive

    def connect_temporary(self, ssid: str, bssid: str, password: str, security: SecurityType) -> None:
        xml = _profile_xml(ssid, bssid, password, security)
        params, _keep = self._make_connection_params(ssid, bssid, xml, None)
        rc = wlanapi.WlanConnect(self._handle, ctypes.byref(self.interface_guid), ctypes.byref(params), None)
        if rc != ERROR_SUCCESS:
            # Некоторые драйверы/версии Windows игнорируют список BSSID или
            # отвергают его — пробуем без ограничения по BSSID, BSSID проверим после.
            params, _keep = self._make_connection_params(ssid, "", xml, None)
            rc = wlanapi.WlanConnect(self._handle, ctypes.byref(self.interface_guid), ctypes.byref(params), None)
        if rc != ERROR_SUCCESS:
            raise WlanError("WlanConnect (временный профиль)", rc)

    def connect_profile(self, profile_name: str, ssid: str = "") -> None:
        params, _keep = self._make_connection_params(ssid, "", None, profile_name)
        rc = wlanapi.WlanConnect(self._handle, ctypes.byref(self.interface_guid), ctypes.byref(params), None)
        if rc != ERROR_SUCCESS:
            raise WlanError("WlanConnect (профиль)", rc)

    def _wait_for_target(self, bssid: str, timeout: float) -> VerifyResult:
        deadline = time.monotonic() + timeout
        saw_progress = False
        disconnected_since: float | None = None
        while time.monotonic() < deadline:
            conn = self.current_connection()
            if conn and conn.state == WLAN_INTERFACE_STATE_CONNECTED:
                if conn.bssid.upper() == bssid.upper():
                    return VerifyResult.OK
                disconnected_since = None
            elif conn and conn.state in (
                WLAN_INTERFACE_STATE_DISCONNECTING,
                WLAN_INTERFACE_STATE_ASSOCIATING,
                WLAN_INTERFACE_STATE_DISCOVERING,
                WLAN_INTERFACE_STATE_AUTHENTICATING,
            ):
                saw_progress = True
                disconnected_since = None
            elif conn is None:
                if saw_progress:
                    if disconnected_since is None:
                        disconnected_since = time.monotonic()
                    elif time.monotonic() - disconnected_since > 1.5:
                        return VerifyResult.WRONG_PASSWORD
            time.sleep(0.15)
        return VerifyResult.TIMEOUT

    def verify_password(
        self,
        ssid: str,
        bssid: str,
        password: str,
        security: SecurityType,
        timeout: float = 12.0,
    ) -> VerifyResult:
        # Даже если адаптер уже подключён к этой точке, это не доказывает, что
        # пароль в CSV верный (подключение могло использовать другой сохранённый
        # профиль). Поэтому всегда проверяем именно пароль из CSV.
        current = self.current_connection()
        if current and current.state == WLAN_INTERFACE_STATE_CONNECTED:
            self.disconnect()

        try:
            self.connect_temporary(ssid, bssid, password, security)
        except WlanError:
            return VerifyResult.ERROR

        result = self._wait_for_target(bssid, timeout)
        if result == VerifyResult.TIMEOUT:
            conn = self.current_connection()
            if conn and conn.state == WLAN_INTERFACE_STATE_CONNECTED and conn.bssid.upper() != bssid.upper():
                return VerifyResult.WRONG_BSSID
        return result

    def restore(self, profile_name: str, timeout: float = 15.0) -> bool:
        if not profile_name:
            return False
        current = self.current_connection()
        if current and current.state == WLAN_INTERFACE_STATE_CONNECTED and current.profile == profile_name:
            return True
        try:
            self.connect_profile(profile_name)
        except WlanError:
            return False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            conn = self.current_connection()
            if conn and conn.state == WLAN_INTERFACE_STATE_CONNECTED and conn.profile == profile_name:
                return True
            time.sleep(0.2)
        return False

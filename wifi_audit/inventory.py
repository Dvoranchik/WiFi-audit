"""Чтение и нормализация инвентарного CSV со списком точек доступа."""

from __future__ import annotations

import codecs
import csv
import io
import os
import re
from dataclasses import dataclass, field

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{12}$")


class InventoryError(Exception):
    """Файл не удалось разобрать; сообщение пригодно для показа пользователю."""


# Ключ -> допустимые варианты заголовка (в нормализованном виде).
_HEADER_ALIASES: dict[str, set[str]] = {
    "bssid": {
        "bssid", "bssid ap", "bssid точки", "bssid точки доступа", "mac", "mac адрес",
        "mac адрес ap", "мак", "мак адрес", "mac address", "physical address",
        "физический адрес", "аппаратный адрес", "hw address", "bssid mac",
    },
    "ssid": {
        "ssid", "essid", "ssid сети", "имя сети", "название сети", "network name", "сеть",
        "имя wi fi сети", "название wi fi сети",
    },
    "password": {
        "password", "pass", "key", "пароль", "пароль wifi", "пароль wi fi", "psk", "wpa",
        "wpa key", "wpa psk", "ключ", "ключ сети", "network key", "wifi key",
        "wi fi key", "ключ wifi", "ключ wi fi", "пароль сети",
    },
}


def _norm_header(value: str) -> str:
    value = value.strip().lower().replace("ё", "е")
    value = re.sub(r"[^0-9a-zа-я]+", " ", value)
    return " ".join(value.split())


def normalize_bssid(value: str | None) -> str | None:
    """Приводит MAC/BSSID к виду AA:BB:CC:DD:EE:FF. Возвращает None, если это не MAC."""
    if not value:
        return None
    compact = re.sub(r"[\s:.\-]", "", str(value).strip())
    if not _MAC_RE.match(compact):
        return None
    compact = compact.upper()
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2))


@dataclass
class InventoryRow:
    index: int
    bssid: str
    ssid: str
    password: str
    values: dict[str, str] = field(default_factory=dict)


@dataclass
class Inventory:
    path: str
    headers: list[str]
    rows: list[InventoryRow]
    bssid_column: str
    ssid_column: str | None
    password_column: str | None
    encoding: str
    delimiter: str
    warnings: list[str] = field(default_factory=list)


def _decode(data: bytes) -> tuple[str, str]:
    if data.startswith(codecs.BOM_UTF8):
        return data.decode("utf-8-sig"), "utf-8-sig"
    if data.startswith(codecs.BOM_UTF16_LE) or data.startswith(codecs.BOM_UTF16_BE):
        return data.decode("utf-16"), "utf-16"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("cp1251"), "cp1251"


def _detect_delimiter(text: str) -> str:
    first_line = ""
    for line in text.splitlines():
        if line.strip():
            first_line = line
            break
    counts = {d: first_line.count(d) for d in (";", ",", "\t", "|")}
    best = max(counts, key=counts.get)
    if counts[best] > 0:
        return best
    try:
        return csv.Sniffer().sniff(text[:8192], delimiters=";,\t|").delimiter
    except csv.Error:
        return ";"


def _pick_column(headers: list[str], kind: str) -> int | None:
    aliases = _HEADER_ALIASES[kind]
    normalized = [_norm_header(h) for h in headers]
    for i, h in enumerate(normalized):
        if h in aliases:
            return i
    # Мягкий поиск: заголовок содержит характерное слово.
    needles = {
        "bssid": ("bssid", "mac"),
        "ssid": ("ssid", "имя сети", "название сети"),
        "password": ("пароль", "password", "psk", "ключ"),
    }[kind]
    for i, h in enumerate(normalized):
        if any(n in h for n in needles):
            return i
    return None


def _looks_like_bssid(value: str) -> bool:
    return normalize_bssid(value) is not None


def _guess_bssid_column(table: list[list[str]], headers_len: int) -> int | None:
    """Ищет колонку, в которой большинство значений похожи на MAC."""
    sample = [r for r in table[:50] if len(r) >= headers_len]
    if not sample:
        return None
    best_idx, best_ratio = None, 0.0
    for i in range(headers_len):
        cells = [r[i] for r in sample if i < len(r) and r[i].strip()]
        if not cells:
            continue
        ratio = sum(1 for c in cells if _looks_like_bssid(c)) / len(cells)
        if ratio > best_ratio:
            best_idx, best_ratio = i, ratio
    return best_idx if best_ratio >= 0.6 else None


def load_inventory(path: str) -> Inventory:
    if not os.path.isfile(path):
        raise InventoryError(f"Файл не найден: {path}")

    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except PermissionError as exc:
        raise InventoryError(
            f"Нет доступа к файлу: {path}\n"
            "Скорее всего, он открыт в Excel. Закройте файл и повторите."
        ) from exc

    if not data.strip():
        raise InventoryError(
            f"Файл пуст: {path}\n"
            "Сохраните инвентаризацию в CSV (разделитель ; или ,) и заполните строки."
        )

    if data.startswith(b"PK\x03\x04"):
        raise InventoryError(
            f"{os.path.basename(path)} — это XLSX (ZIP-контейнер), а не CSV.\n"
            "Откройте файл в Excel и выполните «Файл → Сохранить как → CSV UTF-8 (разделитель — запятая)», "
            "либо пришлите настоящий CSV."
        )

    text, encoding = _decode(data)
    # Старые выгрузки бывают с одиночным CR (Mac/Unix-смесь); csv.reader на таком падает.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    delimiter = _detect_delimiter(text)

    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    table = [row for row in reader if any(cell.strip() for cell in row)]
    if not table:
        raise InventoryError("В файле нет ни одной непустой строки.")

    headers = [h.strip() for h in table[0]]
    # Выгрузки часто заканчиваются пустыми колонками: address;;;; — их убираем.
    while headers and not headers[-1]:
        headers.pop()
    if not any(headers):
        raise InventoryError("Первая строка пустая — ожидался заголовок с колонкой BSSID.")

    bssid_idx = _pick_column(headers, "bssid")
    ssid_idx = _pick_column(headers, "ssid")
    password_idx = _pick_column(headers, "password")

    data_rows = table[1:]
    warnings: list[str] = []

    if bssid_idx is None:
        bssid_idx = _guess_bssid_column(data_rows, len(headers))
        if bssid_idx is None:
            raise InventoryError(
                "Не нашёл колонку BSSID. Ожидались заголовки вроде "
                "«BSSID», «MAC», «MAC-адрес». Найдены: " + ", ".join(headers)
            )
        warnings.append(f"Колонка BSSID определена по значениям: «{headers[bssid_idx]}»")

    if password_idx is None:
        warnings.append("Колонка с паролем не найдена — пароли проверяться не будут.")

    rows: list[InventoryRow] = []
    seen: dict[str, int] = {}
    for line_no, raw in enumerate(data_rows, start=2):
        if bssid_idx >= len(raw):
            continue
        bssid = normalize_bssid(raw[bssid_idx])
        if bssid is None:
            if any(cell.strip() for cell in raw):
                warnings.append(f"Строка {line_no}: пропущен некорректный BSSID «{raw[bssid_idx].strip()}»")
            continue
        if bssid in seen:
            warnings.append(f"Строка {line_no}: дубликат BSSID {bssid} (первая строка — {seen[bssid]})")
            continue
        seen[bssid] = line_no

        def cell(idx: int | None) -> str:
            if idx is None or idx >= len(raw):
                return ""
            return raw[idx].strip()

        ssid = cell(ssid_idx)
        password = raw[password_idx] if password_idx is not None and password_idx < len(raw) else ""
        password = password.rstrip("\r\n")
        values = {headers[i] if i < len(headers) else f"col{i + 1}": (raw[i] if i < len(raw) else "")
                  for i in range(len(headers))}
        rows.append(
            InventoryRow(
                index=len(rows),
                bssid=bssid,
                ssid=ssid,
                password=password,
                values=values,
            )
        )

    if not rows:
        raise InventoryError(
            "В файле не нашлось ни одной строки с корректным BSSID.\n"
            "Проверьте, что колонка BSSID содержит адреса вида AA:BB:CC:DD:EE:FF."
        )

    # Убираем техническую колонку с паролем из отображаемых значений? Нет: пользователь
    # просил показывать те же поля, что в CSV.
    return Inventory(
        path=path,
        headers=headers,
        rows=rows,
        bssid_column=headers[bssid_idx],
        ssid_column=headers[ssid_idx] if ssid_idx is not None else None,
        password_column=headers[password_idx] if password_idx is not None else None,
        encoding=encoding,
        delimiter=delimiter,
        warnings=warnings,
    )

"""Разбор готовых трассировок.

Понимает вывод:
* Windows tracert (русский и английский, с именами узлов и без, IPv4/IPv6);
* traceroute (Linux / macOS / BSD), в т.ч. несколько адресов на одном TTL;
* tracepath;
* mtr --report;
* JSON, сохранённый этой программой;
* просто список IP-адресов (по одному в строке).
"""

from __future__ import annotations

import json
import re
from typing import List, Optional, Tuple

from .models import Hop, TraceResult
from .netutil import parse_ip

# --- регулярные выражения ---------------------------------------------------

_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_RE = re.compile(rf"(?<![\w.]){_OCT}(?:\.{_OCT}){{3}}(?![\w]|\.\d)")
IPV6_CAND_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%[\w.]+)?(?![\w:])")
BRACKET_RE = re.compile(
    r"(?:(?P<host>[^\s\[\]()<>*]+)\s+)?(?P<br>[\[(])(?P<ip>[0-9A-Za-z:.%_\-]+)[\])]")
TOKEN_RE = re.compile(
    r"(?P<star>(?<!\S)\*(?!\S))"
    r"|(?P<time>(?<![\w.\-])(?P<lt><\s*)?(?P<val>\d+(?:[.,]\d+)?)\s*(?:ms|мс|msec)(?![\w]))",
    re.IGNORECASE)
HOP_RE = re.compile(r"^\s*(\d{1,3})(?:\??:|\.\|--|\.(?=\s)|\s|$)")
MTR_RE = re.compile(
    r"^\s*(\d{1,3})\.(?:\|--)?\s+(?:AS\S+\s+)?(\S+)\s+(\d+(?:\.\d+)?)%?\s+(\d+)\s+"
    r"(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)")
MTR_CONT_RE = re.compile(r"^\s*\|\s*`\|--\s+(\S+)")
TR_NOTE_RE = re.compile(r"(?<!\S)!(?:[A-Za-z]|\d+|<\d+>)(?:-\d+)?(?!\S)")
WIN_NOTE_RE = re.compile(r"(?:сообщает|reports)\s*:\s*(.+?)\s*$", re.IGNORECASE)
WIN_ERR_RE = re.compile(r"(Сбой передачи.*|Общий сбой.*|Transmit error.*|General failure.*)$", re.IGNORECASE)
HEADER_RES = [
    re.compile(r"(?:Tracing route to|Трассировка маршрута к)\s+(?P<name>[^\s\[]+)(?:\s+\[(?P<ip>[^\]]+)\])?",
               re.IGNORECASE),
    re.compile(r"traceroute6?\s+to\s+(?P<name>\S+?)(?:\s+\((?P<ip>[^)]+)\))?[\s,]", re.IGNORECASE),
    re.compile(r"Трассировка\s+(?:маршрута\s+)?(?:к|до)\s+(?P<name>[^\s\[]+)(?:\s+\[(?P<ip>[^\]]+)\])?",
               re.IGNORECASE),
]
HEADER_HINT_RE = re.compile(r"(trac|трасс|hops|прыжк|maximum|максим)", re.IGNORECASE)

TR_NOTES = {
    "!H": "!H Узел недоступен.", "!N": "!N Сеть недоступна.", "!P": "!P Протокол недоступен.",
    "!X": "!X Связь административно запрещена.", "!S": "!S Ошибка маршрута источника.",
    "!F": "!F Требуется фрагментация.", "!U": "!U Узел неизвестен.", "!W": "!W Сеть неизвестна.",
    "!A": "!A Сеть запрещена.", "!Z": "!Z Узел запрещён.", "!C": "!C Связь запрещена.",
}


class ParsedLine:
    __slots__ = ("entries", "rtts", "note")

    def __init__(self) -> None:
        self.entries: List[Tuple[Optional[str], str]] = []   # (host, ip)
        self.rtts: List[Optional[float]] = []
        self.note = ""


def _looks_like_host(token: str) -> bool:
    if token.lower() in ("ms", "мс", "msec", "*"):
        return False
    return bool(re.fullmatch(r"[\w.\-]+", token)) and any(ch.isalpha() for ch in token)


def parse_rest(text: str) -> ParsedLine:
    """Разобрать часть строки после номера узла."""
    out = ParsedLine()
    masked = list(text)
    found = []

    def mask(a: int, b: int) -> None:
        for k in range(a, b):
            masked[k] = " "

    for m in BRACKET_RE.finditer(text):
        ip = parse_ip(m.group("ip"))
        if ip is None:
            continue
        host = m.group("host")
        start = m.start()
        if host is not None:
            hip = parse_ip(host)
            if hip is not None and hip == ip:
                host = None                       # «1.1.1.1 (1.1.1.1)»
            elif not _looks_like_host(host):
                host, start = None, m.start("br")
        found.append((start, host, str(ip)))
        mask(start, m.end())

    rest = "".join(masked)
    for m in IPV4_RE.finditer(rest):
        found.append((m.start(), None, m.group(0)))
        mask(m.start(), m.end())
    rest = "".join(masked)
    for m in IPV6_CAND_RE.finditer(rest):
        ip = parse_ip(m.group(0))
        if ip is not None and ip.version == 6:
            found.append((m.start(), None, str(ip)))
            mask(m.start(), m.end())
    rest = "".join(masked)

    found.sort(key=lambda x: x[0])
    out.entries = [(h, ip) for _, h, ip in found]

    for m in TOKEN_RE.finditer(rest):
        if m.group("star"):
            out.rtts.append(None)
        else:
            val = float(m.group("val").replace(",", "."))
            if m.group("lt"):
                val = val / 2.0   # «<1 мс» → 0.5
            out.rtts.append(val)

    wm = WIN_NOTE_RE.search(text)
    if wm:
        out.note = wm.group(1)
    else:
        em = WIN_ERR_RE.search(text)
        if em:
            out.note = em.group(1).strip()
        else:
            tm = TR_NOTE_RE.search(rest)
            if tm:
                code = tm.group(0)
                out.note = TR_NOTES.get(code[:2], f"{code} Узел недоступен.")
    return out


def _merge(hop: Hop, parsed: ParsedLine) -> None:
    for host, ip in parsed.entries:
        if hop.addr is None:
            hop.addr, hop.host = ip, host
        elif ip != hop.addr and ip not in hop.extra_addrs:
            hop.extra_addrs.append(ip)
        if host and not hop.host and ip == hop.addr:
            hop.host = host
    hop.rtts.extend(parsed.rtts)
    if parsed.note and not hop.note:
        hop.note = parsed.note


class TraceParser:
    """Построчный разборщик. Подходит и для «живого» вывода утилиты."""

    def __init__(self) -> None:
        self.hops: dict = {}
        self.last_ttl: Optional[int] = None
        self.target: Optional[str] = None
        self.target_ip: Optional[str] = None
        self.numbered = False
        self._loose: List[ParsedLine] = []

    def _header(self, line: str) -> bool:
        for rx in HEADER_RES:
            m = rx.search(line)
            if m:
                name = m.group("name").strip(",")
                ip = m.group("ip")
                self.target = name
                if ip and parse_ip(ip):
                    self.target_ip = str(parse_ip(ip))
                elif parse_ip(name):
                    self.target_ip = str(parse_ip(name))
                return True
        return False

    def feed(self, line: str) -> Optional[Hop]:
        """Обработать строку. Возвращает созданный/обновлённый узел или None."""
        line = line.rstrip("\r\n")
        if not line.strip() or "[LOCALHOST]" in line:
            return None
        if self.target is None and not HOP_RE.match(line) and self._header(line):
            return None

        m = MTR_RE.match(line)
        if m:
            ttl, host = int(m.group(1)), m.group(2)
            loss = float(m.group(3))
            last, avg, best, worst = (float(m.group(i)) for i in (5, 6, 7, 8))
            hop = self.hops.setdefault(ttl, Hop(ttl=ttl))
            self.numbered, self.last_ttl = True, ttl
            if host != "???":
                ip = parse_ip(host)
                if ip is not None:
                    hop.addr = str(ip)
                else:
                    hop.host = host
                hop.rtts = [best, avg, worst] if loss < 100 else [None, None, None]
                if 0 < loss < 100:
                    hop.note = f"mtr: потери {loss:g}%"
            else:
                hop.rtts = [None, None, None]
            return hop

        m = MTR_CONT_RE.match(line)
        if m and self.last_ttl is not None:
            hop = self.hops[self.last_ttl]
            ip = parse_ip(m.group(1))
            if ip is not None and str(ip) != hop.addr and str(ip) not in hop.extra_addrs:
                hop.extra_addrs.append(str(ip))
            return hop

        m = HOP_RE.match(line)
        if m:
            ttl = int(m.group(1))
            if ttl == 0 or ttl > 255:
                return None
            parsed = parse_rest(line[m.end():])
            if not parsed.entries and not parsed.rtts and "no reply" in line.lower():
                parsed.rtts = [None]
            if not parsed.entries and not parsed.rtts and not parsed.note:
                # строка вида «1?: [LOCALHOST]» или мусор
                if self.target is None:
                    self._header(line)
                return None
            hop = self.hops.setdefault(ttl, Hop(ttl=ttl))
            _merge(hop, parsed)
            self.numbered, self.last_ttl = True, ttl
            return hop

        parsed = parse_rest(line)
        if line[:1].isspace() and self.last_ttl is not None and parsed.entries and parsed.rtts:
            hop = self.hops[self.last_ttl]          # продолжение (другие адреса на том же TTL)
            _merge(hop, parsed)
            return hop
        if parsed.entries and not HEADER_HINT_RE.search(line):
            self._loose.append(parsed)
        return None

    def result(self) -> TraceResult:
        tr = TraceResult(target=self.target or "", target_ip=self.target_ip, completed=True)
        if self.hops:
            tr.hops = [self.hops[k] for k in sorted(self.hops)]
        elif self._loose:
            for i, p in enumerate(self._loose, start=1):
                hop = Hop(ttl=i)
                _merge(hop, p)
                tr.hops.append(hop)
        if not tr.target_ip:
            responded = [h for h in tr.hops if h.addr]
            if responded:
                tr.target_ip = responded[-1].addr
                if not tr.target:
                    tr.target = tr.target_ip
        for h in tr.hops:
            h.reached = bool(tr.target_ip) and (h.addr == tr.target_ip or tr.target_ip in h.extra_addrs)
        # после первого «дошедшего» узла всё остальное — повторы назначения
        for i, h in enumerate(tr.hops):
            if h.reached:
                tr.hops = tr.hops[:i + 1]
                break
        if tr.hops:
            tr.max_hops = max(tr.max_hops, tr.hops[-1].ttl)
        return tr


def parse_text(text: str) -> TraceResult:
    """Разобрать текст готовой трассировки (любого поддерживаемого формата)."""
    stripped = text.strip().lstrip("﻿")
    if stripped.startswith("{"):
        data = json.loads(stripped)
        return TraceResult.from_dict(data)
    p = TraceParser()
    for line in stripped.splitlines():
        p.feed(line)
    tr = p.result()
    if not tr.hops:
        raise ValueError("Не удалось найти в тексте ни одного узла трассировки.")
    return tr


def decode_bytes(data: bytes) -> str:
    """Определить кодировку файла трассировки.

    Учитывает UTF-16 (вывод PowerShell «> file.txt»), UTF-8 и консольные
    кодировки Windows (cp866) / ANSI (cp1251).
    """
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    if len(data) > 4 and data[1::2].count(0) > len(data) // 4:
        try:
            return data.decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    best, best_score = None, -1
    for enc in ("cp866", "cp1251", "koi8-r"):
        txt = data.decode(enc, errors="replace")
        score = sum(txt.count(w) for w in (" мс", "Трасс", "прыжк", "Превыш", "узел", "маршрут"))
        if score > best_score:
            best, best_score = txt, score
    return best or data.decode("latin-1")

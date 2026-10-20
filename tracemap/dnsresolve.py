"""Надёжное преобразование имени узла в IP-адрес.

Порядок:
1. Очистка ввода: «https://ya.ru/path», «ya.ru:443», «user@host», невидимые символы
   из буфера обмена, точка в конце, кириллические домены (IDN → punycode).
2. Системный резолвер (getaddrinfo) — как у tracert.
3. Если системный DNS не ответил или вернул «фиктивный» адрес VPN-клиента
   (FakeDNS, диапазон 198.18.0.0/15) — прямой запрос к публичным DNS по UDP
   (Яндекс, Google, Cloudflare), затем DNS-over-HTTPS по IP-адресу резолвера.
"""

from __future__ import annotations

import ipaddress
import json
import random
import re
import select
import socket
import struct
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

PUBLIC_DNS: Tuple[str, ...] = ("77.88.8.8", "8.8.8.8", "1.1.1.1")
DOH_ENDPOINTS: Tuple[str, ...] = (
    "https://1.1.1.1/dns-query?name={name}&type={qtype}",
    "https://8.8.8.8/resolve?name={name}&type={qtype}",
)
FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")
UDP_TIMEOUT = 2.5

QTYPE_A, QTYPE_AAAA, QTYPE_CNAME = 1, 28, 5

_INVISIBLE = dict.fromkeys(map(ord, "​‌‍‎‏⁠﻿­"), None)
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


class ResolveError(Exception):
    """Имя не удалось разрешить. Текст содержит причины по каждому способу."""


class NxDomain(Exception):
    pass


@dataclass
class Resolved:
    ip: str
    family: int
    host: str            # очищенное имя (или IP), как его стоит показывать
    via: str = ""        # пусто = системный DNS; иначе способ, которым получен адрес
    note: str = ""       # пояснение для журнала (например, про FakeDNS)


# ---------------------------------------------------------------------------
# Очистка ввода

def clean_target(text: str) -> str:
    """Привести ввод пользователя к имени узла или IP-адресу."""
    t = (text or "").translate(_INVISIBLE).replace(" ", " ").strip()
    t = _SCHEME_RE.sub("", t)
    for sep in ("/", "?", "#", "\\"):
        t = t.split(sep, 1)[0]
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    t = t.strip()
    if t.startswith("["):                          # [2001:db8::1]:443
        end = t.find("]")
        t = t[1:end] if end > 0 else t[1:]
    elif t.count(":") == 1:                        # host:port (IPv6 содержит ≥ 2 двоеточий)
        t = t.split(":", 1)[0]
    t = t.strip().rstrip(".")
    if t and not _ip(t):
        t = t.lower()
    return t


def _ip(text: str):
    try:
        return ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return None


def to_ascii_host(host: str) -> str:
    """Кириллический домен → punycode (IDNA 2008, если есть пакет idna)."""
    try:
        host.encode("ascii")
        return host
    except UnicodeEncodeError:
        pass
    try:
        import idna  # ставится вместе с requests
        return idna.encode(host, uts46=True).decode("ascii")
    except Exception:
        pass
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ResolveError(f"Недопустимое доменное имя «{host}»: {e}") from e


def is_fake_ip(ip: str) -> bool:
    a = _ip(ip)
    return a is not None and a.version == 4 and a in FAKE_IP_NET


# ---------------------------------------------------------------------------
# Минимальный DNS-клиент (UDP)

def build_query(name: str, qtype: int, tid: int) -> bytes:
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)   # RD=1
    labels = [lab for lab in name.encode("ascii").split(b".") if lab]
    if not labels or any(len(lab) > 63 for lab in labels):
        raise ResolveError(f"Недопустимое доменное имя «{name}»")
    qname = b"".join(bytes([len(lab)]) + lab for lab in labels) + b"\0"
    return header + qname + struct.pack("!HH", qtype, 1)


def _skip_name(data: bytes, off: int) -> int:
    while True:
        if off >= len(data):
            raise ValueError("обрезанный ответ DNS")
        ln = data[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += ln + 1


def parse_response(data: bytes, tid: int, qtype: int) -> Optional[List[str]]:
    """Адреса из ответа DNS. None — чужой/битый пакет, NxDomain — домена нет."""
    if len(data) < 12:
        return None
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if rid != tid or not flags & 0x8000:
        return None
    rcode = flags & 0x000F
    if rcode == 3:
        raise NxDomain()
    if rcode != 0:
        return None
    try:
        off = 12
        for _ in range(qd):
            off = _skip_name(data, off) + 4
        out = []
        for _ in range(an):
            off = _skip_name(data, off)
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            off += rdlen
            if rtype == qtype == QTYPE_A and rdlen == 4:
                out.append(socket.inet_ntoa(rdata))
            elif rtype == qtype == QTYPE_AAAA and rdlen == 16:
                out.append(socket.inet_ntop(socket.AF_INET6, rdata))
        return out
    except (ValueError, struct.error, OSError):
        return None


def udp_query(name: str, qtype: int, servers: Sequence = PUBLIC_DNS, timeout: Optional[float] = None) -> List[str]:
    """Отправить запрос сразу всем серверам и взять первый ответ с адресами.

    servers — IP или (IP, порт). Бросает NxDomain, если домена нет,
    и OSError/TimeoutError, если никто не ответил.
    """
    timeout = UDP_TIMEOUT if timeout is None else timeout
    tid = random.randint(0, 0xFFFF)
    pkt = build_query(name, qtype, tid)
    addrs = [s if isinstance(s, tuple) else (s, 53) for s in servers]
    nx = empty = False
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        sent = 0
        for a in addrs:
            try:
                sock.sendto(pkt, a)
                sent += 1
            except OSError:
                continue
        if not sent:
            raise OSError("не удалось отправить запрос")
        deadline = time.monotonic() + timeout
        answered = set()
        while time.monotonic() < deadline and len(answered) < sent:
            r, _, _ = select.select([sock], [], [], max(0.0, deadline - time.monotonic()))
            if not r:
                break
            try:
                data, src = sock.recvfrom(4096)
            except (BlockingIOError, ConnectionResetError, OSError):
                continue                      # ICMP port unreachable от одного из серверов
            if (src[0], src[1]) not in addrs:
                continue
            try:
                res = parse_response(data, tid, qtype)
            except NxDomain:
                answered.add(src)
                nx = True
                continue
            if res is None:
                continue
            answered.add(src)
            if res:
                return res
            empty = True
    if nx:
        raise NxDomain()
    if empty:
        return []
    raise TimeoutError("публичные DNS не ответили")


def doh_query(name: str, qtype: int, timeout: float = 4.0) -> List[str]:
    """DNS-over-HTTPS (JSON API) по IP резолвера — работает, даже если системный DNS сломан."""
    qname = "AAAA" if qtype == QTYPE_AAAA else "A"
    last: Optional[Exception] = None
    for tmpl in DOH_ENDPOINTS:
        url = tmpl.format(name=name, qtype=qname)
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json",
                                                   "User-Agent": "TracertMap"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as e:
            last = e
            continue
        if data.get("Status") == 3:
            raise NxDomain()
        return [a["data"] for a in data.get("Answer") or [] if a.get("type") == qtype and a.get("data")]
    raise OSError(f"DNS-over-HTTPS недоступен: {last}")


# ---------------------------------------------------------------------------

def _system(host: str, prefer_ipv6: bool) -> Tuple[str, int]:
    infos = socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM)
    order = (socket.AF_INET6, socket.AF_INET) if prefer_ipv6 else (socket.AF_INET, socket.AF_INET6)
    for fam in order:
        for info in infos:
            if info[0] == fam:
                return info[4][0].split("%")[0], fam
    raise socket.gaierror("нет адресов IPv4/IPv6")


def _public(host: str, prefer_ipv6: bool, udp_servers: Sequence, use_doh: bool) -> Tuple[str, int, str]:
    qtypes = (QTYPE_AAAA, QTYPE_A) if prefer_ipv6 else (QTYPE_A, QTYPE_AAAA)
    errors = []
    methods = [("публичный DNS " + ", ".join(s if isinstance(s, str) else f"{s[0]}:{s[1]}"
                                             for s in udp_servers),
                lambda q: udp_query(host, q, udp_servers))]
    if use_doh:
        methods.append(("DNS-over-HTTPS", lambda q: doh_query(host, q)))
    for label, fn in methods:
        try:
            for q in qtypes:
                ips = [ip for ip in fn(q) if not is_fake_ip(ip)]
                if ips:
                    fam = socket.AF_INET6 if q == QTYPE_AAAA else socket.AF_INET
                    return ips[0], fam, label
            errors.append(f"{label}: нет записей A/AAAA")
        except NxDomain:
            raise ResolveError(f"домен {host} не существует ({label})")
        except (OSError, TimeoutError, ResolveError) as e:
            errors.append(f"{label}: {e}")
    raise ResolveError("; ".join(errors))


def resolve_target(target: str, prefer_ipv6: bool = False, udp_servers: Sequence = PUBLIC_DNS,
                   use_doh: bool = True) -> Resolved:
    """Разрешить ввод пользователя в IP. Бросает ResolveError с понятной причиной."""
    host = clean_target(target)
    if not host:
        raise ResolveError("пустой адрес")
    a = _ip(host)
    if a is not None:
        return Resolved(str(a), socket.AF_INET6 if a.version == 6 else socket.AF_INET, host)
    ascii_host = to_ascii_host(host)
    sys_error = ""
    note = ""
    try:
        ip, fam = _system(ascii_host, prefer_ipv6)
        if not is_fake_ip(ip):
            return Resolved(ip, fam, host)
        note = (f"Системный DNS вернул фиктивный адрес {ip} (FakeDNS VPN-клиента) — "
                f"запрашиваю настоящий адрес у публичного DNS.")
        sys_error = f"системный DNS: фиктивный адрес {ip}"
    except (socket.gaierror, UnicodeError, OSError) as e:
        sys_error = f"системный DNS: {e}"
    try:
        ip, fam, via = _public(ascii_host, prefer_ipv6, udp_servers, use_doh)
    except ResolveError as e:
        raise ResolveError(f"{sys_error}; {e}") from e
    if not note:
        note = f"Системный DNS не смог разрешить имя ({sys_error.split(': ', 1)[-1]}); адрес получен через {via}."
    return Resolved(ip, fam, host, via=via, note=note)


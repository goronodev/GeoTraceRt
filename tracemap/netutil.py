"""Сетевые вспомогательные функции: разбор адресов, DNS, контрольная сумма."""

from __future__ import annotations

import ipaddress
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Optional, Tuple

_dns_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="dns")


def parse_ip(text: str) -> Optional[ipaddress._BaseAddress]:
    """Вернуть объект адреса или None, если строка — не IP."""
    try:
        return ipaddress.ip_address(text.strip().strip("[]").split("%")[0])
    except ValueError:
        return None


def is_ip(text: str) -> bool:
    return parse_ip(text) is not None


def is_public(ip: str) -> bool:
    """True, если адрес глобально маршрутизируемый (его можно геолоцировать)."""
    a = parse_ip(ip)
    if a is None:
        return False
    if a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"):  # CGNAT
        return False
    return a.is_global and not a.is_multicast


def resolve(target: str, prefer_ipv6: bool = False) -> Tuple[str, int]:
    """Разрешить имя узла в IP. Возвращает (ip, family).

    Бросает dnsresolve.ResolveError, если имя не разрешается ни одним способом.
    """
    from .dnsresolve import resolve_target
    r = resolve_target(target, prefer_ipv6)
    return r.ip, r.family


def reverse_dns(ip: str, timeout: float = 2.0) -> Optional[str]:
    """Обратное разрешение имени с ограничением по времени."""
    fut = _dns_pool.submit(_gethostbyaddr, ip)
    try:
        return fut.result(timeout=timeout)
    except (FutureTimeout, Exception):
        return None


def _gethostbyaddr(ip: str) -> Optional[str]:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name if name and name != ip else None
    except (OSError, UnicodeError):
        return None


def checksum(data: bytes) -> int:
    """Контрольная сумма Интернета (RFC 1071) для ICMP."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def route_signature() -> Tuple[Optional[str], Optional[str]]:
    """Локальные адреса, с которых трафик уходит в интернет (IPv4, IPv6).

    Меняются при включении/выключении VPN (новый сетевой адаптер и маршрут по умолчанию),
    смене Wi-Fi и т.п. UDP-«подключение» пакетов не отправляет — проверка бесплатная.
    """
    sig = []
    for fam, dst in ((socket.AF_INET, "8.8.8.8"), (socket.AF_INET6, "2001:4860:4860::8888")):
        try:
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.connect((dst, 53))
                sig.append(s.getsockname()[0].split("%")[0])
        except OSError:
            sig.append(None)
    return sig[0], sig[1]

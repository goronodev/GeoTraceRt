"""Движки отправки запросов с ограниченным TTL.

Каждый движок умеет одно: отправить пачку ICMP Echo с заданными TTL и собрать,
кто ответил (маршрутизатор — «TTL истёк», узел назначения — Echo Reply).

* WindowsIcmpEngine — Windows ICMP API (iphlpapi.dll), тот же механизм, что у
  tracert.exe. Работает без прав администратора. Только IPv4.
* RawSocketEngine — «сырые» ICMP-сокеты (Linux/macOS). Нужны права root
  или CAP_NET_RAW. IPv4 и IPv6.
* LinuxDgramIcmpEngine — непривилегированные ICMP-сокеты Linux
  (net.ipv4.ping_group_range) с IP_RECVERR. Только IPv4.

Если ни один движок недоступен, трассировщик запускает системную утилиту
(tracert / traceroute / tracepath) — см. tracer.py.
"""

from __future__ import annotations

import random
import select
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, List, Optional

from .netutil import checksum

PAYLOAD = b"abcdefghijklmnopqrstuvwabcdefghi"  # 32 байта, как у tracert


class EngineUnavailable(Exception):
    """Движок не может работать в текущей системе / с текущими правами."""


@dataclass
class ProbeResult:
    addr: Optional[str]
    rtt: Optional[float]   # мс
    kind: str              # "ttl" | "reply" | "unreach"
    note: str = ""


ProbeMap = Dict[int, List[Optional[ProbeResult]]]

# Тексты для ICMP Destination Unreachable (в стиле tracert / traceroute)
ICMP4_UNREACH = {
    0: "!N Заданная сеть недоступна.",
    1: "!H Заданный узел недоступен.",
    2: "!P Заданный протокол недоступен.",
    3: "",  # порт недоступен — для ICMP-зондов означает «дошли»
    4: "!F Требуется фрагментация.",
    9: "!X Сеть административно запрещена.",
    10: "!X Узел административно запрещён.",
    13: "!X Связь административно запрещена.",
}
ICMP6_UNREACH = {
    0: "!N Нет маршрута к узлу.",
    1: "!X Связь административно запрещена.",
    3: "!H Адрес недоступен.",
    4: "",
}


class ProbeEngine:
    name = "?"
    families = (socket.AF_INET,)

    def probe(self, dest: str, ttls: List[int], count: int, timeout: float,
              cancel: Optional[threading.Event] = None) -> ProbeMap:
        raise NotImplementedError

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Windows: ICMP API (iphlpapi.dll) — без прав администратора
# ---------------------------------------------------------------------------

class WindowsIcmpEngine(ProbeEngine):
    name = "ICMP (Windows API, как tracert)"
    families = (socket.AF_INET,)

    IP_SUCCESS = 0
    IP_REQ_TIMED_OUT = 11010
    STATUS = {
        11002: ("unreach", "Заданная сеть недоступна."),
        11003: ("unreach", "Заданный узел недоступен."),
        11004: ("unreach", "Заданный протокол недоступен."),
        11005: ("reply", ""),            # порт недоступен = узел ответил
        11013: ("ttl", ""),              # IP_TTL_EXPIRED_TRANSIT
        11014: ("ttl", ""),              # IP_TTL_EXPIRED_REASSEM
        11018: ("unreach", "Недопустимый адрес назначения."),
        11012: ("unreach", "Недопустимый маршрут."),
    }
    REPLY_BUF = 1024

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise EngineUnavailable("Windows ICMP API доступен только в Windows")
        import ctypes
        from ctypes import wintypes

        self._ct = ctypes

        class IP_OPTION_INFORMATION(ctypes.Structure):
            _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte),
                        ("Flags", ctypes.c_ubyte), ("OptionsSize", ctypes.c_ubyte),
                        ("OptionsData", ctypes.c_void_p)]

        self._Opt = IP_OPTION_INFORMATION
        try:
            dll = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
        except OSError as e:
            raise EngineUnavailable(f"iphlpapi.dll: {e}") from e
        self._create = dll.IcmpCreateFile
        self._create.restype = wintypes.HANDLE
        self._create.argtypes = []
        self._close = dll.IcmpCloseHandle
        self._close.restype = wintypes.BOOL
        self._close.argtypes = [wintypes.HANDLE]
        self._send = dll.IcmpSendEcho
        self._send.restype = wintypes.DWORD
        self._send.argtypes = [wintypes.HANDLE, ctypes.c_uint32, ctypes.c_void_p, wintypes.WORD,
                               ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p,
                               wintypes.DWORD, wintypes.DWORD]
        self._invalid = ctypes.c_void_p(-1).value
        h = self._create()
        if not h or h == self._invalid:
            raise EngineUnavailable("IcmpCreateFile завершился ошибкой")
        self._close(h)
        self._pool = ThreadPoolExecutor(max_workers=64, thread_name_prefix="icmp")

    def _one(self, dest_u32: int, ttl: int, timeout_ms: int) -> Optional[ProbeResult]:
        ct = self._ct
        h = self._create()
        if not h or h == self._invalid:
            return None
        try:
            opts = self._Opt(Ttl=ttl)
            buf = ct.create_string_buffer(self.REPLY_BUF)
            t0 = time.perf_counter()
            n = self._send(h, dest_u32, PAYLOAD, len(PAYLOAD), ct.byref(opts),
                           buf, self.REPLY_BUF, timeout_ms)
            elapsed = (time.perf_counter() - t0) * 1000.0
            err = ct.get_last_error() if n == 0 else 0
            # Первые три поля ICMP_ECHO_REPLY одинаковы в 32- и 64-битной версии:
            # Address (IPAddr), Status (ULONG), RoundTripTime (ULONG)
            addr_u32, status, rtt = struct.unpack_from("<III", buf.raw, 0)
        finally:
            self._close(h)
        if n == 0:
            if addr_u32 == 0:
                return None  # таймаут или ошибка без ответа
            status = status or err
        if status == self.IP_REQ_TIMED_OUT:
            return None
        addr = socket.inet_ntoa(struct.pack("<I", addr_u32))
        if status == self.IP_SUCCESS:
            kind, note = "reply", ""
        else:
            kind, note = self.STATUS.get(status, ("unreach", f"Ошибка ICMP {status}."))
        rtt_ms = float(rtt) if rtt > 0 else min(elapsed, 0.99)
        return ProbeResult(addr, rtt_ms, kind, note)

    def probe(self, dest, ttls, count, timeout, cancel=None):
        dest_u32 = int.from_bytes(socket.inet_aton(dest), "little")
        timeout_ms = max(1, int(timeout * 1000))
        futures = {(t, i): self._pool.submit(self._one, dest_u32, t, timeout_ms)
                   for t in ttls for i in range(count)}
        results: ProbeMap = {t: [None] * count for t in ttls}
        for (t, i), fut in futures.items():
            try:
                results[t][i] = fut.result()
            except Exception:
                results[t][i] = None
        return results

    def close(self):
        self._pool.shutdown(wait=False)


# ---------------------------------------------------------------------------
# Общая логика для сокетных движков: отправить пачку, собрать ответы
# ---------------------------------------------------------------------------

class _SocketEngine(ProbeEngine):
    def __init__(self) -> None:
        self.ident = random.randint(1, 0xFFFF)
        self._seq = random.randint(0, 0xFFFF)
        self.sock: Optional[socket.socket] = None

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFFFF
        return self._seq

    def _echo_packet(self, icmp_type: int, seq: int, ident: Optional[int] = None) -> bytes:
        ident = self.ident if ident is None else ident
        header = struct.pack("!BBHHH", icmp_type, 0, 0, ident, seq)
        csum = checksum(header + PAYLOAD)
        return struct.pack("!BBHHH", icmp_type, 0, csum, ident, seq) + PAYLOAD

    # Реализуются в наследниках
    def _send(self, dest: str, ttl: int, seq: int) -> None:
        raise NotImplementedError

    def _read(self):
        """Прочитать всё доступное; генератор (seq, addr, kind, note, t_recv)."""
        raise NotImplementedError

    def _drain(self) -> None:
        """Выбросить запоздавшие ответы от прошлых пачек."""
        try:
            for _ in self._read():
                pass
        except OSError:
            pass

    def probe(self, dest, ttls, count, timeout, cancel=None):
        results: ProbeMap = {t: [None] * count for t in ttls}
        pending = {}
        self._drain()
        for t in ttls:
            for i in range(count):
                seq = self._next_seq()
                t0 = time.perf_counter()
                try:
                    self._send(dest, t, seq)
                except OSError:
                    continue
                pending[seq] = (t, i, t0)
        deadline = time.perf_counter() + timeout
        poller = select.poll() if hasattr(select, "poll") else None
        if poller:
            poller.register(self.sock, select.POLLIN | select.POLLERR)
        while pending:
            now = time.perf_counter()
            if now >= deadline or (cancel is not None and cancel.is_set()):
                break
            wait = min(deadline - now, 0.2)
            if poller:
                ready = poller.poll(wait * 1000)
            else:
                r, _, x = select.select([self.sock], [], [self.sock], wait)
                ready = r or x
            if not ready:
                continue
            for seq, addr, kind, note, t_recv in self._read():
                item = pending.pop(seq, None)
                if item is None:
                    continue
                t, i, t0 = item
                results[t][i] = ProbeResult(addr, (t_recv - t0) * 1000.0, kind, note)
        return results

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


# ---------------------------------------------------------------------------
# Raw ICMP (Linux/macOS, root)
# ---------------------------------------------------------------------------

class RawSocketEngine(_SocketEngine):
    def __init__(self, family: int = socket.AF_INET) -> None:
        super().__init__()
        self.family = family
        self.families = (family,)
        self.name = "ICMP (raw-сокет)" + (" IPv6" if family == socket.AF_INET6 else "")
        proto = socket.IPPROTO_ICMPV6 if family == socket.AF_INET6 else socket.IPPROTO_ICMP
        try:
            self.sock = socket.socket(family, socket.SOCK_RAW, proto)
        except PermissionError as e:
            raise EngineUnavailable("raw-сокеты требуют прав root (sudo) или CAP_NET_RAW") from e
        except OSError as e:
            raise EngineUnavailable(f"raw-сокет недоступен: {e}") from e
        self.sock.setblocking(False)

    def _send(self, dest, ttl, seq):
        if self.family == socket.AF_INET6:
            self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
            self.sock.sendto(self._echo_packet(128, seq), (dest, 0, 0, 0))
        else:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            self.sock.sendto(self._echo_packet(8, seq), (dest, 0))

    def _read(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except (BlockingIOError, InterruptedError):
                return
            t_recv = time.perf_counter()
            parsed = (parse_icmp6(data, self.ident) if self.family == socket.AF_INET6
                      else parse_icmp4(data, self.ident))
            if parsed:
                seq, kind, note = parsed
                yield seq, addr[0].split("%")[0], kind, note, t_recv


def parse_icmp4(data: bytes, ident: int):
    """Разобрать IPv4-пакет с ICMP. Возвращает (seq, kind, note) или None."""
    if len(data) < 28:
        return None
    ihl = (data[0] & 0x0F) * 4
    icmp = data[ihl:]
    if len(icmp) < 8:
        return None
    itype, code = icmp[0], icmp[1]
    if itype == 0:  # Echo Reply
        rid, seq = struct.unpack("!HH", icmp[4:8])
        return (seq, "reply", "") if rid == ident else None
    if itype in (11, 3):  # Time Exceeded / Destination Unreachable
        inner = icmp[8:]
        if len(inner) < 20:
            return None
        ihl2 = (inner[0] & 0x0F) * 4
        orig = inner[ihl2:ihl2 + 8]
        if len(orig) < 8 or orig[0] != 8:
            return None
        rid, seq = struct.unpack("!HH", orig[4:8])
        if rid != ident:
            return None
        if itype == 11:
            return seq, "ttl", ""
        note = ICMP4_UNREACH.get(code, f"!{code} Узел недоступен.")
        return seq, ("reply" if code == 3 else "unreach"), note
    return None


def parse_icmp6(data: bytes, ident: int):
    """Разобрать ICMPv6-сообщение (без IPv6-заголовка, как отдаёт raw-сокет)."""
    if len(data) < 8:
        return None
    itype, code = data[0], data[1]
    if itype == 129:  # Echo Reply
        rid, seq = struct.unpack("!HH", data[4:8])
        return (seq, "reply", "") if rid == ident else None
    if itype in (3, 1):  # Time Exceeded / Destination Unreachable
        orig = data[8 + 40:8 + 48]
        if len(orig) < 8 or orig[0] != 128:
            return None
        rid, seq = struct.unpack("!HH", orig[4:8])
        if rid != ident:
            return None
        if itype == 3:
            return seq, "ttl", ""
        note = ICMP6_UNREACH.get(code, f"!{code} Узел недоступен.")
        return seq, ("reply" if code == 4 else "unreach"), note
    return None


# ---------------------------------------------------------------------------
# Непривилегированный ICMP в Linux (ping-сокеты + IP_RECVERR)
# ---------------------------------------------------------------------------

IP_RECVERR = 11
SO_EE_ORIGIN_ICMP = 2


class LinuxDgramIcmpEngine(_SocketEngine):
    name = "ICMP (ping-сокет Linux, без root)"
    families = (socket.AF_INET,)

    def __init__(self) -> None:
        super().__init__()
        if not sys.platform.startswith("linux"):
            raise EngineUnavailable("ping-сокеты используются только в Linux")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        except OSError as e:
            raise EngineUnavailable(
                "ping-сокеты запрещены (см. sysctl net.ipv4.ping_group_range)") from e
        self.sock.setsockopt(socket.SOL_IP, IP_RECVERR, 1)
        self.sock.setblocking(False)
        self._msg_errqueue = getattr(socket, "MSG_ERRQUEUE", 0x2000)

    def _send(self, dest, ttl, seq):
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        # идентификатор подставит ядро (номер «порта» сокета)
        self.sock.sendto(self._echo_packet(8, seq, ident=0), (dest, 0))

    def _read(self):
        # 1) ошибки ICMP (TTL истёк, узел недоступен) — из очереди ошибок
        while True:
            try:
                data, anc, _flags, _addr = self.sock.recvmsg(2048, 1024, self._msg_errqueue)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break
            t_recv = time.perf_counter()
            if len(data) < 8:
                continue
            seq = struct.unpack("!H", data[6:8])[0]
            for level, ctype, cdata in anc:
                if level != socket.SOL_IP or ctype != IP_RECVERR or len(cdata) < 24:
                    continue
                _errno, origin, etype, ecode, _pad, _info, _d = struct.unpack_from("=IBBBBII", cdata, 0)
                if origin != SO_EE_ORIGIN_ICMP:
                    continue
                offender = socket.inet_ntoa(cdata[20:24])
                if etype == 11:
                    yield seq, offender, "ttl", "", t_recv
                elif etype == 3:
                    note = ICMP4_UNREACH.get(ecode, f"!{ecode} Узел недоступен.")
                    yield seq, offender, ("reply" if ecode == 3 else "unreach"), note, t_recv
        # 2) обычные Echo Reply
        while True:
            try:
                data, addr = self.sock.recvfrom(2048)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                continue  # ошибка уже лежит в очереди ошибок — заберём на следующем круге
            t_recv = time.perf_counter()
            if len(data) >= 8 and data[0] == 0:
                seq = struct.unpack("!H", data[6:8])[0]
                yield seq, addr[0], "reply", "", t_recv


# ---------------------------------------------------------------------------

def create_probe_engine(family: int = socket.AF_INET) -> ProbeEngine:
    """Подобрать лучший встроенный движок для текущей ОС.

    Бросает EngineUnavailable со списком причин, если ничего не подошло.
    """
    reasons = []
    candidates = []
    if sys.platform == "win32":
        if family == socket.AF_INET:
            candidates.append(WindowsIcmpEngine)
        else:
            reasons.append("встроенный движок Windows поддерживает только IPv4")
    else:
        candidates.append(lambda: RawSocketEngine(family))
        if sys.platform.startswith("linux") and family == socket.AF_INET:
            candidates.append(LinuxDgramIcmpEngine)
    for make in candidates:
        try:
            return make()
        except EngineUnavailable as e:
            reasons.append(str(e))
    raise EngineUnavailable("; ".join(reasons) or "нет подходящего движка")


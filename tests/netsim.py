"""Эмулятор цепочки маршрутизаторов на TUN-интерфейсе (только Linux, нужен root).

Создаёт интерфейс tmsim0 с адресом 203.0.113.1/24. Пакеты к 203.0.113.0/24
уходят в эмулятор, который отвечает так, как ответили бы маршрутизаторы:
ICMP Time Exceeded от узла №TTL, Echo Reply от узла назначения, молчание от
«закрытых» узлов и Destination Unreachable для отдельного адреса.

Используется в тестах движков и для демонстрации GUI без доступа в интернет.
"""

from __future__ import annotations

import fcntl
import os
import select
import socket
import struct
import threading
import time

TUNSETIFF = 0x400454CA
IFF_TUN, IFF_NO_PI = 0x0001, 0x1000
SIOCSIFADDR, SIOCSIFNETMASK, SIOCGIFFLAGS, SIOCSIFFLAGS = 0x8916, 0x891C, 0x8913, 0x8914

LOCAL = "203.0.113.1"
DEST = "203.0.113.50"          # достижим за len(ROUTERS)+1 прыжков
DEST_UNREACH = "203.0.113.99"  # на 3-м прыжке «Заданный узел недоступен»
DEST_SILENT = "203.0.113.77"   # после 3-го прыжка — тишина

# (адрес маршрутизатора или None = не отвечает, задержка мс)
ROUTERS = [
    ("192.168.1.1", 0.4),
    ("100.64.0.1", 3.0),
    ("87.226.181.89", 5.0),
    (None, 0),
    ("195.208.208.250", 12.0),
    ("80.81.192.123", 46.0),
]
DEST_RTT = 47.0


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _ip(src: str, dst: str, payload: bytes, ttl: int = 64) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, ttl, 1, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:]
    return hdr + payload


def _icmp(itype: int, code: int, body: bytes, rest: bytes = b"\0\0\0\0") -> bytes:
    msg = struct.pack("!BBH", itype, code, 0) + rest + body
    return msg[:2] + struct.pack("!H", _csum(msg)) + msg[4:]


class NetSim:
    def __init__(self, name: str = "tmsim0", routers=None, dest_rtt: float = DEST_RTT):
        self.name = name
        self.routers = routers or ROUTERS
        self.dest_rtt = dest_rtt
        self.fd = None
        self._stop = threading.Event()
        self._thread = None
        self.seen = 0

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def start(self):
        self.fd = os.open("/dev/net/tun", os.O_RDWR)
        fcntl.ioctl(self.fd, TUNSETIFF, struct.pack("16sH", self.name.encode(), IFF_TUN | IFF_NO_PI))
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        nm = self.name.encode()
        fcntl.ioctl(s, SIOCSIFADDR, struct.pack("16sH2s4s8s", nm, socket.AF_INET, b"\0\0",
                                                socket.inet_aton(LOCAL), b"\0" * 8))
        fcntl.ioctl(s, SIOCSIFNETMASK, struct.pack("16sH2s4s8s", nm, socket.AF_INET, b"\0\0",
                                                   socket.inet_aton("255.255.255.0"), b"\0" * 8))
        flags = struct.unpack("16sH", fcntl.ioctl(s, SIOCGIFFLAGS, struct.pack("16sH14s", nm, 0, b""))[:18])[1]
        fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14s", nm, flags | 0x1 | 0x40, b""))
        s.close()
        for path in ("/proc/sys/net/ipv4/conf/all/rp_filter", f"/proc/sys/net/ipv4/conf/{self.name}/rp_filter"):
            try:
                with open(path, "w") as f:
                    f.write("0")
            except OSError:
                pass
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        time.sleep(0.2)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(1)
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def _send_later(self, delay_ms: float, pkt: bytes):
        def go():
            try:
                os.write(self.fd, pkt)
            except OSError:
                pass
        threading.Timer(delay_ms / 1000.0, go).start()

    def _loop(self):
        while not self._stop.is_set():
            r, _, _ = select.select([self.fd], [], [], 0.2)
            if not r:
                continue
            try:
                pkt = os.read(self.fd, 65535)
            except OSError:
                return
            if len(pkt) < 28 or pkt[0] >> 4 != 4 or pkt[9] != 1:
                continue
            ihl = (pkt[0] & 0xF) * 4
            ttl = pkt[8]
            src = socket.inet_ntoa(pkt[12:16])
            dst = socket.inet_ntoa(pkt[16:20])
            icmp = pkt[ihl:]
            if icmp[0] != 8:
                continue
            self.seen += 1
            quote = pkt[:ihl + 8]
            n = len(self.routers)
            if dst == DEST_UNREACH and ttl >= 3:
                addr, rtt = self.routers[2]
                self._send_later(rtt, _ip(addr, src, _icmp(3, 1, quote)))
                continue
            if dst == DEST_SILENT and ttl > 3:
                continue
            if ttl <= n:
                addr, rtt = self.routers[ttl - 1]
                if addr is None:
                    continue
                self._send_later(rtt, _ip(addr, src, _icmp(11, 0, quote)))
            else:
                reply = b"\0" + icmp[1:2] + b"\0\0" + icmp[4:]
                reply = reply[:2] + struct.pack("!H", _csum(reply)) + reply[4:]
                self._send_later(self.dest_rtt, _ip(dst, src, reply))


if __name__ == "__main__":
    import sys
    with NetSim() as sim:
        print(f"Эмулятор запущен: {DEST} (достижим), {DEST_UNREACH} (недоступен), {DEST_SILENT} (молчит).")
        print("Ctrl+C для выхода")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            sys.exit(0)

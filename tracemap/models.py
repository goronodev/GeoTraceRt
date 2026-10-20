"""Модели данных: узел маршрута (hop), геоданные и результат трассировки."""

from __future__ import annotations

import datetime as _dt
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class GeoInfo:
    """Географическое положение IP-адреса."""

    lat: Optional[float] = None
    lon: Optional[float] = None
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    source: str = ""
    private: bool = False     # частный / служебный адрес — геолокация невозможна
    approximate: bool = False  # координаты подставлены (например, для частной сети)

    @property
    def has_coords(self) -> bool:
        return self.lat is not None and self.lon is not None

    @property
    def place(self) -> str:
        """Короткое описание места: «Город, Страна»."""
        if self.private:
            return "Частная сеть"
        parts = [p for p in (self.city, self.country) if p]
        return ", ".join(parts)

    @property
    def provider(self) -> str:
        """Провайдер / автономная система для отображения."""
        parts = []
        if self.asn:
            parts.append(self.asn.split(" ")[0])
        name = self.isp or self.org
        if name:
            parts.append(name)
        return " ".join(parts)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> Optional["GeoInfo"]:
        if not data:
            return None
        known = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**known)


@dataclass
class Hop:
    """Один узел маршрута (один TTL)."""

    ttl: int
    addr: Optional[str] = None                 # основной ответивший адрес
    host: Optional[str] = None                 # DNS-имя узла
    rtts: list = field(default_factory=list)   # задержки в мс, None = нет ответа
    extra_addrs: list = field(default_factory=list)  # другие адреса на том же TTL
    note: str = ""                             # «!H», «Заданный узел недоступен» и т.п.
    geo: Optional[GeoInfo] = None
    reached: bool = False                      # это узел назначения

    @property
    def responded(self) -> bool:
        return self.addr is not None

    @property
    def valid_rtts(self) -> list:
        return [r for r in self.rtts if r is not None]

    @property
    def avg_rtt(self) -> Optional[float]:
        v = self.valid_rtts
        return sum(v) / len(v) if v else None

    @property
    def min_rtt(self) -> Optional[float]:
        v = self.valid_rtts
        return min(v) if v else None

    @property
    def loss(self) -> float:
        """Доля потерянных запросов (0..1)."""
        if not self.rtts:
            return 0.0 if self.responded else 1.0
        return sum(1 for r in self.rtts if r is None) / len(self.rtts)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["geo"] = self.geo.to_dict() if self.geo else None
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Hop":
        return cls(
            ttl=int(data["ttl"]),
            addr=data.get("addr"),
            host=data.get("host"),
            rtts=list(data.get("rtts") or []),
            extra_addrs=list(data.get("extra_addrs") or []),
            note=data.get("note") or "",
            geo=GeoInfo.from_dict(data.get("geo")),
            reached=bool(data.get("reached")),
        )

    @staticmethod
    def from_probes(ttl: int, probes: list, dest_ip: Optional[str] = None) -> "Hop":
        """Собрать узел из результатов отдельных запросов.

        probes — список ProbeResult (см. engines.py) длиной = числу запросов.
        """
        rtts, addrs, notes = [], [], []
        reached = False
        for p in probes:
            if p is None or p.addr is None:
                rtts.append(None)
                continue
            rtts.append(p.rtt)
            addrs.append(p.addr)
            if p.kind == "reply" or (dest_ip and p.addr == dest_ip):
                reached = True
            if p.kind == "unreach" and p.note:
                notes.append(p.note)
        hop = Hop(ttl=ttl, rtts=rtts, reached=reached)
        if addrs:
            ordered = [a for a, _ in Counter(addrs).most_common()]
            hop.addr = ordered[0]
            hop.extra_addrs = ordered[1:]
        if notes:
            hop.note = notes[0]
        return hop


@dataclass
class TraceResult:
    """Полный результат трассировки (живой или загруженной из файла)."""

    target: str = ""
    target_ip: Optional[str] = None
    hops: list = field(default_factory=list)
    started: str = field(default_factory=lambda: _dt.datetime.now().isoformat(timespec="seconds"))
    source: str = ""          # метод получения: «ICMP (Windows API)», «файл: trace.txt» …
    max_hops: int = 30
    completed: bool = False
    origin: Optional[GeoInfo] = None   # местоположение компьютера, с которого шла трассировка

    def hop_by_ttl(self, ttl: int) -> Optional[Hop]:
        for h in self.hops:
            if h.ttl == ttl:
                return h
        return None

    def upsert(self, hop: Hop) -> None:
        """Добавить узел или заменить узел с тем же TTL (сохраняя геоданные/имя)."""
        for i, h in enumerate(self.hops):
            if h.ttl == hop.ttl:
                if hop.geo is None and h.geo is not None and h.addr == hop.addr:
                    hop.geo = h.geo
                if not hop.host and h.host and h.addr == hop.addr:
                    hop.host = h.host
                self.hops[i] = hop
                return
        self.hops.append(hop)
        self.hops.sort(key=lambda x: x.ttl)

    @property
    def reached(self) -> bool:
        return any(h.reached for h in self.hops)

    def to_dict(self) -> dict:
        return {
            "format": "tracertmap/1",
            "target": self.target,
            "target_ip": self.target_ip,
            "started": self.started,
            "source": self.source,
            "max_hops": self.max_hops,
            "completed": self.completed,
            "origin": self.origin.to_dict() if self.origin else None,
            "hops": [h.to_dict() for h in self.hops],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TraceResult":
        tr = cls(
            target=data.get("target") or "",
            target_ip=data.get("target_ip"),
            started=data.get("started") or "",
            source=data.get("source") or "",
            max_hops=int(data.get("max_hops") or 30),
            completed=bool(data.get("completed", True)),
            origin=GeoInfo.from_dict(data.get("origin")),
        )
        tr.hops = sorted((Hop.from_dict(h) for h in data.get("hops") or []), key=lambda h: h.ttl)
        return tr

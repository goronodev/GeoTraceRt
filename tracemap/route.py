"""Подготовка маршрута к отрисовке: точки на карте, группы узлов, отрезки пути."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .geomath import LatLon, great_circle, is_geo_plausible
from .models import GeoInfo, Hop, TraceResult

COLOR_FAST = "#2E9D57"      # < 50 мс
COLOR_MEDIUM = "#E3A21A"    # 50–150 мс
COLOR_SLOW = "#D64545"      # > 150 мс
COLOR_UNKNOWN = "#8A8F98"   # нет данных о задержке
COLOR_ORIGIN = "#2B2D42"    # старт (этот компьютер)
COLOR_PATH = "#3E69CB"


def rtt_color(rtt: Optional[float]) -> str:
    if rtt is None:
        return COLOR_UNKNOWN
    if rtt < 50:
        return COLOR_FAST
    if rtt < 150:
        return COLOR_MEDIUM
    return COLOR_SLOW


def fmt_rtt(r: Optional[float]) -> str:
    if r is None:
        return "*"
    if r < 1:
        return "<1"
    return str(int(round(r)))


def compress_ttls(ttls: List[int]) -> str:
    """[1,2,3,5,7,8] → «1-3,5,7,8»."""
    if not ttls:
        return ""
    ttls = sorted(set(ttls))
    parts, start, prev = [], ttls[0], ttls[0]
    for t in ttls[1:] + [None]:
        if t is not None and t == prev + 1:
            prev = t
            continue
        parts.append(str(start) if start == prev else (f"{start},{prev}" if prev == start + 1 else f"{start}-{prev}"))
        if t is not None:
            start = prev = t
    return ",".join(parts)


@dataclass
class MapPoint:
    lat: float
    lon: float
    hops: List[Hop] = field(default_factory=list)
    is_origin: bool = False
    is_dest: bool = False

    @property
    def ttls(self) -> List[int]:
        return [h.ttl for h in self.hops]

    @property
    def label(self) -> str:
        if not self.hops:
            return "Вы" if self.is_origin else "?"
        return compress_ttls(self.ttls)

    @property
    def color(self) -> str:
        if self.is_origin:
            return COLOR_ORIGIN
        last = max(self.hops, key=lambda h: h.ttl)
        return rtt_color(last.avg_rtt)

    @property
    def coords(self) -> LatLon:
        return (self.lat, self.lon)

    @property
    def place(self) -> str:
        """Подпись точки: город первого узла с геоданными, иначе «Старт» / «Частная сеть»."""
        for h in self.hops:
            if h.geo is not None and not h.geo.private and h.geo.place:
                return h.geo.place
        return "Старт (этот компьютер)" if self.is_origin else "Частная сеть"


@dataclass
class Segment:
    points: List[LatLon]
    color: str
    to_ttl: int


@dataclass
class RouteView:
    points: List[MapPoint]
    segments: List[Segment]
    suspicious: Dict[int, str]           # ttl → пояснение, почему геолокация сомнительна
    located: int                         # сколько узлов удалось разместить на карте

    def point_for_ttl(self, ttl: int) -> Optional[MapPoint]:
        for p in self.points:
            if ttl in p.ttls:
                return p
        return None

    def bounds(self) -> Optional[Tuple[float, float, float, float]]:
        """(lat_max, lon_min, lat_min, lon_max) по всем точкам."""
        if not self.points:
            return None
        lats = [p.lat for p in self.points]
        lons = [p.lon for p in self.points]
        return max(lats), min(lons), min(lats), max(lons)


def build_route(trace: TraceResult, origin: Optional[GeoInfo] = None) -> RouteView:
    points: List[MapPoint] = []
    by_key: Dict[Tuple[float, float], MapPoint] = {}
    origin_pt: Optional[MapPoint] = None
    if origin is not None and origin.has_coords:
        origin_pt = MapPoint(origin.lat, origin.lon, is_origin=True)
        points.append(origin_pt)
        by_key[(round(origin.lat, 2), round(origin.lon, 2))] = origin_pt

    sequence: List[Tuple[LatLon, Hop]] = []
    suspicious: Dict[int, str] = {}
    located = 0
    # Частные адреса (LAN, CGNAT, внутренние сети провайдера) не геолоцируются —
    # ставим их туда же, где предыдущий известный узел (в начале маршрута — точка старта).
    last: Optional[LatLon] = (origin.lat, origin.lon) if origin_pt else None
    for hop in trace.hops:
        if not hop.responded or hop.geo is None:
            continue
        if hop.geo.private:
            c = last
        elif hop.geo.has_coords:
            c = (hop.geo.lat, hop.geo.lon)
        else:
            c = None
        if c is None:
            continue
        last = c
        located += 1
        key = (round(c[0], 2), round(c[1], 2))
        pt = by_key.get(key)
        if pt is None:
            pt = MapPoint(c[0], c[1])
            by_key[key] = pt
            points.append(pt)
        pt.hops.append(hop)
        if hop.reached:
            pt.is_dest = True
        sequence.append((c, hop))
        if (origin is not None and origin.has_coords and hop.geo and not hop.geo.private
                and hop.min_rtt is not None
                and not is_geo_plausible((origin.lat, origin.lon), c, hop.min_rtt)):
            suspicious[hop.ttl] = (
                f"Задержка {hop.min_rtt:.0f} мс слишком мала для такого расстояния: "
                f"свет в оптоволокне не успел бы дойти. Реальный узел, вероятно, ближе.")

    segments: List[Segment] = []
    prev: Optional[LatLon] = (origin.lat, origin.lon) if origin_pt else None
    for c, hop in sequence:
        if prev is not None and (round(prev[0], 2), round(prev[1], 2)) != (round(c[0], 2), round(c[1], 2)):
            segments.append(Segment(great_circle(prev, c), rtt_color(hop.avg_rtt), hop.ttl))
        prev = c
    return RouteView(points, segments, suspicious, located)

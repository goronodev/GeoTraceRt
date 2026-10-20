"""Геометрия на сфере: расстояния, дуги большого круга, линия перемены дат."""

from __future__ import annotations

import math
from typing import List, Sequence, Tuple

LatLon = Tuple[float, float]
EARTH_R = 6371.0
FIBER_KM_PER_MS = 200.0   # свет в оптоволокне ≈ 2/3 c ≈ 200 км за 1 мс


def haversine_km(a: LatLon, b: LatLon) -> float:
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * EARTH_R * math.asin(min(1.0, math.sqrt(h)))


def great_circle(a: LatLon, b: LatLon, step_km: float = 150.0, max_points: int = 96) -> List[LatLon]:
    """Точки дуги большого круга от a до b (включая концы)."""
    d = haversine_km(a, b)
    n = int(min(max_points, max(1, d // step_km)))
    if n <= 1 or d < 1:
        return [a, b]
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    v1 = (math.cos(lat1) * math.cos(lon1), math.cos(lat1) * math.sin(lon1), math.sin(lat1))
    v2 = (math.cos(lat2) * math.cos(lon2), math.cos(lat2) * math.sin(lon2), math.sin(lat2))
    omega = d / EARTH_R
    so = math.sin(omega)
    pts = []
    for i in range(n + 1):
        t = i / n
        k1, k2 = math.sin((1 - t) * omega) / so, math.sin(t * omega) / so
        x, y, z = (k1 * v1[j] + k2 * v2[j] for j in range(3))
        pts.append((math.degrees(math.atan2(z, math.hypot(x, y))), math.degrees(math.atan2(y, x))))
    pts[0], pts[-1] = a, b
    return pts


def split_antimeridian(points: Sequence[LatLon]) -> List[List[LatLon]]:
    """Разбить ломаную на части там, где она пересекает 180-й меридиан."""
    if not points:
        return []
    parts: List[List[LatLon]] = [[points[0]]]
    for (la1, lo1), (la2, lo2) in zip(points, points[1:]):
        if abs(lo2 - lo1) > 180:
            # переход через ±180: интерполируем широту в точке пересечения
            edge1 = 180.0 if lo1 > 0 else -180.0
            lo2u = lo2 + 360 if lo1 > 0 else lo2 - 360
            t = (edge1 - lo1) / (lo2u - lo1) if lo2u != lo1 else 0.5
            lat_c = la1 + t * (la2 - la1)
            parts[-1].append((lat_c, edge1))
            parts.append([(lat_c, -edge1), (la2, lo2)])
        else:
            parts[-1].append((la2, lo2))
    return [p for p in parts if len(p) >= 2]


def unwrap_longitudes(points: Sequence[LatLon]) -> List[LatLon]:
    """Сделать долготы непрерывными (для Leaflet), допуская выход за ±180."""
    if not points:
        return []
    out = [points[0]]
    for lat, lon in points[1:]:
        prev = out[-1][1]
        while lon - prev > 180:
            lon -= 360
        while lon - prev < -180:
            lon += 360
        out.append((lat, lon))
    return out


def min_rtt_for_distance(km: float) -> float:
    """Минимально возможное время туда-обратно по оптоволокну, мс."""
    return 2.0 * km / FIBER_KM_PER_MS


def is_geo_plausible(origin: LatLon, point: LatLon, rtt_ms: float, slack_km: float = 300.0) -> bool:
    """Физически ли возможна такая задержка до точки (скорость света в волокне).

    Если узел «отвечает» быстрее, чем свет успел бы дойти до его предполагаемого
    местоположения и обратно — геолокация этого адреса, скорее всего, неверна.
    """
    reach_km = rtt_ms * FIBER_KM_PER_MS / 2.0 + slack_km
    return haversine_km(origin, point) <= reach_km

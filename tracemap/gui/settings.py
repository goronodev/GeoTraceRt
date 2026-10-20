"""Сохранение настроек между запусками (~/.tracertmap/settings.json)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import List, NamedTuple

from ..geo import app_dir


class TileServer(NamedTuple):
    url: str
    max_zoom: int
    dark: bool          # тёмная подложка (спутник) — подписи на карте делаются светлыми
    attribution: str


# Только подложки, которые работают без API-ключа.
TILE_SERVERS = {
    "OpenStreetMap": TileServer(
        "https://tile.openstreetmap.org/{z}/{x}/{y}.png", 19, False, "© участники OpenStreetMap"),
    "Улицы (Esri)": TileServer(
        "https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}",
        19, False, "© Esri, HERE, Garmin, участники OpenStreetMap"),
    "Топографическая (Esri)": TileServer(
        "https://server.arcgisonline.com/ArcGIS/rest/services/World_Topo_Map/MapServer/tile/{z}/{y}/{x}",
        19, False, "© Esri, HERE, Garmin, участники OpenStreetMap"),
    "Спутник (Esri)": TileServer(
        "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
        18, True, "© Esri, Maxar, Earthstar Geographics"),
}
DEFAULT_TILES = "OpenStreetMap"


@dataclass
class Settings:
    max_hops: int = 30
    timeout_ms: int = 2000
    probes: int = 3
    parallel: int = 5
    stop_after_silent: int = 5
    method: str = "auto"
    resolve_names: bool = False
    geo_provider: str = "ip-api"
    geo_lang: str = "ru"
    mmdb_path: str = ""
    tile_server: str = DEFAULT_TILES
    history: List[str] = field(default_factory=lambda: ["ya.ru", "google.com", "8.8.8.8"])
    geometry: str = ""
    sash: int = 0

    @classmethod
    def load(cls) -> "Settings":
        path = app_dir() / "settings.json"
        try:
            data = json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            return cls()
        s = cls()
        for k, v in data.items():
            if k in cls.__dataclass_fields__ and isinstance(v, type(getattr(s, k))):
                setattr(s, k, v)
        if s.tile_server not in TILE_SERVERS:
            s.tile_server = cls.tile_server
        return s

    def save(self) -> None:
        path = app_dir() / "settings.json"
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), "utf-8")
            os.replace(tmp, path)
        except OSError:
            pass

    def remember_target(self, target: str) -> None:
        target = target.strip()
        if not target:
            return
        self.history = [target] + [h for h in self.history if h != target][:14]

"""Геолокация IP-адресов.

Провайдеры:
* ip-api.com — пакетные запросы до 100 IP, 15 пакетов/мин, без ключа (только HTTP);
* ipwho.is   — HTTPS, без ключа, ~1000 запросов в сутки;
* локальная база MaxMind/DB-IP (.mmdb) — офлайн, нужен пакет maxminddb.

Результаты кэшируются на диске (~/.tracertmap/geo_cache.json).
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .models import GeoInfo
from .netutil import is_public

USER_AGENT = "TracertMap/1.0 (+desktop traceroute visualizer)"
CACHE_TTL = 30 * 24 * 3600


def app_dir() -> Path:
    d = Path(os.environ.get("TRACERTMAP_HOME") or (Path.home() / ".tracertmap"))
    d.mkdir(parents=True, exist_ok=True)
    return d


class GeoError(Exception):
    pass


_DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def system_proxy() -> str:
    """Адрес системного прокси (в Windows — из настроек «Прокси-сервер»), если он включён."""
    try:
        proxies = urllib.request.getproxies()
    except Exception:
        return ""
    return proxies.get("https") or proxies.get("http") or ""


def _http_json(url: str, data: Optional[bytes] = None, timeout: float = 8.0, direct: bool = False):
    """GET/POST и разбор JSON. direct=True — в обход системного прокси."""
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": USER_AGENT, "Accept": "application/json",
        **({"Content-Type": "application/json"} if data else {})})
    opener = _DIRECT_OPENER.open if direct else urllib.request.urlopen
    with opener(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8")), resp.headers


@dataclass
class MyLocation:
    """Где находится этот компьютер с точки зрения интернета."""
    geo: GeoInfo
    ip: str
    direct: bool = True     # запрос шёл мимо системного прокси
    proxy: str = ""         # адрес системного прокси, если он включён


# ---------------------------------------------------------------------------

class Provider:
    name = "?"

    def lookup(self, ips: List[str]) -> Dict[str, GeoInfo]:
        raise NotImplementedError

    def my_location(self, direct: bool = True) -> Optional[Tuple[GeoInfo, str]]:
        """Местоположение и внешний IP этого компьютера."""
        return None


class IpApiProvider(Provider):
    """ip-api.com: пакетный POST /batch, лимит 15 запросов в минуту."""

    name = "ip-api.com"
    FIELDS = "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"
    MIN_INTERVAL = 4.2  # 60 / 15 с запасом

    def __init__(self, lang: str = "ru") -> None:
        self.lang = lang
        self._lock = threading.Lock()
        self._next_time = 0.0

    def _wait_slot(self) -> None:
        with self._lock:
            delay = self._next_time - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self._next_time = time.monotonic() + self.MIN_INTERVAL

    def _convert(self, item: dict) -> Optional[GeoInfo]:
        if item.get("status") != "success" or item.get("lat") is None:
            return None
        return GeoInfo(lat=float(item["lat"]), lon=float(item["lon"]),
                       country=item.get("country", ""), country_code=item.get("countryCode", ""),
                       region=item.get("regionName", ""), city=item.get("city", ""),
                       isp=item.get("isp", ""), org=item.get("org", ""), asn=item.get("as", ""),
                       source=self.name)

    def lookup(self, ips):
        out: Dict[str, GeoInfo] = {}
        for i in range(0, len(ips), 100):
            chunk = ips[i:i + 100]
            for attempt in range(2):
                self._wait_slot()
                url = f"http://ip-api.com/batch?fields={self.FIELDS}&lang={self.lang}"
                try:
                    data, headers = _http_json(url, json.dumps(chunk).encode())
                except urllib.error.HTTPError as e:
                    if e.code == 429 and attempt == 0:
                        ttl = int(e.headers.get("X-Ttl", "60") or 60)
                        with self._lock:
                            self._next_time = time.monotonic() + ttl + 1
                        continue
                    raise GeoError(f"ip-api.com: HTTP {e.code}") from e
                except (urllib.error.URLError, OSError, ValueError) as e:
                    raise GeoError(f"ip-api.com недоступен: {e}") from e
                if headers.get("X-Rl") == "0":
                    ttl = int(headers.get("X-Ttl", "60") or 60)
                    with self._lock:
                        self._next_time = time.monotonic() + ttl + 1
                for item in data:
                    g = self._convert(item)
                    if g:
                        out[item.get("query")] = g
                break
        return out

    def my_location(self, direct=True):
        try:
            data, _ = _http_json(f"http://ip-api.com/json/?fields={self.FIELDS}&lang={self.lang}",
                                 timeout=6.0, direct=direct)
        except Exception:
            return None
        g = self._convert(data)
        return (g, data.get("query", "")) if g else None


class IpWhoIsProvider(Provider):
    """ipwho.is: по одному IP на запрос, HTTPS, до 1000 запросов в сутки."""

    name = "ipwho.is"
    FIELDS = "success,message,ip,country,country_code,region,city,latitude,longitude,connection"

    def __init__(self, lang: str = "ru") -> None:
        self.lang = lang
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ipwho")

    def _one(self, ip: str) -> Optional[GeoInfo]:
        url = f"https://ipwho.is/{ip}?lang={self.lang}&fields={self.FIELDS}"
        try:
            data, _ = _http_json(url)
        except urllib.error.HTTPError as e:
            raise GeoError(f"ipwho.is: HTTP {e.code}") from e
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise GeoError(f"ipwho.is недоступен: {e}") from e
        return self._convert(data)

    def _convert(self, data: dict) -> Optional[GeoInfo]:
        if not data.get("success") or data.get("latitude") is None:
            return None
        conn = data.get("connection") or {}
        asn = f"AS{conn['asn']}" if conn.get("asn") else ""
        return GeoInfo(lat=float(data["latitude"]), lon=float(data["longitude"]),
                       country=data.get("country", ""), country_code=data.get("country_code", ""),
                       region=data.get("region", ""), city=data.get("city", ""),
                       isp=conn.get("isp", ""), org=conn.get("org", ""), asn=asn, source=self.name)

    def lookup(self, ips):
        out: Dict[str, GeoInfo] = {}
        futures = {ip: self._pool.submit(self._one, ip) for ip in ips}
        errors = 0
        for ip, fut in futures.items():
            try:
                g = fut.result()
                if g:
                    out[ip] = g
            except GeoError:
                errors += 1
        if errors and not out:
            raise GeoError("ipwho.is недоступен")
        return out

    def my_location(self, direct=True):
        try:
            data, _ = _http_json(f"https://ipwho.is/?lang={self.lang}&fields={self.FIELDS}",
                                 timeout=6.0, direct=direct)
        except Exception:
            return None
        g = self._convert(data)
        return (g, data.get("ip", "")) if g else None


class MmdbProvider(Provider):
    """Локальная база GeoLite2-City / DB-IP City Lite в формате .mmdb."""

    name = "локальная база .mmdb"

    def __init__(self, path: str, lang: str = "ru") -> None:
        try:
            import maxminddb  # type: ignore
        except ImportError as e:
            raise GeoError("Для локальной базы установите пакет: pip install maxminddb") from e
        if not path or not os.path.exists(path):
            raise GeoError(f"Файл базы не найден: {path}")
        self._reader = maxminddb.open_database(path)
        self.lang = lang
        self.name = f"база {os.path.basename(path)}"

    def _name(self, obj: Optional[dict]) -> str:
        names = (obj or {}).get("names") or {}
        return names.get(self.lang) or names.get("en") or ""

    def lookup(self, ips):
        out = {}
        for ip in ips:
            try:
                rec = self._reader.get(ip)
            except ValueError:
                rec = None
            loc = (rec or {}).get("location") or {}
            if loc.get("latitude") is None:
                continue
            subs = (rec.get("subdivisions") or [{}])[0]
            out[ip] = GeoInfo(lat=float(loc["latitude"]), lon=float(loc["longitude"]),
                              country=self._name(rec.get("country")),
                              country_code=(rec.get("country") or {}).get("iso_code", ""),
                              region=self._name(subs), city=self._name(rec.get("city")),
                              source=self.name)
        return out


PROVIDERS = {"ip-api": "ip-api.com", "ipwhois": "ipwho.is", "mmdb": "Локальная база .mmdb"}


def make_provider(key: str, lang: str = "ru", mmdb_path: str = "") -> Provider:
    if key == "ipwhois":
        return IpWhoIsProvider(lang)
    if key == "mmdb":
        return MmdbProvider(mmdb_path, lang)
    return IpApiProvider(lang)


# ---------------------------------------------------------------------------

class GeoCache:
    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or (app_dir() / "geo_cache.json")
        self._lock = threading.Lock()
        self._data: Dict[str, dict] = {}
        try:
            self._data = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            self._data = {}

    def get(self, ip: str, lang: str) -> Optional[GeoInfo]:
        with self._lock:
            item = self._data.get(f"{lang}:{ip}")
        if not item or time.time() - item.get("ts", 0) > CACHE_TTL:
            return None
        return GeoInfo.from_dict(item.get("geo"))

    def put_many(self, items: Dict[str, GeoInfo], lang: str) -> None:
        if not items:
            return
        now = time.time()
        with self._lock:
            for ip, g in items.items():
                self._data[f"{lang}:{ip}"] = {"ts": now, "geo": g.to_dict()}
            snapshot = json.dumps(self._data, ensure_ascii=False)
        tmp = self.path.with_suffix(".tmp")
        try:
            tmp.write_text(snapshot, "utf-8")
            os.replace(tmp, self.path)
        except OSError:
            pass

    def clear(self) -> None:
        with self._lock:
            self._data = {}
        try:
            self.path.unlink()
        except OSError:
            pass


class GeoResolver:
    """Геолокация списка адресов: кэш → основной провайдер → запасной."""

    def __init__(self, provider: str = "ip-api", lang: str = "ru", mmdb_path: str = "",
                 cache: Optional[GeoCache] = None) -> None:
        self.lang = lang
        self.cache = cache or GeoCache()
        self.primary = make_provider(provider, lang, mmdb_path)
        self.fallback: Provider = IpApiProvider(lang) if provider == "ipwhois" else IpWhoIsProvider(lang)
        self.last_error = ""

    def lookup(self, ips: Iterable[str]) -> Dict[str, GeoInfo]:
        result: Dict[str, GeoInfo] = {}
        todo = []
        for ip in dict.fromkeys(ips):
            if not ip:
                continue
            if not is_public(ip):
                result[ip] = GeoInfo(private=True, source="частный адрес")
                continue
            cached = self.cache.get(ip, self.lang)
            if cached:
                result[ip] = cached
            else:
                todo.append(ip)
        if todo:
            found: Dict[str, GeoInfo] = {}
            self.last_error = ""
            for prov in (self.primary, self.fallback):
                if prov is None:
                    continue
                rest = [ip for ip in todo if ip not in found]
                if not rest:
                    break
                try:
                    found.update(prov.lookup(rest))
                    if found:
                        break
                except GeoError as e:
                    self.last_error = str(e)
            self.cache.put_many(found, self.lang)
            result.update(found)
        return result

    def my_location(self) -> Optional[MyLocation]:
        """Где находится этот компьютер (по внешнему IP), или None.

        Запрос идёт мимо системного прокси: ICMP-пакеты трассировки через HTTP/SOCKS-прокси
        (например, VPN-клиент в режиме «системный прокси») не проходят, поэтому точка
        старта должна соответствовать прямому выходу в интернет. Если напрямую сервисы
        недоступны — пробуем через прокси и помечаем это.
        """
        proxy = system_proxy()
        modes = (True, False) if proxy else (True,)
        for direct in modes:
            tried = set()
            for prov in (self.primary, self.fallback, IpApiProvider(self.lang), IpWhoIsProvider(self.lang)):
                if prov.name in tried:
                    continue
                tried.add(prov.name)
                res = prov.my_location(direct=direct)
                if res and res[0].has_coords:
                    return MyLocation(res[0], res[1], direct=direct, proxy=proxy)
        return None

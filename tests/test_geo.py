import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tracemap import geo  # noqa: E402
from tracemap.geomath import (great_circle, haversine_km, is_geo_plausible,  # noqa: E402
                              split_antimeridian, unwrap_longitudes)
from tracemap.models import GeoInfo, Hop, TraceResult  # noqa: E402
from tracemap.netutil import is_public  # noqa: E402
from tracemap.route import build_route, compress_ttls, rtt_color  # noqa: E402

MOSCOW = (55.7558, 37.6173)
VLADIVOSTOK = (43.1155, 131.8855)
SEATTLE = (47.6062, -122.3321)
FRANKFURT = (50.1109, 8.6821)


class GeoMathTests(unittest.TestCase):
    def test_distance(self):
        self.assertAlmostEqual(haversine_km(MOSCOW, VLADIVOSTOK), 6430, delta=60)

    def test_great_circle_endpoints(self):
        pts = great_circle(MOSCOW, FRANKFURT)
        self.assertEqual(pts[0], MOSCOW)
        self.assertEqual(pts[-1], FRANKFURT)
        self.assertGreater(len(pts), 5)

    def test_antimeridian_split(self):
        pts = great_circle(VLADIVOSTOK, SEATTLE)
        parts = split_antimeridian(pts)
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[0][-1][1], 180.0)
        self.assertEqual(parts[1][0][1], -180.0)
        self.assertAlmostEqual(parts[0][-1][0], parts[1][0][0])

    def test_unwrap(self):
        u = unwrap_longitudes([(0, 170), (0, -170)])
        self.assertEqual(u[1][1], 190)

    def test_plausibility(self):
        # 2 мс до Франкфурта из Москвы — физически невозможно
        self.assertFalse(is_geo_plausible(MOSCOW, FRANKFURT, 2.0))
        self.assertTrue(is_geo_plausible(MOSCOW, FRANKFURT, 40.0))


class RouteTests(unittest.TestCase):
    def test_compress(self):
        self.assertEqual(compress_ttls([1, 2, 3, 5, 7, 8]), "1-3,5,7,8")
        self.assertEqual(rtt_color(10), "#2E9D57")

    def test_build_route_groups_and_private(self):
        origin = GeoInfo(lat=VLADIVOSTOK[0], lon=VLADIVOSTOK[1], city="Владивосток")
        tr = TraceResult(target="x", target_ip="5.5.5.5", hops=[
            Hop(1, "192.168.1.1", rtts=[1], geo=GeoInfo(private=True)),
            Hop(2, "1.1.1.1", rtts=[70], geo=GeoInfo(lat=MOSCOW[0], lon=MOSCOW[1])),
            Hop(3, "1.1.1.2", rtts=[71], geo=GeoInfo(lat=MOSCOW[0], lon=MOSCOW[1])),
            Hop(4, None, rtts=[None]),
            Hop(5, "5.5.5.5", rtts=[5], geo=GeoInfo(lat=FRANKFURT[0], lon=FRANKFURT[1]), reached=True),
        ])
        view = build_route(tr, origin)
        self.assertEqual(len(view.points), 3)             # старт(+1), Москва(2,3), Франкфурт(5)
        self.assertEqual(view.points[0].ttls, [1])
        self.assertEqual(view.points[1].label, "2,3")
        self.assertTrue(view.points[2].is_dest)
        self.assertEqual(len(view.segments), 2)
        self.assertIn(5, view.suspicious)                  # 5 мс до Франкфурта из Владивостока
        self.assertNotIn(2, view.suspicious)

    def test_private_hop_in_the_middle_follows_previous(self):
        tr = TraceResult(hops=[
            Hop(1, "1.1.1.1", rtts=[70], geo=GeoInfo(lat=MOSCOW[0], lon=MOSCOW[1])),
            Hop(2, "10.0.0.1", rtts=[71], geo=GeoInfo(private=True)),
            Hop(3, "5.5.5.5", rtts=[90], geo=GeoInfo(lat=FRANKFURT[0], lon=FRANKFURT[1]), reached=True),
        ])
        view = build_route(tr, GeoInfo(lat=VLADIVOSTOK[0], lon=VLADIVOSTOK[1]))
        self.assertEqual(view.point_for_ttl(2).ttls, [1, 2])   # частный узел — рядом с Москвой, не у старта
        self.assertEqual(len(view.segments), 2)
        self.assertEqual(view.point_for_ttl(2).place, "Частная сеть")  # в тесте у узла нет названия города
        view2 = build_route(tr, None)
        self.assertEqual(len(view2.points), 2)


class FakeProvider(geo.Provider):
    name = "fake"

    def __init__(self):
        self.calls = []

    def lookup(self, ips):
        self.calls.append(list(ips))
        return {ip: GeoInfo(lat=1.0, lon=2.0, city="X", source="fake") for ip in ips}


class ResolverTests(unittest.TestCase):
    def test_private_cache_and_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            cache = geo.GeoCache(Path(d) / "c.json")
            r = geo.GeoResolver(cache=cache)
            fake = FakeProvider()

            class Broken(geo.Provider):
                name = "broken"

                def lookup(self, ips):
                    raise geo.GeoError("offline")

            r.primary, r.fallback = Broken(), fake
            res = r.lookup(["10.0.0.1", "8.8.8.8", "8.8.4.4", "100.64.1.1"])
            self.assertTrue(res["10.0.0.1"].private)
            self.assertTrue(res["100.64.1.1"].private)
            self.assertEqual(res["8.8.8.8"].city, "X")
            self.assertEqual(fake.calls, [["8.8.8.8", "8.8.4.4"]])
            # второй раз — из кэша (в т.ч. новый экземпляр кэша с диска)
            r2 = geo.GeoResolver(cache=geo.GeoCache(Path(d) / "c.json"))
            r2.primary = r2.fallback = Broken()
            self.assertEqual(r2.lookup(["8.8.8.8"])["8.8.8.8"].city, "X")

    def test_is_public(self):
        self.assertFalse(is_public("192.168.1.1"))
        self.assertFalse(is_public("100.64.0.1"))
        self.assertFalse(is_public("fe80::1"))
        self.assertTrue(is_public("8.8.8.8"))
        self.assertTrue(is_public("2a02:6b8::2:242"))


if __name__ == "__main__":
    unittest.main()


class MyLocationTests(unittest.TestCase):
    class P(geo.Provider):
        name = "p"

        def __init__(self, direct_ok):
            self.direct_ok = direct_ok
            self.calls = []

        def my_location(self, direct=True):
            self.calls.append(direct)
            if direct and not self.direct_ok:
                return None
            return GeoInfo(lat=1, lon=2, city="Direct" if direct else "ViaProxy"), "9.9.9.9"

    def _resolver(self, prov):
        with tempfile.TemporaryDirectory() as d:
            r = geo.GeoResolver(cache=geo.GeoCache(Path(d) / "c.json"))
        r.primary = r.fallback = prov
        return r

    def test_direct_first_even_with_proxy(self):
        prov = self.P(direct_ok=True)
        r = self._resolver(prov)
        with unittest.mock.patch.object(geo, "system_proxy", return_value="http://127.0.0.1:10809"), \
                unittest.mock.patch.object(geo, "IpApiProvider", lambda lang: prov), \
                unittest.mock.patch.object(geo, "IpWhoIsProvider", lambda lang: prov):
            loc = r.my_location()
        self.assertTrue(loc.direct)
        self.assertEqual(loc.geo.city, "Direct")
        self.assertEqual(loc.proxy, "http://127.0.0.1:10809")

    def test_falls_back_to_proxy(self):
        prov = self.P(direct_ok=False)
        r = self._resolver(prov)
        with unittest.mock.patch.object(geo, "system_proxy", return_value="http://127.0.0.1:10809"), \
                unittest.mock.patch.object(geo, "IpApiProvider", lambda lang: prov), \
                unittest.mock.patch.object(geo, "IpWhoIsProvider", lambda lang: prov):
            loc = r.my_location()
        self.assertFalse(loc.direct)
        self.assertEqual(loc.geo.city, "ViaProxy")

    def test_no_proxy_no_fallback(self):
        prov = self.P(direct_ok=False)
        r = self._resolver(prov)
        with unittest.mock.patch.object(geo, "system_proxy", return_value=""), \
                unittest.mock.patch.object(geo, "IpApiProvider", lambda lang: prov), \
                unittest.mock.patch.object(geo, "IpWhoIsProvider", lambda lang: prov):
            self.assertIsNone(r.my_location())
        self.assertNotIn(False, prov.calls)


class SettingsMigrationTests(unittest.TestCase):
    def test_carto_replaced_by_osm(self):
        try:
            from tracemap.gui import settings as st
        except ImportError as e:   # без tkinter пакет gui всё равно импортируется — tk не нужен
            self.skipTest(str(e))
        with tempfile.TemporaryDirectory() as d:
            old = os.environ.get("TRACERTMAP_HOME")
            os.environ["TRACERTMAP_HOME"] = d
            try:
                Path(d, "settings.json").write_text('{"tile_server": "Тёмная (CARTO)", "max_hops": 20}', "utf-8")
                s = st.Settings.load()
            finally:
                if old is None:
                    os.environ.pop("TRACERTMAP_HOME")
                else:
                    os.environ["TRACERTMAP_HOME"] = old
        self.assertEqual(s.tile_server, "OpenStreetMap")
        self.assertEqual(s.max_hops, 20)
        self.assertFalse(any("CARTO" in name or "carto" in t.url for name, t in st.TILE_SERVERS.items()))

import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tracemap.exporters import format_hop_line, to_csv, to_html, to_json, to_text  # noqa: E402
from tracemap.models import GeoInfo, TraceResult  # noqa: E402
from tracemap.parser import decode_bytes, parse_text  # noqa: E402

SAMPLES = os.path.join(ROOT, "samples")


def sample(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return f.read()


class ParserTests(unittest.TestCase):
    def test_windows_ru(self):
        tr = parse_text(sample("tracert_windows_ru.txt"))
        self.assertEqual(tr.target, "github.com")
        self.assertEqual(tr.target_ip, "140.82.121.4")
        self.assertEqual(len(tr.hops), 8)
        self.assertTrue(tr.reached)
        self.assertEqual(tr.hops[0].rtts, [0.5, 0.5, 0.5])          # «<1 мс»
        self.assertIsNone(tr.hops[4].addr)                           # * * *
        self.assertEqual(tr.hops[7].host, "lb-140-82-121-4-fra.github.com")

    def test_windows_en_with_names_and_partial_loss(self):
        tr = parse_text(sample("tracert_windows_en.txt"))
        self.assertEqual(tr.hops[0].host, "router.lan")
        self.assertEqual(tr.hops[2].rtts, [10.0, None, 11.0])
        self.assertEqual(tr.hops[2].addr, "80.81.192.10")

    def test_linux_multi_address(self):
        tr = parse_text(sample("traceroute_linux.txt"))
        self.assertEqual(tr.target_ip, "142.250.185.78")
        self.assertEqual(tr.hops[4].extra_addrs, ["108.170.246.161"])
        self.assertEqual(tr.hops[5].extra_addrs, ["142.251.54.27"])     # строка-продолжение
        self.assertEqual(len(tr.hops[5].rtts), 3)
        self.assertEqual(tr.hops[0].host, "_gateway")

    def test_tracepath(self):
        tr = parse_text(sample("tracepath.txt"))
        self.assertEqual([h.ttl for h in tr.hops], [1, 2, 3, 4, 5])
        self.assertEqual(tr.hops[0].rtts, [0.512, 0.43])                # две строки на TTL 1
        self.assertFalse(tr.hops[2].responded)
        self.assertTrue(tr.hops[-1].reached)

    def test_mtr(self):
        tr = parse_text(sample("mtr_report.txt"))
        self.assertEqual([h.ttl for h in tr.hops], [1, 2, 3, 4, 5])
        self.assertFalse(tr.hops[2].responded)
        self.assertIn("10", tr.hops[3].note)

    def test_ip_list(self):
        tr = parse_text(sample("ip_list.txt"))
        self.assertEqual(len(tr.hops), 5)
        self.assertEqual(tr.hops[1].addr, "95.213.4.1")

    def test_ipv6(self):
        tr = parse_text(sample("tracert_ipv6.txt"))
        self.assertEqual(tr.target_ip, "2a02:6b8::2:242")
        self.assertEqual(tr.hops[2].addr, "2001:7f8:20::1:3")
        self.assertTrue(tr.hops[-1].reached)

    def test_unreachable(self):
        tr = parse_text(sample("tracert_unreachable.txt"))
        self.assertEqual(tr.target_ip, "10.9.9.9")
        self.assertIn("недоступен", tr.hops[1].note)
        self.assertFalse(tr.reached)

    def test_encodings(self):
        text = sample("tracert_windows_ru.txt")
        for enc in ("cp866", "cp1251", "utf-16", "utf-8-sig"):
            decoded = decode_bytes(text.encode(enc))
            self.assertIn("Трассировка маршрута", decoded, enc)
            self.assertEqual(len(parse_text(decoded).hops), 8, enc)

    def test_hostname_with_ms_inside_is_not_a_time(self):
        tr = parse_text("  1    5 ms    6 ms    7 ms  r1.msk.ms-net.ru [1.2.3.4]\n")
        self.assertEqual(tr.hops[0].rtts, [5.0, 6.0, 7.0])
        self.assertEqual(tr.hops[0].host, "r1.msk.ms-net.ru")

    def test_garbage_raises(self):
        with self.assertRaises(ValueError):
            parse_text("hello world\nnothing here")


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tr = parse_text(sample("tracert_windows_ru.txt"))
        self.tr.hops[2].geo = GeoInfo(lat=55.75, lon=37.62, city="Москва", country="Россия",
                                      asn="AS12389 Rostelecom", isp="Rostelecom")
        self.tr.hops[7].geo = GeoInfo(lat=50.11, lon=8.68, city="Франкфурт", country="Германия")

    def test_roundtrip_json(self):
        back = parse_text(to_json(self.tr))
        self.assertEqual(back.to_dict(), TraceResult.from_dict(json.loads(to_json(self.tr))).to_dict())
        self.assertEqual(back.hops[2].geo.city, "Москва")

    def test_text_roundtrip(self):
        back = parse_text(to_text(self.tr))
        self.assertEqual([h.addr for h in back.hops], [h.addr for h in self.tr.hops])
        self.assertTrue(back.reached)

    def test_line_format(self):
        self.assertIn("Превышен интервал", format_hop_line(self.tr.hops[4]))
        self.assertTrue(format_hop_line(self.tr.hops[0]).startswith("  1"))

    def test_csv_and_html(self):
        csv_text = to_csv(self.tr)
        self.assertIn("Москва", csv_text)
        page = to_html(self.tr, GeoInfo(lat=43.1, lon=131.9, city="Владивосток"))
        self.assertIn("leaflet", page)
        self.assertIn("Франкфурт", page)


if __name__ == "__main__":
    unittest.main()

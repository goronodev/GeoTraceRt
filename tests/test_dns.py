import os
import socket
import struct
import sys
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tracemap import dnsresolve as d  # noqa: E402
from tracemap.dnsresolve import ResolveError, clean_target, resolve_target, to_ascii_host  # noqa: E402

RECORDS = {   # имя -> (cname или None, [A], [AAAA])
    "ya.ru": (None, ["5.255.255.242"], ["2a02:6b8::2:242"]),
    "www.example.org": ("edge.cdn.example.net", ["93.184.215.14"], []),
    "xn--d1acpjx3f.xn--p1ai": (None, ["5.255.255.70"], []),     # яндекс.рф
    "v6only.example": (None, [], ["2001:db8::50"]),
}


class FakeDnsServer(threading.Thread):
    """Мини-DNS на 127.0.0.1: CNAME + A/AAAA со сжатием имён, NXDOMAIN, режим «молчать»."""

    def __init__(self, silent=False):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.addr = self.sock.getsockname()
        self.silent = silent
        self.queries = []
        self.start()

    @staticmethod
    def _read_name(data, off):
        labels = []
        while data[off]:
            ln = data[off]
            labels.append(data[off + 1:off + 1 + ln].decode())
            off += ln + 1
        return ".".join(labels), off + 1

    @staticmethod
    def _encode(name):
        return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"

    def run(self):
        while True:
            try:
                data, src = self.sock.recvfrom(512)
            except OSError:
                return
            tid = struct.unpack("!H", data[:2])[0]
            name, off = self._read_name(data, 12)
            qtype = struct.unpack("!H", data[off:off + 2])[0]
            self.queries.append((name, qtype))
            if self.silent:
                continue
            question = data[12:off + 4]
            rec = RECORDS.get(name)
            if rec is None:
                self.sock.sendto(struct.pack("!HHHHHH", tid, 0x8183, 1, 0, 0, 0) + question, src)
                continue
            cname, a, aaaa = rec
            answers = []
            target_ptr = b"\xc0\x0c"                     # указатель на имя из вопроса
            if cname:
                rdata = self._encode(cname)
                answers.append(target_ptr + struct.pack("!HHIH", 5, 1, 60, len(rdata)) + rdata)
                target_ptr = struct.pack("!H", 0xC000 | (12 + len(question) + 12))  # на имя в rdata CNAME
            if qtype == 1:
                for ip in a:
                    answers.append(target_ptr + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip))
            elif qtype == 28:
                for ip in aaaa:
                    answers.append(target_ptr + struct.pack("!HHIH", 28, 1, 60, 16)
                                   + socket.inet_pton(socket.AF_INET6, ip))
            hdr = struct.pack("!HHHHHH", tid, 0x8180, 1, len(answers), 0, 0)
            self.sock.sendto(hdr + question + b"".join(answers), src)

    def close(self):
        self.sock.close()


def broken_system_dns(*a, **k):
    raise socket.gaierror(11001, "getaddrinfo failed")


class CleanTargetTests(unittest.TestCase):
    def test_variants(self):
        cases = {
            "https://ya.ru/": "ya.ru",
            "http://ya.ru/search?text=x#a": "ya.ru",
            "ya.ru/": "ya.ru",
            "ya.ru:443": "ya.ru",
            "  YA.RU.  ": "ya.ru",
            "​ya.ru﻿": "ya.ru",
            "user@mail.ya.ru": "mail.ya.ru",
            "8.8.8.8": "8.8.8.8",
            "8.8.8.8:53": "8.8.8.8",
            "[2a02:6b8::2:242]:443": "2a02:6b8::2:242",
            "2a02:6b8::2:242": "2a02:6b8::2:242",
            "https://[2001:db8::1]/x": "2001:db8::1",
            "Яндекс.РФ": "яндекс.рф",
            "": "",
        }
        for raw, expected in cases.items():
            self.assertEqual(clean_target(raw), expected, raw)

    def test_idn(self):
        self.assertEqual(to_ascii_host("яндекс.рф"), "xn--d1acpjx3f.xn--p1ai")
        self.assertEqual(to_ascii_host("ya.ru"), "ya.ru")


class ResolveTests(unittest.TestCase):
    def setUp(self):
        self.srv = FakeDnsServer()
        self.servers = [self.srv.addr]

    def tearDown(self):
        self.srv.close()

    def test_ip_literal_skips_dns(self):
        r = resolve_target("https://1.2.3.4/", udp_servers=self.servers, use_doh=False)
        self.assertEqual((r.ip, r.family), ("1.2.3.4", socket.AF_INET))
        self.assertEqual(self.srv.queries, [])

    def test_system_dns_used_first(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 0))]
        with mock.patch.object(d.socket, "getaddrinfo", return_value=fake):
            r = resolve_target("ya.ru/", udp_servers=self.servers, use_doh=False)
        self.assertEqual(r.ip, "10.1.2.3")
        self.assertEqual(r.via, "")
        self.assertEqual(self.srv.queries, [])

    def test_fallback_when_system_dns_broken(self):
        with mock.patch.object(d.socket, "getaddrinfo", side_effect=broken_system_dns):
            r = resolve_target("ya.ru", udp_servers=self.servers, use_doh=False)
        self.assertEqual(r.ip, "5.255.255.242")
        self.assertIn("публичный DNS", r.via)
        self.assertIn("11001", r.note)

    def test_cname_chain_with_compression(self):
        with mock.patch.object(d.socket, "getaddrinfo", side_effect=broken_system_dns):
            r = resolve_target("https://www.example.org/", udp_servers=self.servers, use_doh=False)
        self.assertEqual(r.ip, "93.184.215.14")

    def test_idn_fallback(self):
        with mock.patch.object(d.socket, "getaddrinfo", side_effect=broken_system_dns):
            r = resolve_target("Яндекс.рф", udp_servers=self.servers, use_doh=False)
        self.assertEqual(r.ip, "5.255.255.70")
        self.assertIn(("xn--d1acpjx3f.xn--p1ai", 1), self.srv.queries)

    def test_ipv6_only(self):
        with mock.patch.object(d.socket, "getaddrinfo", side_effect=broken_system_dns):
            r = resolve_target("v6only.example", udp_servers=self.servers, use_doh=False)
        self.assertEqual((r.ip, r.family), ("2001:db8::50", socket.AF_INET6))

    def test_fake_ip_from_vpn_is_replaced(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.18.0.27", 0))]
        with mock.patch.object(d.socket, "getaddrinfo", return_value=fake):
            r = resolve_target("ya.ru", udp_servers=self.servers, use_doh=False)
        self.assertEqual(r.ip, "5.255.255.242")
        self.assertIn("FakeDNS", r.note)

    def test_nxdomain_message(self):
        with mock.patch.object(d.socket, "getaddrinfo", side_effect=broken_system_dns):
            with self.assertRaises(ResolveError) as cm:
                resolve_target("no-such.example", udp_servers=self.servers, use_doh=False)
        msg = str(cm.exception)
        self.assertIn("не существует", msg)
        self.assertIn("системный DNS", msg)

    def test_everything_down_gives_reasons(self):
        silent = FakeDnsServer(silent=True)
        try:
            with mock.patch.object(d.socket, "getaddrinfo", side_effect=broken_system_dns), \
                    mock.patch.object(d, "UDP_TIMEOUT", 0.4):
                with self.assertRaises(ResolveError) as cm:
                    resolve_target("ya.ru", udp_servers=[silent.addr], use_doh=False)
        finally:
            silent.close()
        msg = str(cm.exception)
        self.assertIn("11001", msg)
        self.assertIn("не ответили", msg)


if __name__ == "__main__":
    unittest.main()

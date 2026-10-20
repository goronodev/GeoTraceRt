import os
import stat
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from tracemap import tracer  # noqa: E402
from tracemap.tracer import SystemTraceroute, TraceOptions, run_trace  # noqa: E402

FAKE_TRACEROUTE = r'''#!/bin/sh
echo "traceroute to 203.0.113.50 (203.0.113.50), 30 hops max, 60 byte packets"
sleep 0.1; echo " 1  192.168.1.1  0.412 ms  0.388 ms  0.371 ms"
sleep 0.1; echo " 2  100.64.0.1  5.120 ms 100.64.0.2  5.098 ms  5.077 ms"
sleep 0.1; echo " 3  * * *"
sleep 0.1; echo " 4  80.81.192.123  45.1 ms"
sleep 0.1; echo "    80.81.192.124  45.3 ms  45.2 ms"
if [ "$SILENT" = "1" ]; then
  for i in 5 6 7 8 9 10 11 12; do sleep 0.1; echo " $i  * * *"; done
fi
sleep 0.1; echo " 13  203.0.113.50  47.0 ms  46.9 ms  47.2 ms"
'''


class SystemToolTests(unittest.TestCase):
    def setUp(self):
        if sys.platform == "win32":
            self.skipTest("POSIX-скрипт")
        self.dir = tempfile.mkdtemp()
        path = os.path.join(self.dir, "traceroute")
        with open(path, "w") as f:
            f.write(FAKE_TRACEROUTE)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        self.old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = self.dir + os.pathsep + self.old_path

    def tearDown(self):
        os.environ["PATH"] = self.old_path
        os.environ.pop("SILENT", None)

    def run_tool(self, opts):
        events = []
        tool = SystemTraceroute()
        self.assertEqual(tool.kind, "traceroute")
        reached, reason = tool.run("203.0.113.50", opts, lambda k, p: events.append((k, p)), threading.Event())
        hops = {}
        for k, p in events:
            if k == "hop":
                hops[p.ttl] = p
        return reached, reason, hops

    def test_streaming_parse(self):
        reached, reason, hops = self.run_tool(TraceOptions(stop_after_silent=0))
        self.assertTrue(reached)
        self.assertEqual(sorted(hops), [1, 2, 3, 4, 13])
        self.assertEqual(hops[2].extra_addrs, ["100.64.0.2"])
        self.assertEqual(hops[4].extra_addrs, ["80.81.192.124"])   # строка-продолжение обновила узел
        self.assertEqual(len(hops[4].rtts), 3)
        self.assertTrue(hops[13].reached)

    def test_stop_after_silent(self):
        os.environ["SILENT"] = "1"
        t0 = time.time()
        reached, reason, hops = self.run_tool(TraceOptions(stop_after_silent=4))
        self.assertFalse(reached)
        self.assertIn("не ответили", reason)
        self.assertNotIn(13, hops)
        self.assertLess(time.time() - t0, 2.5)

    def test_run_trace_falls_back_to_system_tool(self):
        orig = tracer.create_probe_engine

        def unavailable(family):
            raise tracer.EngineUnavailable("нет прав")
        tracer.create_probe_engine = unavailable
        try:
            events = []
            run_trace("203.0.113.50", TraceOptions(), lambda k, p: events.append((k, p)))
        finally:
            tracer.create_probe_engine = orig
        kinds = [k for k, _ in events]
        self.assertIn("start", kinds)
        start = dict(events)["start"]
        self.assertIn("traceroute", start["method"])
        self.assertEqual(events[-1][0], "done")
        self.assertTrue(events[-1][1]["reached"])

    def test_bad_name(self):
        events = []
        run_trace("no-such-host.invalid", TraceOptions(), lambda k, p: events.append((k, p)))
        self.assertEqual(events[-2][0], "error")
        self.assertEqual(events[-1][0], "done")


@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0 and os.path.exists("/dev/net/tun"),
                     "нужен Linux, root и /dev/net/tun")
class EmulatedNetworkTests(unittest.TestCase):
    def test_raw_and_dgram_engines(self):
        from netsim import DEST, NetSim
        from tracemap.engines import LinuxDgramIcmpEngine, RawSocketEngine
        with NetSim():
            for make in (RawSocketEngine, LinuxDgramIcmpEngine):
                try:
                    eng = make()
                except tracer.EngineUnavailable as e:
                    self.skipTest(str(e))
                events = []
                ok, reason = tracer._probe_loop(eng, DEST, TraceOptions(timeout_ms=600), 
                                                lambda k, p: events.append(p), threading.Event())
                eng.close()
                self.assertTrue(ok, reason)
                addrs = [h.addr for h in events]
                self.assertEqual(addrs, ["192.168.1.1", "100.64.0.1", "87.226.181.89", None,
                                         "195.208.208.250", "80.81.192.123", DEST], make.__name__)


if __name__ == "__main__":
    unittest.main()

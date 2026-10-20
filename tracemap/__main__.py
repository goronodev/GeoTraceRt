"""Точка входа: python -m tracemap [адрес] [--file трассировка.txt] [--cli]"""

from __future__ import annotations

import argparse
import sys


def main(argv=None) -> int:
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
            except Exception:
                pass
    ap = argparse.ArgumentParser(prog="tracertmap",
                                 description="Трассировка маршрута с визуализацией на карте мира.")
    ap.add_argument("target", nargs="?", help="IP-адрес или доменное имя (сразу запустить трассировку)")
    ap.add_argument("-f", "--file", help="построить маршрут по готовой трассировке из файла")
    ap.add_argument("--cli", action="store_true", help="консольный режим без окна (как tracert)")
    ap.add_argument("-H", "--max-hops", type=int, default=30, help="макс. число прыжков (по умолч. 30)")
    ap.add_argument("-w", "--timeout", type=int, default=2000, help="таймаут ответа, мс (по умолч. 2000)")
    ap.add_argument("-q", "--probes", type=int, default=3, help="запросов на узел (по умолч. 3)")
    ap.add_argument("-p", "--parallel", type=int, default=5, help="сколько TTL опрашивать одновременно")
    ap.add_argument("--method", choices=["auto", "icmp", "system"], default="auto")
    args = ap.parse_args(argv)

    if args.cli:
        from .tracer import TraceOptions, trace_blocking
        if args.file:
            from .exporters import to_text
            from .parser import decode_bytes, parse_text
            with open(args.file, "rb") as f:
                print(to_text(parse_text(decode_bytes(f.read()))))
            return 0
        if not args.target:
            ap.error("укажите адрес назначения")
        trace_blocking(args.target, TraceOptions(max_hops=args.max_hops, timeout_ms=args.timeout,
                                                 probes=args.probes, parallel=args.parallel,
                                                 method=args.method))
        return 0

    import importlib.util
    if importlib.util.find_spec("tkinter") is None:
        print("Не найден модуль tkinter. В Windows переустановите Python с компонентом «tcl/tk and IDLE»,\n"
              "в Ubuntu/Debian: sudo apt install python3-tk", file=sys.stderr)
        return 1
    if importlib.util.find_spec("tkintermapview") is None:
        print("Не установлена библиотека карты. Выполните:\n    pip install -r requirements.txt", file=sys.stderr)
        return 1
    from .gui.app import run_app
    run_app(target=args.target, file=args.file)
    return 0


if __name__ == "__main__":
    sys.exit(main())

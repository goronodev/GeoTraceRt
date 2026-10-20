"""Оркестрация трассировки: выбор движка, цикл по TTL, системная утилита.

Результаты передаются через функцию emit(kind, payload):
    ("log",   str)                         — служебное сообщение
    ("start", {"target", "target_ip", "method", "max_hops"})
    ("hop",   Hop)                         — новый или обновлённый узел
    ("error", str)                         — ошибка (после неё всегда приходит "done")
    ("done",  {"reached", "reason", "cancelled"})
"""

from __future__ import annotations

import locale
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from .engines import EngineUnavailable, ProbeEngine, create_probe_engine
from .models import Hop
from .dnsresolve import ResolveError, clean_target, resolve_target
from .netutil import is_ip
from .parser import TraceParser

Emit = Callable[[str, object], None]

METHODS = {
    "auto": "Авто",
    "icmp": "Встроенный ICMP",
    "system": "Системная утилита (tracert/traceroute)",
}


@dataclass
class TraceOptions:
    max_hops: int = 30
    timeout_ms: int = 2000
    probes: int = 3
    parallel: int = 5          # сколько TTL опрашивать одновременно (1 = как tracert)
    stop_after_silent: int = 5  # остановиться после N молчащих узлов подряд (0 = нет)
    method: str = "auto"
    prefer_ipv6: bool = False


def run_trace(target: str, opts: TraceOptions, emit: Emit,
              cancel: Optional[threading.Event] = None) -> None:
    """Выполнить трассировку (блокирующе; вызывать в фоновом потоке)."""
    cancel = cancel or threading.Event()
    reached, reason = False, ""
    try:
        cleaned = clean_target(target) or target.strip()
        if cleaned != target.strip():
            emit("log", f"Адрес «{target.strip()}» приведён к виду {cleaned}")
        target = cleaned
        if not is_ip(target):
            emit("log", f"Разрешение имени {target}…")
        try:
            res = resolve_target(target, opts.prefer_ipv6)
        except ResolveError as e:
            emit("error", f"Не удается разрешить системное имя узла {target}.\n\nПричина: {e}")
            emit("done", {"reached": False, "reason": "Ошибка разрешения имени.", "cancelled": False})
            return
        dest_ip, family = res.ip, res.family
        if res.note:
            emit("log", res.note)

        engine: Optional[ProbeEngine] = None
        if opts.method in ("auto", "icmp"):
            try:
                engine = create_probe_engine(family)
                if family == socket.AF_INET and not _self_test(engine):
                    msg = "самопроверка встроенного движка на 127.0.0.1 не прошла"
                    if opts.method == "auto":
                        engine.close()
                        engine = None
                        emit("log", f"Внимание: {msg}; переключаюсь на системную утилиту.")
                    else:
                        emit("log", f"Внимание: {msg}.")
            except EngineUnavailable as e:
                if opts.method == "icmp":
                    emit("error", f"Встроенный ICMP-движок недоступен: {e}.")
                    emit("done", {"reached": False, "reason": "Движок недоступен.", "cancelled": False})
                    return
                emit("log", f"Встроенный ICMP-движок недоступен ({e}). Использую системную утилиту.")

        if engine is not None:
            emit("start", {"target": target, "target_ip": dest_ip, "method": engine.name,
                           "max_hops": opts.max_hops})
            try:
                reached, reason = _probe_loop(engine, dest_ip, opts, emit, cancel)
            finally:
                engine.close()
        else:
            tool = SystemTraceroute(family)
            emit("start", {"target": target, "target_ip": dest_ip, "method": tool.name,
                           "max_hops": opts.max_hops})
            reached, reason = tool.run(dest_ip, opts, emit, cancel)
    except EngineUnavailable as e:
        emit("error", str(e))
        reason = "Трассировка невозможна."
    except Exception as e:  # не даём фоновому потоку умереть молча
        emit("error", f"Непредвиденная ошибка: {type(e).__name__}: {e}")
        reason = "Ошибка."
    emit("done", {"reached": reached, "reason": reason, "cancelled": cancel.is_set()})


def _self_test(engine: ProbeEngine) -> bool:
    try:
        res = engine.probe("127.0.0.1", [64], 1, 1.0)
        p = res[64][0]
        return p is not None and p.kind == "reply"
    except Exception:
        return False


def _probe_loop(engine: ProbeEngine, dest_ip: str, opts: TraceOptions, emit: Emit,
                cancel: threading.Event) -> Tuple[bool, str]:
    ttl, silent = 1, 0
    timeout = max(0.1, opts.timeout_ms / 1000.0)
    while ttl <= opts.max_hops:
        if cancel.is_set():
            return False, "Трассировка прервана пользователем."
        window = list(range(ttl, min(ttl + max(1, opts.parallel), opts.max_hops + 1)))
        res = engine.probe(dest_ip, window, max(1, opts.probes), timeout, cancel)
        if cancel.is_set():
            return False, "Трассировка прервана пользователем."
        for t in window:
            probes = res.get(t, [])
            hop = Hop.from_probes(t, probes, dest_ip)
            emit("hop", hop)
            if hop.reached:
                return True, "Трассировка завершена."
            if hop.responded and any(p is not None and p.kind == "unreach" for p in probes):
                return False, f"Трассировка остановлена: {hop.addr} сообщает: {hop.note}"
            silent = 0 if hop.responded else silent + 1
            if opts.stop_after_silent and silent >= opts.stop_after_silent:
                return False, (f"Остановлено: {silent} узлов подряд не ответили "
                               f"(узел назначения или сеть, вероятно, блокирует ICMP).")
        ttl = window[-1] + 1
    return False, f"Достигнуто максимальное число прыжков ({opts.max_hops})."


class SystemTraceroute:
    """Запуск системной утилиты и разбор её вывода «на лету»."""

    def __init__(self, family: int = socket.AF_INET) -> None:
        self.family = family
        self.win = sys.platform == "win32"
        if self.win:
            self.exe = shutil.which("tracert") or "tracert"
            self.kind = "tracert"
        else:
            self.exe, self.kind = None, None
            for name in ("traceroute", "tracepath"):
                path = shutil.which(name) or next(
                    (p for p in (f"/usr/sbin/{name}", f"/sbin/{name}", f"/usr/bin/{name}")
                     if shutil.which(p)), None)
                if path:
                    self.exe, self.kind = path, name
                    break
            if not self.exe:
                raise EngineUnavailable(
                    "Нет прав на ICMP-сокеты и не найдена утилита traceroute/tracepath. "
                    "Установите traceroute (sudo apt install traceroute) или запустите программу "
                    "с правами root.")
        self.name = f"системная утилита {self.kind}"

    def command(self, dest_ip: str, opts: TraceOptions) -> list:
        if self.kind == "tracert":
            return [self.exe, "-d", "-h", str(opts.max_hops), "-w", str(opts.timeout_ms), dest_ip]
        if self.kind == "traceroute":
            cmd = [self.exe, "-n", "-m", str(opts.max_hops),
                   "-w", str(max(1, round(opts.timeout_ms / 1000))), "-q", str(max(1, opts.probes))]
            if self.family == socket.AF_INET6:
                cmd.append("-6")
            return cmd + [dest_ip]
        cmd = [self.exe, "-n", "-m", str(opts.max_hops)]
        if self.family == socket.AF_INET6:
            cmd.append("-6")
        return cmd + [dest_ip]

    def _encoding(self) -> str:
        if self.win:
            try:
                import ctypes
                return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
            except Exception:
                return "cp866"
        return locale.getpreferredencoding(False) or "utf-8"

    def run(self, dest_ip: str, opts: TraceOptions, emit: Emit,
            cancel: threading.Event) -> Tuple[bool, str]:
        cmd = self.command(dest_ip, opts)
        emit("log", "Команда: " + " ".join(cmd))
        flags = 0x08000000 if self.win else 0  # CREATE_NO_WINDOW
        env = None
        if not self.win:
            import os
            env = dict(os.environ, LC_ALL="C", LANG="C")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL, creationflags=flags, env=env)
        except OSError as e:
            raise EngineUnavailable(f"Не удалось запустить {cmd[0]}: {e}") from e

        stop_reason = {"text": ""}

        def watcher() -> None:
            while proc.poll() is None:
                if cancel.wait(0.2):
                    proc.terminate()
                    return

        threading.Thread(target=watcher, daemon=True).start()
        parser = TraceParser()
        enc = self._encoding()
        silent_ttls: set = set()
        reached = False
        assert proc.stdout is not None
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode(enc, errors="replace")
            hop = parser.feed(line)
            if hop is None:
                continue
            hop.reached = hop.addr == dest_ip or dest_ip in hop.extra_addrs
            emit("hop", Hop.from_dict(hop.to_dict()))   # копия: парсер продолжит менять свою
            if hop.reached:
                reached = True
            if hop.responded:
                silent_ttls.clear()
            else:
                silent_ttls.add(hop.ttl)
            if opts.stop_after_silent and len(silent_ttls) >= opts.stop_after_silent and proc.poll() is None:
                stop_reason["text"] = (f"Остановлено: {len(silent_ttls)} узлов подряд не ответили "
                                       f"(узел назначения или сеть, вероятно, блокирует ICMP).")
                proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        finally:
            proc.stdout.close()
        if cancel.is_set():
            return reached, "Трассировка прервана пользователем."
        if stop_reason["text"]:
            return reached, stop_reason["text"]
        if not parser.hops and proc.returncode not in (0, None):
            return False, f"{self.kind} завершился с кодом {proc.returncode}."
        return reached, "Трассировка завершена." if reached else "Утилита завершила работу."


def trace_blocking(target: str, opts: Optional[TraceOptions] = None,
                   printer: Callable[[str], None] = print):
    """Простой консольный режим: python -m tracemap --cli ya.ru"""
    from .exporters import format_hop_line
    opts = opts or TraceOptions()
    started = time.time()

    def emit(kind, payload):
        if kind == "start":
            printer(f"\nТрассировка маршрута к {payload['target']} [{payload['target_ip']}]")
            printer(f"с максимальным числом прыжков {payload['max_hops']} ({payload['method']}):\n")
        elif kind == "hop":
            printer(format_hop_line(payload, opts.probes))
        elif kind in ("error", "log"):
            printer(("Ошибка: " if kind == "error" else "") + str(payload))
        elif kind == "done":
            printer(f"\n{payload['reason']} ({time.time() - started:.1f} с)")

    run_trace(target, opts, emit)

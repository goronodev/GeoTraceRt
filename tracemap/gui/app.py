"""Главное окно TracertMap: ввод адреса, таблица узлов, вывод в стиле tracert и карта."""

from __future__ import annotations

import datetime as _dt
import math
import os
import queue
import re
import threading
import time
import tkinter as tk
import traceback
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont
from typing import Dict, Optional

import tkintermapview

from .. import APP_NAME, __version__
from ..exporters import format_hop_line, to_csv, to_html, to_json, to_text
from ..geo import PROVIDERS, GeoError, GeoResolver
from ..geomath import haversine_km, split_antimeridian
from ..models import GeoInfo, Hop, TraceResult
from ..dnsresolve import clean_target
from ..netutil import resolve, reverse_dns, route_signature
from ..route import (COLOR_FAST, COLOR_MEDIUM, COLOR_ORIGIN, COLOR_SLOW, COLOR_UNKNOWN,
                     RouteView, build_route, fmt_rtt, rtt_color)
from ..tracer import METHODS, TraceOptions, run_trace
from .icons import IconFactory, mono_font_family
from .load_dialog import FILETYPES, LoadTraceDialog, read_trace_file
from .settings import DEFAULT_TILES, TILE_SERVERS, Settings


def _d2o(lat: float, lon: float, zoom: int):
    lat = max(-85.0, min(85.0, lat))
    n = 2.0 ** zoom
    x = (lon + 180.0) / 360.0 * n
    y = (1.0 - math.asinh(math.tan(math.radians(lat))) / math.pi) / 2.0 * n
    return x, y


def _o2d(x: float, y: float, zoom: int):
    n = 2.0 ** zoom
    lon = x / n * 360.0 - 180.0
    lat = math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * y / n))))
    return lat, lon


class GeoWorker(threading.Thread):
    """Фоновая геолокация: собирает адреса в пачки, чтобы не превышать лимиты API."""

    def __init__(self, resolver: GeoResolver, post) -> None:
        super().__init__(daemon=True, name="geo")
        self.resolver = resolver
        self.post = post
        self.q: "queue.Queue[list]" = queue.Queue()
        self.start()

    def request(self, ips) -> None:
        ips = [ip for ip in ips if ip]
        if ips:
            self.q.put(ips)

    def run(self) -> None:
        while True:
            batch = list(self.q.get())
            end = time.monotonic() + 0.8
            while True:
                rest = end - time.monotonic()
                if rest <= 0:
                    break
                try:
                    batch += self.q.get(timeout=rest)
                except queue.Empty:
                    break
            batch = list(dict.fromkeys(batch))
            resolver = self.resolver
            try:
                res = resolver.lookup(batch)
                if resolver.last_error:
                    self.post("geo_error", resolver.last_error)
            except Exception as e:
                res = {}
                self.post("geo_error", f"{type(e).__name__}: {e}")
            self.post("geo", (batch, res))


class OriginWorker(threading.Thread):
    """Определение своего внешнего IP и местоположения. Запросы, пришедшие во время
    проверки, объединяются в одну следующую проверку."""

    def __init__(self, get_resolver, post) -> None:
        super().__init__(daemon=True, name="origin")
        self.get_resolver = get_resolver
        self.post = post
        self.q: "queue.Queue[tuple]" = queue.Queue()
        self.start()

    def request(self, reason: str, apply_run: Optional[int]) -> None:
        self.q.put((reason, apply_run))

    def run(self) -> None:
        while True:
            items = [self.q.get()]
            while True:
                try:
                    items.append(self.q.get_nowait())
                except queue.Empty:
                    break
            reason = items[-1][0]
            runs = {r for _, r in items if r is not None}
            self.post("origin_busy", reason)
            try:
                res = self.get_resolver().my_location()
            except Exception:
                res = None
            self.post("origin", {"res": res, "runs": runs, "reason": reason})


class NetWatcher(threading.Thread):
    """Следит за сменой сети (VPN включён/выключен, другой Wi-Fi) без сетевых запросов."""

    INTERVAL = 3.0

    def __init__(self, post) -> None:
        super().__init__(daemon=True, name="netwatch")
        self.post = post
        self.start()

    def run(self) -> None:
        last = route_signature()
        while True:
            time.sleep(self.INTERVAL)
            try:
                cur = route_signature()
            except Exception:
                continue
            if cur != last:
                self.post("netchange", (last, cur))
                last = cur


class TracertMapApp:
    def __init__(self, root: tk.Tk, target: Optional[str] = None, file: Optional[str] = None) -> None:
        self.root = root
        self.s = Settings.load()
        self.events: "queue.Queue[tuple]" = queue.Queue()
        self.run_id = 0
        self.cancel = threading.Event()
        self.running = False
        self.trace: Optional[TraceResult] = None
        self.trace_uses_my_origin = True
        self.trace_follows_me = False      # точку старта текущего маршрута можно обновлять
        self.origin: Optional[GeoInfo] = None
        self.origin_ip = ""
        self.origin_suffix = ""
        self._netchange_job = None
        self.geo_by_ip: Dict[str, GeoInfo] = {}
        self.geo_pending: set = set()
        self.dns_done: set = set()
        self.selected_ttl: Optional[int] = None
        self.view: Optional[RouteView] = None
        self.log_lines: list = []
        self.done_reason = ""
        self.user_moved_map = False
        self._redraw_job = None
        self._in_redraw = False
        self._fit_pending = False
        self._fit_job = None
        self._last_located = -1
        self.dns_pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix="rdns")

        self.scale = max(1.0, root.winfo_fpixels("1i") / 96.0)
        self.icons = IconFactory(self.scale)
        self.geo = GeoWorker(self._make_resolver(), self._post_global)

        self._setup_style()
        self._build_menu()
        self._build_ui()
        self._apply_tiles(initial=True)
        self._bind_keys()
        self._show_summary()

        root.title(f"{APP_NAME} — трассировка маршрута на карте мира")
        try:
            root.iconphoto(True, self.icons.marker("T", "#3E69CB"))
        except tk.TclError:
            pass
        if self.s.geometry:
            try:
                root.geometry(self.s.geometry)
            except tk.TclError:
                pass
        else:
            root.geometry(f"{int(1360 * self.scale)}x{int(820 * self.scale)}")
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(50, self._poll)
        root.after(300, self._restore_sash)
        self.origin_worker = OriginWorker(lambda: self.geo.resolver, self._post_global)
        self.refresh_origin("startup")
        self.net_watcher = NetWatcher(self._post_global)

        if file:
            root.after(400, lambda: self.load_file(file))
        elif target:
            self.target_var.set(target)
            root.after(400, self.start_trace)

    # ------------------------------------------------------------------ UI
    def _setup_style(self) -> None:
        style = ttk.Style(self.root)
        if self.root.tk.call("tk", "windowingsystem") == "x11" and "clam" in style.theme_names():
            style.theme_use("clam")
        base = tkfont.nametofont("TkDefaultFont")
        self.font_bold = base.copy()
        self.font_bold.configure(weight="bold")
        self.font_small = base.copy()
        size = int(base.cget("size"))
        self.font_small.configure(size=size - 1 if size > 0 else size + 1)
        self.font_mono = tkfont.Font(family=mono_font_family(), size=10)
        style.configure("Treeview", rowheight=int(24 * self.scale))
        style.configure("Accent.TButton", font=self.font_bold)
        style.configure("Status.TLabel", padding=(8, 3))
        style.configure("Legend.TLabel", background="#FFFFFF", foreground="#1D2330", font=self.font_small)
        style.configure("Legend.TFrame", background="#FFFFFF")

    def _build_menu(self) -> None:
        m = tk.Menu(self.root)
        f = tk.Menu(m, tearoff=False)
        f.add_command(label="Новая трассировка", accelerator="F5", command=self.start_trace)
        f.add_command(label="Построить по готовой трассировке…", accelerator="Ctrl+O", command=self.open_load_dialog)
        f.add_command(label="Открыть файл трассировки…", command=self.open_file)
        f.add_separator()
        f.add_command(label="Сохранить как…", accelerator="Ctrl+S", command=self.save_as)
        f.add_command(label="Экспорт в HTML-карту…", accelerator="Ctrl+E", command=self.export_html)
        f.add_separator()
        f.add_command(label="Выход", command=self.on_close)
        m.add_cascade(label="Файл", menu=f)

        v = tk.Menu(m, tearoff=False)
        self.tile_var = tk.StringVar(value=self.s.tile_server)
        tiles = tk.Menu(v, tearoff=False)
        for name in TILE_SERVERS:
            tiles.add_radiobutton(label=name, value=name, variable=self.tile_var, command=self._apply_tiles)
        v.add_cascade(label="Подложка карты", menu=tiles)
        v.add_command(label="Показать весь маршрут", command=self.fit_route)
        v.add_command(label="Очистить", command=self.clear)
        m.add_cascade(label="Вид", menu=v)

        g = tk.Menu(m, tearoff=False)
        self.provider_var = tk.StringVar(value=self.s.geo_provider)
        for key, title in PROVIDERS.items():
            g.add_radiobutton(label=title, value=key, variable=self.provider_var, command=self._change_provider)
        g.add_command(label="Выбрать файл базы .mmdb…", command=self._choose_mmdb)
        g.add_separator()
        self.lang_var = tk.StringVar(value=self.s.geo_lang)
        g.add_radiobutton(label="Названия на русском", value="ru", variable=self.lang_var, command=self._change_provider)
        g.add_radiobutton(label="Названия на английском", value="en", variable=self.lang_var, command=self._change_provider)
        g.add_separator()
        g.add_command(label="Повторить геолокацию узлов", command=self.retry_geo)
        g.add_command(label="Обновить мой IP и местоположение", accelerator="F6",
                      command=lambda: self.refresh_origin("manual"))
        g.add_command(label="Очистить кэш геолокации", command=self._clear_geo_cache)
        m.add_cascade(label="Геолокация", menu=g)

        h = tk.Menu(m, tearoff=False)
        h.add_command(label="Как это работает", command=self._help)
        h.add_command(label="О программе", command=self._about)
        m.add_cascade(label="Справка", menu=h)
        self.root.configure(menu=m)

    def _build_ui(self) -> None:
        root = self.root
        top = ttk.Frame(root, padding=(10, 8, 10, 4))
        top.pack(fill="x")

        row1 = ttk.Frame(top)
        row1.pack(fill="x")
        ttk.Label(row1, text="Узел назначения (IP или домен):").pack(side="left")
        self.target_var = tk.StringVar()
        self.target_cb = ttk.Combobox(row1, textvariable=self.target_var, values=self.s.history, width=34)
        self.target_cb.pack(side="left", padx=(6, 6))
        self.target_cb.bind("<Return>", lambda e: self.start_trace())
        self.btn_start = ttk.Button(row1, text="Трассировать", style="Accent.TButton", command=self.start_trace)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(row1, text="Стоп", command=self.stop_trace, state="disabled")
        self.btn_stop.pack(side="left", padx=(6, 0))
        ttk.Separator(row1, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Button(row1, text="Построить по готовой трассировке…", command=self.open_load_dialog).pack(side="left")
        ttk.Button(row1, text="HTML-карта", command=self.export_html).pack(side="right")
        ttk.Button(row1, text="Сохранить…", command=self.save_as).pack(side="right", padx=6)

        row2 = ttk.Frame(top)
        row2.pack(fill="x", pady=(6, 0))
        self.v_hops = tk.StringVar(value=str(self.s.max_hops))
        self.v_timeout = tk.StringVar(value=str(self.s.timeout_ms))
        self.v_probes = tk.StringVar(value=str(self.s.probes))
        self.v_parallel = tk.StringVar(value=str(self.s.parallel))
        self.v_silent = tk.StringVar(value=str(self.s.stop_after_silent))
        self.v_dns = tk.BooleanVar(value=self.s.resolve_names)
        self.v_method = tk.StringVar(value=METHODS.get(self.s.method, METHODS["auto"]))

        def spin(label, var, lo, hi, inc=1, width=5, tip=None):
            ttk.Label(row2, text=label).pack(side="left")
            sb = ttk.Spinbox(row2, from_=lo, to=hi, increment=inc, textvariable=var, width=width)
            sb.pack(side="left", padx=(4, 12))
            return sb

        spin("Макс. прыжков:", self.v_hops, 1, 64)
        spin("Таймаут, мс:", self.v_timeout, 200, 10000, 100, 6)
        spin("Запросов:", self.v_probes, 1, 5, width=3)
        spin("Параллельно:", self.v_parallel, 1, 16, width=3)
        spin("Стоп после пустых:", self.v_silent, 0, 30, width=3)
        ttk.Label(row2, text="Метод:").pack(side="left")
        ttk.Combobox(row2, textvariable=self.v_method, values=list(METHODS.values()), state="readonly",
                     width=34).pack(side="left", padx=(4, 12))
        ttk.Checkbutton(row2, text="DNS-имена узлов", variable=self.v_dns).pack(side="left")

        # --- центральная часть
        self.paned = ttk.PanedWindow(root, orient="horizontal")
        self.paned.pack(fill="both", expand=True, padx=10, pady=(4, 0))

        left = ttk.Frame(self.paned)
        self.paned.add(left, weight=0)
        self.nb = ttk.Notebook(left)
        self.nb.pack(fill="both", expand=True)

        tab_table = ttk.Frame(self.nb)
        self.nb.add(tab_table, text="Узлы маршрута")
        cols = ("addr", "host", "rtt", "place", "prov")
        self.tree = ttk.Treeview(tab_table, columns=cols, show="tree headings", selectmode="browse", height=14)
        heads = {"#0": ("№", 56), "addr": ("IP-адрес", 118), "host": ("Имя узла", 130),
                 "rtt": ("Задержки, мс", 96), "place": ("Местоположение", 170), "prov": ("Провайдер / AS", 170)}
        for c, (title, w) in heads.items():
            self.tree.heading(c, text=title, anchor="w")
            self.tree.column(c, width=int(w * self.scale), minwidth=40, stretch=c in ("place", "prov"), anchor="w")
        ys = ttk.Scrollbar(tab_table, orient="vertical", command=self.tree.yview)
        xs = ttk.Scrollbar(tab_table, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        tab_table.rowconfigure(0, weight=1)
        tab_table.columnconfigure(0, weight=1)
        self.tree.tag_configure("timeout", foreground="#8A8F98")
        self.tree.tag_configure("dest", font=self.font_bold)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Button-3>", self._tree_menu)
        self.tree.bind("<Button-2>", self._tree_menu)
        self.tree.bind("<Double-1>", lambda e: self._zoom_to_selected())
        self.tree.bind("<Escape>", lambda e: self._clear_selection())

        tab_out = ttk.Frame(self.nb)
        self.nb.add(tab_out, text="Вывод (как tracert)")
        self.out = tk.Text(tab_out, wrap="none", font=self.font_mono, state="disabled", relief="flat",
                           padx=8, pady=6, height=14)
        oys = ttk.Scrollbar(tab_out, orient="vertical", command=self.out.yview)
        oxs = ttk.Scrollbar(tab_out, orient="horizontal", command=self.out.xview)
        self.out.configure(yscrollcommand=oys.set, xscrollcommand=oxs.set)
        self.out.grid(row=0, column=0, sticky="nsew")
        oys.grid(row=0, column=1, sticky="ns")
        oxs.grid(row=1, column=0, sticky="ew")
        tab_out.rowconfigure(0, weight=1)
        tab_out.columnconfigure(0, weight=1)

        info_box = ttk.LabelFrame(left, text="Подробности", padding=(6, 4))
        info_box.pack(fill="x", pady=(8, 0))
        self.info = tk.Text(info_box, height=9, wrap="word", relief="flat", state="disabled", padx=4, pady=2,
                            font="TkDefaultFont")
        self.info.pack(fill="both", expand=True)
        self.info.tag_configure("h", font=self.font_bold)
        self.info.tag_configure("k", foreground="#667085")
        self.info.tag_configure("warn", foreground="#B54708")

        # --- карта
        self.map_frame = ttk.Frame(self.paned)
        self.paned.add(self.map_frame, weight=1)
        self.map = tkintermapview.TkinterMapView(self.map_frame, corner_radius=0)
        self.map.pack(fill="both", expand=True)
        self.map.set_zoom(3)
        self.map.set_position(50.0, 60.0)
        for ev in ("<ButtonPress-1>", "<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.map.canvas.bind(ev, self._map_touched, add="+")

        ctrl = ttk.Frame(self.map_frame)
        ctrl.place(relx=1.0, x=-10, y=10, anchor="ne")
        self.tile_cb = ttk.Combobox(ctrl, values=list(TILE_SERVERS), textvariable=self.tile_var,
                                    state="readonly", width=24)
        self.tile_cb.pack(side="left")
        self.tile_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_tiles())
        ttk.Button(ctrl, text="Весь маршрут", command=self.fit_route).pack(side="left", padx=(6, 0))

        legend = ttk.Frame(self.map_frame, style="Legend.TFrame", padding=(8, 5))
        legend.place(relx=0.0, rely=1.0, x=10, y=-10, anchor="sw")
        for color, text in ((COLOR_FAST, "< 50 мс"), (COLOR_MEDIUM, "50–150 мс"), (COLOR_SLOW, "> 150 мс"),
                            (COLOR_UNKNOWN, "нет данных"), (COLOR_ORIGIN, "старт")):
            ttk.Label(legend, image=self.icons.dot(color, 12), text=f" {text}", compound="left",
                      style="Legend.TLabel").pack(anchor="w")
        self.attr_label = ttk.Label(self.map_frame, style="Legend.TLabel", padding=(4, 1))
        self.attr_label.place(relx=1.0, rely=1.0, anchor="se")

        # --- строка состояния
        # Упаковываем раньше карты (before=...), иначе в невысоком окне строку состояния
        # вытесняет растягивающаяся центральная часть.
        bar = ttk.Frame(root)
        bar.pack(fill="x", side="bottom", before=self.paned)
        ttk.Separator(root, orient="horizontal").pack(fill="x", side="bottom", before=self.paned)
        self.status_var = tk.StringVar(value="Введите адрес и нажмите «Трассировать» "
                                             "или постройте маршрут по готовой трассировке.")
        ttk.Label(bar, textvariable=self.status_var, style="Status.TLabel").pack(side="left", fill="x", expand=True)
        self.origin_var = tk.StringVar(value="Определяю ваш IP…")
        self.btn_origin = ttk.Button(bar, text="Обновить IP", command=lambda: self.refresh_origin("manual"))
        self.btn_origin.pack(side="right", padx=(0, 6), pady=2)
        ttk.Label(bar, textvariable=self.origin_var, style="Status.TLabel").pack(side="right")
        self.progress = ttk.Progressbar(bar, length=int(160 * self.scale), mode="determinate")
        self.progress.pack(side="right", padx=8, pady=3)

    def _bind_keys(self) -> None:
        r = self.root
        for seq, fn in (("<F5>", self.start_trace), ("<Escape>", self.stop_trace),
                        ("<Control-o>", self.open_load_dialog), ("<Control-O>", self.open_load_dialog),
                        ("<Control-s>", self.save_as), ("<Control-S>", self.save_as),
                        ("<Control-e>", self.export_html), ("<Control-E>", self.export_html),
                        ("<F6>", lambda: self.refresh_origin("manual"))):
            r.bind(seq, lambda e, f=fn: (f(), "break")[1])

    def _restore_sash(self) -> None:
        try:
            total = self.paned.winfo_width()
            pos = self.s.sash if 200 < self.s.sash < total - 200 else int(total * 0.46)
            self.paned.sashpos(0, pos)
        except tk.TclError:
            pass

    # ------------------------------------------------------------- events
    def _post_global(self, kind: str, payload=None) -> None:
        self.events.put((None, kind, payload))

    def _emitter(self, run_id: int):
        return lambda kind, payload=None: self.events.put((run_id, kind, payload))

    def _poll(self) -> None:
        try:
            for _ in range(300):
                rid, kind, payload = self.events.get_nowait()
                if rid is not None and rid != self.run_id:
                    continue
                handler = getattr(self, f"_on_{kind}", None)
                if handler is None:
                    continue
                try:
                    handler(payload)
                except Exception:
                    traceback.print_exc()
                    self.status(f"Внутренняя ошибка при обработке «{kind}» — подробности в консоли.")
        except queue.Empty:
            pass
        finally:
            self.root.after(40, self._poll)

    def _on_start(self, p: dict) -> None:
        t = self.trace
        t.target = p.get("target") or t.target
        t.target_ip = p["target_ip"]
        t.source = p["method"]
        t.max_hops = p["max_hops"]
        self.progress.configure(maximum=t.max_hops, value=0)
        self.status(f"Трассировка маршрута к {t.target} [{t.target_ip}] · {t.source}")
        self._render_output()

    def _on_hop(self, hop: Hop) -> None:
        if hop.addr and hop.addr in self.geo_by_ip:
            hop.geo = self.geo_by_ip[hop.addr]
        self.trace.upsert(hop)
        hop = self.trace.hop_by_ttl(hop.ttl)
        self._update_row(hop)
        self._request_info([hop])
        self.progress.configure(value=hop.ttl)
        self._render_output()
        self._schedule_redraw()

    def _on_log(self, msg: str) -> None:
        self.log_lines.append(msg)
        self.status(msg)
        self._render_output()

    def _on_error(self, msg: str) -> None:
        self.log_lines.append("Ошибка: " + msg)
        self.status(msg)
        self._render_output()
        self.root.after(50, lambda: messagebox.showerror(APP_NAME, msg, parent=self.root))

    def _on_done(self, p: dict) -> None:
        self.running = False
        self.trace_follows_me = False   # маршрут снят с того адреса, что был во время трассировки
        self._update_buttons()
        if self.trace is not None:
            self.trace.completed = True
            self.done_reason = p.get("reason", "")
            if self.trace.hops:
                self.progress.configure(value=self.trace.max_hops if p.get("reached") else self.trace.hops[-1].ttl)
        self._render_output()
        self.status(self._summary_line(prefix=self.done_reason))
        if self.selected_ttl is None:
            self._show_summary()
        self._request_fit()

    def _on_geo(self, payload) -> None:
        requested, results = payload
        changed = False
        for ip in requested:
            self.geo_pending.discard(ip)
            g = results.get(ip) or GeoInfo(source="нет данных")
            self.geo_by_ip[ip] = g
        if self.trace is not None:
            for hop in self.trace.hops:
                if hop.addr in self.geo_by_ip and hop.geo is not self.geo_by_ip[hop.addr]:
                    hop.geo = self.geo_by_ip[hop.addr]
                    self._update_row(hop)
                    changed = True
        if changed:
            self._schedule_redraw()
            if self.selected_ttl is not None:
                self._show_info(self.selected_ttl)
            elif self.trace and self.trace.completed:
                self._show_summary()
            if self.trace and self.trace.completed and not self.running:
                self.status(self._summary_line(prefix=self.done_reason))
            self._request_fit()

    def _on_geo_error(self, msg: str) -> None:
        self.status(f"Геолокация: {msg}")

    def _on_host(self, payload) -> None:
        addr, name = payload
        if not name or self.trace is None:
            return
        for hop in self.trace.hops:
            if hop.addr == addr and not hop.host:
                hop.host = name
                self._update_row(hop)
        self._render_output()

    def _on_resolved(self, payload) -> None:
        ttl, ip = payload
        hop = self.trace.hop_by_ttl(ttl) if self.trace else None
        if hop is not None and ip and not hop.addr:
            hop.addr = ip
            self._update_row(hop)
            self._request_info([hop])

    # ----------------------------------------------------- my IP / origin
    def refresh_origin(self, reason: str = "manual") -> None:
        """Заново определить свой внешний IP (например, после включения/выключения VPN).

        reason: "startup" | "manual" | "network" | "trace".
        """
        if reason == "trace":
            apply_run = self.run_id
        elif self.trace is not None and self.trace_follows_me:
            apply_run = self.run_id
        else:
            apply_run = None
        self.origin_worker.request(reason, apply_run)

    def _origin_text(self) -> str:
        if not self.origin_ip:
            return "Ваш IP не определён"
        place = self.origin.place if self.origin else ""
        return f"Вы: {self.origin_ip}" + (f" · {place}" if place else "") + self.origin_suffix

    def _on_origin_busy(self, reason: str) -> None:
        self.btn_origin.configure(state="disabled")
        self.origin_var.set((self._origin_text() + " — обновляю…") if self.origin_ip else "Определяю ваш IP…")

    def _on_origin(self, payload: dict) -> None:
        self.btn_origin.configure(state="normal")
        res, runs, reason = payload["res"], payload["runs"], payload["reason"]
        if res is None:
            if self.origin_ip:
                self.origin_var.set(self._origin_text() + " (обновить не удалось)")
            else:
                self.origin_var.set("Ваш IP не определён — нет связи с сервисом геолокации")
            if reason in ("manual", "network"):
                self.status("Не удалось определить внешний IP: сервисы геолокации недоступны.")
            return
        old_ip, first = self.origin_ip, not self.origin_ip
        self.origin, self.origin_ip = res.geo, res.ip
        if res.proxy and res.direct:
            self.origin_suffix = " · мимо системного прокси"
        elif not res.direct:
            self.origin_suffix = " · через прокси (точка старта может быть неточной)"
        else:
            self.origin_suffix = ""
        self.origin_var.set(self._origin_text())

        applied = False
        if self.trace is not None and self.trace_uses_my_origin and (
                self.run_id in runs or (self.trace.origin is None and self.trace_follows_me)):
            prev = self.trace.origin
            self.trace.origin = res.geo
            applied = prev is None or (prev.lat, prev.lon) != (res.geo.lat, res.geo.lon)
            if applied:
                self._schedule_redraw()
                self._request_fit()
        elif self.trace is None and (first or old_ip != res.ip):
            self.map.set_zoom(4)
            self.map.set_position(res.geo.lat, res.geo.lon)

        if old_ip and old_ip != res.ip:
            msg = f"Ваш внешний IP изменился: {old_ip} → {res.ip}"
            if res.geo.place:
                msg += f" ({res.geo.place})"
            t_origin = self.trace.origin if self.trace is not None else None
            if (t_origin is not None and self.trace_uses_my_origin and not applied and not self.running
                    and (round(t_origin.lat, 2), round(t_origin.lon, 2))
                    != (round(res.geo.lat, 2), round(res.geo.lon, 2))):
                msg += ". Текущий маршрут построен со старого адреса — запустите трассировку заново."
            self.status(msg)
        elif reason == "manual":
            self.status(f"Внешний IP не изменился: {res.ip}" + (f" ({res.geo.place})" if res.geo.place else ""))

    def _on_netchange(self, payload) -> None:
        old, new = payload
        self.status(f"Сеть изменилась (локальный адрес {old[0] or '—'} → {new[0] or '—'}) — "
                    f"проверяю внешний IP…")
        if self._netchange_job is not None:
            self.root.after_cancel(self._netchange_job)
        # VPN-клиент часто меняет маршруты в несколько шагов — ждём, пока всё уляжется
        self._netchange_job = self.root.after(2500, self._netchange_settled)

    def _netchange_settled(self) -> None:
        self._netchange_job = None
        self.refresh_origin("network")

    # --------------------------------------------------------- actions
    def status(self, text: str) -> None:
        self.status_var.set(text)

    def _read_options(self) -> TraceOptions:
        def num(var, default, lo, hi):
            try:
                return max(lo, min(hi, int(float(var.get()))))
            except (ValueError, tk.TclError):
                return default
        method = next((k for k, v in METHODS.items() if v == self.v_method.get()), "auto")
        opts = TraceOptions(max_hops=num(self.v_hops, 30, 1, 64), timeout_ms=num(self.v_timeout, 2000, 100, 30000),
                            probes=num(self.v_probes, 3, 1, 10), parallel=num(self.v_parallel, 5, 1, 32),
                            stop_after_silent=num(self.v_silent, 5, 0, 64), method=method)
        self.s.max_hops, self.s.timeout_ms, self.s.probes = opts.max_hops, opts.timeout_ms, opts.probes
        self.s.parallel, self.s.stop_after_silent, self.s.method = opts.parallel, opts.stop_after_silent, method
        self.s.resolve_names = bool(self.v_dns.get())
        return opts

    def start_trace(self, target: Optional[str] = None) -> None:
        target = clean_target(target or self.target_var.get())
        if not target:
            messagebox.showwarning(APP_NAME, "Введите IP-адрес или доменное имя узла назначения.", parent=self.root)
            self.target_cb.focus_set()
            return
        if self.running:
            self.cancel.set()
        opts = self._read_options()
        self.s.remember_target(target)
        self.target_cb.configure(values=self.s.history)
        self.target_var.set(target)
        self.run_id += 1
        self.cancel = threading.Event()
        self._reset_view()
        self.trace = TraceResult(target=target, max_hops=opts.max_hops, origin=self.origin, source="…")
        self.trace_uses_my_origin = True
        self.trace_follows_me = True
        self.refresh_origin("trace")     # точка старта — по текущему внешнему IP (VPN мог смениться)
        self.running = True
        self._update_buttons()
        self.progress.configure(maximum=opts.max_hops, value=0)
        self.nb.select(0)
        self.status(f"Запуск трассировки к {target}…")
        threading.Thread(target=run_trace, args=(target, opts, self._emitter(self.run_id), self.cancel),
                         daemon=True, name="trace").start()

    def stop_trace(self) -> None:
        if self.running:
            self.cancel.set()
            self.status("Остановка…")

    def clear(self) -> None:
        if self.running:
            self.cancel.set()
            self.running = False
            self._update_buttons()
        self.run_id += 1
        self.trace = None
        self.trace_follows_me = False
        self._reset_view()
        self._show_summary()
        self.status("Очищено.")

    def _reset_view(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.selected_ttl = None
        self.view = None
        self.log_lines = []
        self.done_reason = ""
        self.user_moved_map = False
        self._last_located = -1
        self._in_redraw = True
        try:
            self.map.delete_all_path()
            self.map.delete_all_marker()
        finally:
            self._in_redraw = False
        self._set_text(self.out, "")
        self._set_text(self.info, "")

    def _update_buttons(self) -> None:
        self.btn_start.configure(state="disabled" if self.running else "normal")
        self.btn_stop.configure(state="normal" if self.running else "disabled")

    def open_load_dialog(self) -> None:
        LoadTraceDialog(self.root, self._on_trace_loaded)

    def open_file(self) -> None:
        path = filedialog.askopenfilename(parent=self.root, title="Открыть трассировку", filetypes=FILETYPES)
        if path:
            self.load_file(path)

    def load_file(self, path: str) -> None:
        try:
            text = read_trace_file(path)
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Не удалось прочитать файл:\n{e}", parent=self.root)
            return
        LoadTraceDialog(self.root, self._on_trace_loaded, initial_text=text).source_name = os.path.basename(path)

    def _on_trace_loaded(self, trace: TraceResult, from_here: bool, source_name: str) -> None:
        if self.running:
            self.cancel.set()
            self.running = False
            self._update_buttons()
        self.run_id += 1
        self._reset_view()
        if not trace.source or not trace.started:
            trace.source = f"загружено: {source_name}"
        self.trace = trace
        self.trace_uses_my_origin = from_here
        self.trace_follows_me = from_here and trace.origin is None   # в JSON старт уже сохранён
        if from_here and trace.origin is None:
            trace.origin = self.origin
        self.target_var.set(trace.target or trace.target_ip or "")
        for hop in trace.hops:
            self._update_row(hop)
        self._request_info(trace.hops)
        self.done_reason = "Маршрут построен по готовой трассировке."
        self.progress.configure(maximum=max(1, trace.max_hops), value=trace.max_hops)
        self._render_output()
        self._show_summary()
        self._schedule_redraw()
        self._request_fit()
        located = sum(1 for h in trace.hops if h.geo is not None)
        need = sum(1 for h in trace.hops if h.addr and h.geo is None)
        self.status(f"Загружено узлов: {len(trace.hops)}" +
                    (f" · определяю местоположение {need} адресов…" if need else f" · с геоданными: {located}"))

    def _request_info(self, hops) -> None:
        geo_req = []
        for hop in hops:
            if hop.addr and hop.geo is None:
                if hop.addr in self.geo_by_ip:
                    hop.geo = self.geo_by_ip[hop.addr]
                    self._update_row(hop)
                elif hop.addr not in self.geo_pending:
                    self.geo_pending.add(hop.addr)
                    geo_req.append(hop.addr)
            if hop.addr and not hop.host and self.v_dns.get() and hop.addr not in self.dns_done:
                self.dns_done.add(hop.addr)
                addr = hop.addr
                fut = self.dns_pool.submit(reverse_dns, addr)
                fut.add_done_callback(lambda f, a=addr: self._post_global("host", (a, f.result())))
            if not hop.addr and hop.host:
                ttl, host = hop.ttl, hop.host

                def job(ttl=ttl, host=host):
                    try:
                        return ttl, resolve(host)[0]
                    except Exception:
                        return ttl, None
                self.dns_pool.submit(job).add_done_callback(lambda f: self._post_global("resolved", f.result()))
        if geo_req:
            self.geo.request(geo_req)

    def retry_geo(self) -> None:
        if not self.trace:
            return
        for hop in self.trace.hops:
            if hop.addr and (hop.geo is None or (not hop.geo.has_coords and not hop.geo.private)):
                hop.geo = None
                self.geo_by_ip.pop(hop.addr, None)
                self.geo_pending.discard(hop.addr)
        self._request_info(self.trace.hops)
        self.status("Повторная геолокация…")

    # ---------------------------------------------------------- table
    def _row_values(self, hop: Hop):
        g = hop.geo
        suspicious = self.view is not None and hop.ttl in self.view.suspicious
        if hop.responded:
            addr = hop.addr + (f"  (+{len(hop.extra_addrs)})" if hop.extra_addrs else "")
            if g is None:
                place = "определяется…" if hop.addr in self.geo_pending else ""
            elif g.private:
                place = "Частная сеть"
            elif g.has_coords:
                place = g.place or f"{g.lat:.2f}, {g.lon:.2f}"
            else:
                place = "нет данных"
            if suspicious:
                place = "⚠ " + place
            prov = g.provider if g else ""
        else:
            addr = hop.host or "*"
            place = "Превышен интервал ожидания" if not hop.host else "имя не разрешено"
            prov = ""
        host = hop.host or ""
        if hop.note:
            host = f"{host}  [{hop.note}]".strip()
        rtt = " / ".join(fmt_rtt(r) for r in hop.rtts) or "—"
        return addr, host, rtt, place, prov

    def _update_row(self, hop: Hop) -> None:
        iid = f"ttl{hop.ttl}"
        color = rtt_color(hop.avg_rtt) if hop.responded else COLOR_UNKNOWN
        tags = ["timeout"] if not hop.responded else []
        if hop.reached:
            tags.append("dest")
        values = self._row_values(hop)
        img = self.icons.dot(color, 12)
        if self.tree.exists(iid):
            self.tree.item(iid, text=f" {hop.ttl}", values=values, image=img, tags=tags)
        else:
            ttls = sorted(int(i[3:]) for i in self.tree.get_children())
            index = sum(1 for t in ttls if t < hop.ttl)
            self.tree.insert("", index, iid=iid, text=f" {hop.ttl}", values=values, image=img, tags=tags)
            self.tree.see(iid)

    def _refresh_rows(self) -> None:
        if self.trace:
            for hop in self.trace.hops:
                self._update_row(hop)

    def _on_tree_select(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        ttl = int(sel[0][3:])
        if ttl == self.selected_ttl:
            return
        self.selected_ttl = ttl
        self._show_info(ttl)
        self._schedule_redraw()
        pt = self.view.point_for_ttl(ttl) if self.view else None
        if pt is not None:
            self.map.set_position(pt.lat, pt.lon)

    def _clear_selection(self) -> None:
        self.tree.selection_remove(*self.tree.selection())
        self.selected_ttl = None
        self._show_summary()
        self._schedule_redraw()

    def _zoom_to_selected(self) -> None:
        if self.selected_ttl is None or self.view is None:
            return
        pt = self.view.point_for_ttl(self.selected_ttl)
        if pt is not None:
            self.map.set_zoom(max(int(round(self.map.zoom)), 8))
            self.map.set_position(pt.lat, pt.lon)

    def _tree_menu(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        hop = self.trace.hop_by_ttl(int(iid[3:])) if self.trace else None
        if hop is None:
            return
        m = tk.Menu(self.root, tearoff=False)
        if hop.addr:
            m.add_command(label=f"Копировать IP ({hop.addr})", command=lambda: self._copy(hop.addr))
        m.add_command(label="Копировать строку", command=lambda: self._copy(format_hop_line(hop).strip()))
        m.add_command(label="Показать на карте крупно", command=self._zoom_to_selected)
        if hop.addr:
            m.add_separator()
            m.add_command(label="Трассировать до этого узла", command=lambda: self.start_trace(hop.addr))
            m.add_command(label="Сведения об IP в браузере (bgp.he.net)",
                          command=lambda: webbrowser.open(f"https://bgp.he.net/ip/{hop.addr}"))
        try:
            m.tk_popup(event.x_root, event.y_root)
        finally:
            m.grab_release()

    def _copy(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status(f"Скопировано: {text}")

    # ----------------------------------------------------------- texts
    @staticmethod
    def _set_text(widget: tk.Text, text: str, tagged=None) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        if tagged:
            for chunk, tag in tagged:
                widget.insert("end", chunk, tag or ())
        else:
            widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _render_output(self) -> None:
        t = self.trace
        if t is None:
            self._set_text(self.out, "")
            return
        lines = []
        name = t.target or t.target_ip or "?"
        ip = f" [{t.target_ip}]" if t.target_ip and t.target_ip != name else ""
        lines.append(f"Трассировка маршрута к {name}{ip}")
        lines.append(f"с максимальным числом прыжков {t.max_hops}:")
        if t.source and t.source != "…":
            lines.append(f"(источник: {t.source})")
        for msg in self.log_lines:
            lines.append(f"» {msg}")
        lines.append("")
        probes = max((len(h.rtts) for h in t.hops), default=3) or 3
        for h in t.hops:
            lines.append(format_hop_line(h, probes))
        lines.append("")
        if self.running:
            lines.append("…")
        elif self.done_reason:
            lines.append(self.done_reason)
        self._set_text(self.out, "\n".join(lines))
        self.out.see("end")

    def _route_km(self) -> float:
        if not self.view:
            return 0.0
        return sum(haversine_km(s.points[0], s.points[-1]) for s in self.view.segments)

    def _countries(self) -> str:
        seq = []
        for h in (self.trace.hops if self.trace else []):
            g = h.geo
            if g and g.has_coords and not g.private and g.country:
                if not seq or seq[-1] != g.country:
                    seq.append(g.country)
        return " → ".join(seq)

    def _summary_line(self, prefix: str = "") -> str:
        t = self.trace
        if not t:
            return prefix
        n = len(t.hops)
        resp = sum(1 for h in t.hops if h.responded)
        located = self.view.located if self.view else 0
        km = self._route_km()
        parts = [prefix] if prefix else []
        parts.append(f"Узлов: {n}, ответили: {resp}, на карте: {located}")
        if km > 0:
            parts.append(f"путь ≈ {km:,.0f} км".replace(",", " "))
        return " · ".join(parts)

    def _show_summary(self) -> None:
        t = self.trace
        if t is None:
            self._set_text(self.info, "", [
                ("Как пользоваться\n", "h"),
                ("1. Введите IP-адрес или домен и нажмите «Трассировать» (Enter / F5).\n", None),
                ("2. Или нажмите «Построить по готовой трассировке…» и вставьте вывод tracert / traceroute.\n", None),
                ("3. Щёлкните узел в таблице или на карте, чтобы увидеть подробности.\n", None),
                ("Правый щелчок по строке — копирование IP, трассировка до узла и другое.", "k"),
            ])
            return
        name = t.target or t.target_ip or "?"
        chunks = [(f"Маршрут к {name}" + (f" [{t.target_ip}]" if t.target_ip and t.target_ip != name else "") + "\n", "h")]
        if t.source:
            chunks += [("Источник: ", "k"), (f"{t.source}\n", None)]
        chunks += [("Итог: ", "k"), (self._summary_line() + "\n", None)]
        if t.completed:
            chunks += [("Назначение: ", "k"), ("достигнуто\n" if t.reached else "не достигнуто\n", None)]
        countries = self._countries()
        if countries:
            chunks += [("Страны: ", "k"), (countries + "\n", None)]
        if t.origin and t.origin.has_coords:
            chunks += [("Старт: ", "k"), ((t.origin.place or "определён по внешнему IP") + "\n", None)]
        if self.view and self.view.suspicious:
            chunks.append((f"⚠ Сомнительная геолокация у узлов: {', '.join(map(str, sorted(self.view.suspicious)))} "
                           "— задержка меньше, чем позволяет скорость света.\n", "warn"))
        chunks.append(("Выберите узел в таблице или на карте, чтобы увидеть подробности.", "k"))
        self._set_text(self.info, "", chunks)

    def _show_info(self, ttl: int) -> None:
        hop = self.trace.hop_by_ttl(ttl) if self.trace else None
        if hop is None:
            return
        g = hop.geo
        chunks = [(f"Узел {hop.ttl}" + (f" · {hop.addr}" if hop.addr else " · нет ответа") +
                   ("  (узел назначения)" if hop.reached else "") + "\n", "h")]
        if hop.host:
            chunks += [("Имя: ", "k"), (hop.host + "\n", None)]
        if hop.rtts:
            v = hop.valid_rtts
            stat = f" (мин {min(v):.1f}, сред {sum(v) / len(v):.1f})" if v else ""
            chunks += [("Задержки: ", "k"), (" / ".join(fmt_rtt(r) for r in hop.rtts) + f" мс{stat}, "
                                               f"потери {hop.loss * 100:.0f}%\n", None)]
        if hop.extra_addrs:
            chunks += [("Также отвечали: ", "k"), (", ".join(hop.extra_addrs) + "\n", None)]
        if hop.note:
            chunks += [("Сообщение: ", "k"), (hop.note + "\n", "warn")]
        if g is not None:
            if g.private:
                chunks += [("Место: ", "k"), ("частная / служебная сеть — геолокация невозможна; на карте "
                                               "узел показан рядом с предыдущим узлом маршрута\n", None)]
            elif g.has_coords:
                place = ", ".join(p for p in (g.city, g.region, g.country) if p)
                chunks += [("Место: ", "k"), (f"{place} ({g.lat:.3f}, {g.lon:.3f})\n", None)]
                if self.trace.origin and self.trace.origin.has_coords:
                    km = haversine_km((self.trace.origin.lat, self.trace.origin.lon), (g.lat, g.lon))
                    chunks += [("От старта: ", "k"), (f"≈ {km:,.0f} км".replace(",", " ") +
                                                      f", свету в оптоволокне нужно ≥ {2 * km / 200:.1f} мс туда-обратно\n",
                                                      None)]
            else:
                chunks += [("Место: ", "k"), ("нет данных\n", None)]
            if g.isp or g.org or g.asn:
                prov = " · ".join(p for p in (g.isp, g.org if g.org != g.isp else "", g.asn) if p)
                chunks += [("Провайдер: ", "k"), (prov + "\n", None)]
            if g.source and not g.private:
                chunks += [("Геоданные: ", "k"), (g.source + "\n", None)]
        elif hop.responded:
            chunks += [("Место: ", "k"), ("определяется…\n", None)]
        if self.view:
            if hop.ttl in self.view.suspicious:
                chunks.append(("⚠ " + self.view.suspicious[hop.ttl] + "\n", "warn"))
            pt = self.view.point_for_ttl(hop.ttl)
            if pt is not None and len(pt.hops) > 1:
                chunks.append((f"В этой точке карты узлы: {pt.label}\n", "k"))
        self._set_text(self.info, "", chunks)

    # ------------------------------------------------------------- map
    def _map_touched(self, _event=None) -> None:
        self.user_moved_map = True

    def _apply_tiles(self, initial: bool = False) -> None:
        name = self.tile_var.get()
        if name not in TILE_SERVERS:
            name = DEFAULT_TILES
            self.tile_var.set(name)
        tiles = TILE_SERVERS[name]
        self.s.tile_server = name
        self.map.set_tile_server(tiles.url, max_zoom=tiles.max_zoom)
        self.attr_label.configure(text=tiles.attribution)
        if not initial:
            self._schedule_redraw()

    def _schedule_redraw(self) -> None:
        if self._redraw_job is None:
            self._redraw_job = self.root.after(80, self._redraw_map)

    def _redraw_map(self) -> None:
        self._redraw_job = None
        if self._in_redraw:
            self._schedule_redraw()
            return
        self._in_redraw = True
        try:
            old_susp = dict(self.view.suspicious) if self.view else {}
            self.map.delete_all_path()
            self.map.delete_all_marker()
            if self.trace is None:
                self.view = None
                return
            view = build_route(self.trace, self.trace.origin)
            self.view = view
            w = max(3, int(round(3 * self.scale)))
            for seg in view.segments:
                for part in split_antimeridian(seg.points):
                    self.map.set_path(list(part), color="#FFFFFF", width=w + 3)
                    self.map.set_path(list(part), color=seg.color, width=w)
            sel = view.point_for_ttl(self.selected_ttl) if self.selected_ttl is not None else None
            dark = TILE_SERVERS.get(self.tile_var.get(), TILE_SERVERS[DEFAULT_TILES]).dark
            captions = []
            for p in sorted(view.points, key=lambda q: (q is sel, q.is_dest)):
                selected = p is sel
                icon = self.icons.marker(p.label, p.color, selected=selected, dest=p.is_dest)
                text = None
                if selected:
                    text = p.place
                elif p.is_origin:
                    text = "Вы"
                elif p.is_dest:
                    text = self.trace.target or None
                self.map.set_marker(p.lat, p.lon, icon=icon,
                                    command=lambda _m, pt=p: self._on_marker_click(pt))
                if text:
                    captions.append((p, text, icon.height()))
            # Подписи — отдельные картинки поверх точек: текст с контрастной обводкой,
            # на спутнике светлый, на обычных картах тёмный. Щелчки по ним уходят карте.
            for p, text, icon_h in captions:
                cap = self.icons.caption(text, light=dark, gap=icon_h // 2 + 2)
                self.map.set_marker(p.lat, p.lon, icon=cap, icon_anchor="s")
            if view.suspicious != old_susp:
                self._refresh_rows()
                if self.selected_ttl is None and self.trace.completed:
                    self._show_summary()
            if view.located != self._last_located:
                self._last_located = view.located
                if not self.running and self.trace.completed:
                    self.status(self._summary_line(prefix=self.done_reason))
        finally:
            self._in_redraw = False

    def _on_marker_click(self, point) -> None:
        if not point.hops:
            self._clear_selection()
            return
        ttls = point.ttls
        if self.selected_ttl in ttls:
            # повторный щелчок по группе — перейти к следующему узлу этой точки
            ttl = ttls[(ttls.index(self.selected_ttl) + 1) % len(ttls)]
        else:
            ttl = ttls[0]
        iid = f"ttl{ttl}"
        if self.tree.exists(iid):
            self.nb.select(0)
            self.tree.selection_set(iid)
            self.tree.see(iid)

    def _request_fit(self) -> None:
        if self.user_moved_map:
            return
        if self._fit_job is not None:
            self.root.after_cancel(self._fit_job)
        self._fit_job = self.root.after(250, self._do_auto_fit)

    def _do_auto_fit(self) -> None:
        self._fit_job = None
        if not self.user_moved_map:
            self.fit_route()

    def fit_route(self) -> None:
        if self._redraw_job is not None:          # сначала дорисовать
            self.root.after_cancel(self._redraw_job)
            self._redraw_map()
        if not self.view or not self.view.points:
            return
        pts = [p.coords for p in self.view.points]
        for s in self.view.segments:
            pts += s.points[::3]
        lats = [p[0] for p in pts]
        lons = [p[1] for p in pts]
        self.map.update_idletasks()
        w = max(200, self.map.winfo_width())
        h = max(200, self.map.winfo_height())
        lat_max, lat_min = min(max(lats), 80.0), max(min(lats), -80.0)
        lon_min, lon_max = min(lons), max(lons)
        if lon_max - lon_min > 300 and any(len(split_antimeridian(s.points)) > 1 for s in self.view.segments):
            self.map.set_zoom(max(self.map.min_zoom, 2))
            self.map.set_position((lat_max + lat_min) / 2, 160.0)
            return
        if lat_max - lat_min < 0.2 and lon_max - lon_min < 0.2:
            self.map.set_zoom(9)
            self.map.set_position(pts[0][0], pts[0][1])
            return
        zoom = 2
        for z in range(12, -1, -1):
            x1, y1 = _d2o(lat_max, lon_min, z)
            x2, y2 = _d2o(lat_min, lon_max, z)
            if (x2 - x1) * 256 <= w * 0.78 and (y2 - y1) * 256 <= h * 0.72:
                zoom = z
                break
        zoom = max(zoom, int(self.map.min_zoom))
        x1, y1 = _d2o(lat_max, lon_min, zoom)
        x2, y2 = _d2o(lat_min, lon_max, zoom)
        clat, clon = _o2d((x1 + x2) / 2, (y1 + y2) / 2, zoom)
        self.map.set_zoom(zoom)
        self.map.set_position(clat, clon)

    # -------------------------------------------------------- save etc.
    def _default_name(self, ext: str) -> str:
        t = self.trace
        base = re.sub(r"[^\w.\-]+", "_", (t.target or t.target_ip or "trace") if t else "trace")
        return f"trace_{base}_{_dt.datetime.now():%Y%m%d_%H%M}{ext}"

    def save_as(self) -> None:
        if not self.trace or not self.trace.hops:
            messagebox.showinfo(APP_NAME, "Пока нечего сохранять — выполните или загрузите трассировку.",
                                parent=self.root)
            return
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Сохранить трассировку", defaultextension=".json",
            initialfile=self._default_name(".json"),
            filetypes=[("JSON — можно открыть снова", "*.json"), ("Текст в стиле tracert", "*.txt"),
                       ("CSV для Excel", "*.csv"), ("HTML-карта", "*.html")])
        if not path:
            return
        ext = Path(path).suffix.lower()
        try:
            if ext == ".txt":
                Path(path).write_text(to_text(self.trace), "utf-8")
            elif ext == ".csv":
                Path(path).write_text(to_csv(self.trace), "utf-8-sig")
            elif ext in (".html", ".htm"):
                Path(path).write_text(to_html(self.trace, self.trace.origin), "utf-8")
            else:
                Path(path).write_text(to_json(self.trace), "utf-8")
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Не удалось сохранить файл:\n{e}", parent=self.root)
            return
        self.status(f"Сохранено: {path}")

    def export_html(self) -> None:
        if not self.trace or not self.trace.hops:
            messagebox.showinfo(APP_NAME, "Пока нечего экспортировать.", parent=self.root)
            return
        path = filedialog.asksaveasfilename(parent=self.root, title="Экспорт в HTML-карту", defaultextension=".html",
                                            initialfile=self._default_name(".html"),
                                            filetypes=[("HTML-страница", "*.html")])
        if not path:
            return
        try:
            Path(path).write_text(to_html(self.trace, self.trace.origin), "utf-8")
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Не удалось сохранить файл:\n{e}", parent=self.root)
            return
        self.status(f"HTML-карта сохранена: {path}")
        webbrowser.open(Path(path).resolve().as_uri())

    # ------------------------------------------------------- geo settings
    def _make_resolver(self) -> GeoResolver:
        try:
            return GeoResolver(self.s.geo_provider, self.s.geo_lang, self.s.mmdb_path)
        except GeoError as e:
            msg = f"{e}\nИспользуется ip-api.com."
            self.root.after(500, lambda: messagebox.showwarning(APP_NAME, msg, parent=self.root))
            self.s.geo_provider = "ip-api"
            return GeoResolver("ip-api", self.s.geo_lang)

    def _change_provider(self) -> None:
        self.s.geo_provider = self.provider_var.get()
        self.s.geo_lang = self.lang_var.get()
        self.geo.resolver = self._make_resolver()
        self.provider_var.set(self.s.geo_provider)
        self.geo_by_ip.clear()
        self.geo_pending.clear()
        if self.trace:
            for hop in self.trace.hops:
                hop.geo = None
            self._refresh_rows()
            self._request_info(self.trace.hops)
        self.status(f"Источник геоданных: {PROVIDERS.get(self.s.geo_provider)}")

    def _choose_mmdb(self) -> None:
        path = filedialog.askopenfilename(parent=self.root, title="База геолокации",
                                          filetypes=[("MaxMind DB", "*.mmdb"), ("Все файлы", "*.*")])
        if path:
            self.s.mmdb_path = path
            self.provider_var.set("mmdb")
            self._change_provider()

    def _clear_geo_cache(self) -> None:
        self.geo.resolver.cache.clear()
        self.status("Кэш геолокации очищен.")

    # ------------------------------------------------------------- help
    def _help(self) -> None:
        messagebox.showinfo("Как это работает", (
            "Программа повторяет принцип tracert: отправляет ICMP Echo-запросы с TTL = 1, 2, 3…\n"
            "Каждый маршрутизатор уменьшает TTL на 1 и, когда TTL доходит до нуля, отвечает "
            "сообщением «Time Exceeded» — так становится известен адрес очередного узла и задержка до него. "
            "Узел назначения отвечает обычным Echo Reply.\n\n"
            "Для каждого адреса определяется примерное местоположение по базам геолокации IP "
            "(ip-api.com, ipwho.is или локальный файл .mmdb). Частные адреса (192.168.x.x, 10.x.x.x, 100.64.x.x) "
            "геолоцировать нельзя — они показываются в точке старта.\n\n"
            "Важно: геолокация маршрутизаторов приблизительна. Адреса магистральных узлов иногда "
            "«привязаны» к офису провайдера, а не к реальному месту. Если задержка до узла меньше, чем "
            "нужно свету в оптоволокне, чтобы дойти до указанной точки и обратно, узел помечается знаком ⚠.\n\n"
            "Строка «* * *» означает, что узел не ответил (часто это фильтрация ICMP, а не обрыв связи)."),
            parent=self.root)

    def _about(self) -> None:
        messagebox.showinfo("О программе", (
            f"{APP_NAME} {__version__}\n\n"
            "Трассировка маршрута с визуализацией узлов на карте мира.\n"
            "Python · tkinter · tkintermapview\n"
            f"Настройки и кэш: {Path.home() / '.tracertmap'}"), parent=self.root)

    def on_close(self) -> None:
        self.cancel.set()
        try:
            self._read_options()
            self.s.geometry = self.root.geometry()
            self.s.sash = int(self.paned.sashpos(0))
        except tk.TclError:
            pass
        self.s.save()
        try:
            self.map.destroy()
        except Exception:
            pass
        self.root.destroy()


def run_app(target: Optional[str] = None, file: Optional[str] = None) -> None:
    import sys
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    TracertMapApp(root, target=target, file=file)
    root.mainloop()

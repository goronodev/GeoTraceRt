"""Сохранение результатов: JSON, текст в стиле tracert, CSV, HTML-карта (Leaflet)."""

from __future__ import annotations

import csv
import html
import io
import json
from typing import Optional

from .geomath import unwrap_longitudes
from .models import GeoInfo, Hop, TraceResult
from .route import build_route, fmt_rtt


def format_hop_line(hop: Hop, probes: int = 3) -> str:
    """Строка в стиле Windows tracert."""
    rtts = list(hop.rtts) + [None] * max(0, probes - len(hop.rtts)) if hop.rtts or not hop.responded else []
    cells = "".join(f"{fmt_rtt(r):>6} мс" if r is not None else f"{'*':>6}   " for r in rtts)
    if hop.responded:
        who = f"{hop.host} [{hop.addr}]" if hop.host else hop.addr
        if hop.extra_addrs:
            who += "  (также: " + ", ".join(hop.extra_addrs) + ")"
        tail = f"  {who}"
        if hop.note:
            tail += f"  сообщает: {hop.note}" if not hop.note.startswith("mtr") else f"  {hop.note}"
    elif hop.host:
        tail = f"  {hop.host}"
    else:
        tail = "  Превышен интервал ожидания для запроса."
    return f"{hop.ttl:>3}{cells}{tail}"


def to_text(trace: TraceResult) -> str:
    out = io.StringIO()
    name = trace.target or trace.target_ip or "?"
    if trace.target_ip and trace.target_ip != name:
        out.write(f"Трассировка маршрута к {name} [{trace.target_ip}]\n")
    else:
        out.write(f"Трассировка маршрута к {name}\n")
    out.write(f"с максимальным числом прыжков {trace.max_hops}:\n\n")
    probes = max((len(h.rtts) for h in trace.hops), default=3) or 3
    for h in trace.hops:
        out.write(format_hop_line(h, probes) + "\n")
    out.write("\nТрассировка завершена.\n" if trace.reached else "\n")
    return out.getvalue()


def to_json(trace: TraceResult) -> str:
    return json.dumps(trace.to_dict(), ensure_ascii=False, indent=2)


def to_csv(trace: TraceResult) -> str:
    out = io.StringIO()
    w = csv.writer(out, delimiter=";", lineterminator="\r\n")
    n = max((len(h.rtts) for h in trace.hops), default=3) or 3
    w.writerow(["№", "IP-адрес", "Имя узла"] + [f"RTT{i + 1}, мс" for i in range(n)] +
               ["Среднее, мс", "Потери, %", "Страна", "Регион", "Город", "Широта", "Долгота",
                "Провайдер", "AS", "Примечание"])
    for h in trace.hops:
        g = h.geo or GeoInfo()
        rtts = [("" if r is None else f"{r:.1f}".replace(".", ",")) for r in h.rtts] + [""] * (n - len(h.rtts))
        avg = h.avg_rtt
        w.writerow([h.ttl, h.addr or "*", h.host or ""] + rtts +
                   ["" if avg is None else f"{avg:.1f}".replace(".", ","), f"{h.loss * 100:.0f}",
                    g.country, g.region, g.city if not g.private else "частная сеть",
                    "" if g.lat is None else g.lat, "" if g.lon is None else g.lon,
                    g.isp or g.org, g.asn, h.note])
    return out.getvalue()


def to_html(trace: TraceResult, origin: Optional[GeoInfo] = None) -> str:
    """Самодостаточная HTML-страница с интерактивной картой Leaflet."""
    view = build_route(trace, origin or trace.origin)
    markers = []
    for p in view.points:
        rows = []
        for h in p.hops:
            g = h.geo or GeoInfo()
            rows.append(f"<b>{h.ttl}.</b> {html.escape(h.addr or '')}"
                        + (f" <i>{html.escape(h.host)}</i>" if h.host else "")
                        + f"<br><small>{html.escape(' / '.join(fmt_rtt(r) for r in h.rtts))} мс"
                        + (f" · {html.escape(g.place)}" if g.place else "")
                        + (f" · {html.escape(g.provider)}" if g.provider else "") + "</small>")
        title = p.place
        markers.append({"lat": p.lat, "lon": p.lon, "label": p.label, "color": p.color,
                        "origin": p.is_origin, "dest": p.is_dest,
                        "popup": f"<b>{html.escape(title)}</b><br>" + "<br>".join(rows)})
    segs = [{"pts": unwrap_longitudes(s.points), "color": s.color} for s in view.segments]
    # непрерывность долгот между соседними отрезками (переход через 180°)
    shift = 0.0
    for i in range(1, len(segs)):
        prev_end = segs[i - 1]["pts"][-1][1]
        first = segs[i]["pts"][0][1] + shift
        while first - prev_end > 180:
            shift -= 360
            first -= 360
        while first - prev_end < -180:
            shift += 360
            first += 360
        segs[i]["pts"] = [(la, lo + shift) for la, lo in segs[i]["pts"]]
    table_rows = []
    for h in trace.hops:
        g = h.geo or GeoInfo()
        warn = " ⚠" if h.ttl in view.suspicious else ""
        table_rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                h.ttl, html.escape(h.addr or "*"), html.escape(h.host or ""),
                html.escape(" / ".join(fmt_rtt(r) for r in h.rtts)),
                html.escape(g.place) + warn, html.escape(g.provider)))
    data = json.dumps({"markers": markers, "segments": segs}, ensure_ascii=False)
    title = html.escape(f"Трассировка: {trace.target or trace.target_ip}")
    return (_HTML.replace("__TITLE__", title)
            .replace("__SUB__", html.escape(f"{trace.target_ip or ''} · {trace.started} · {trace.source}"))
            .replace("__ROWS__", "\n".join(table_rows))
            .replace("__DATA__", data))


_HTML = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
 :root{--bg:#f6f7f9;--fg:#1d2330;--muted:#667085;--card:#fff;--line:#e4e7ec}
 @media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e6e8eb;--muted:#9aa3af;--card:#1c2027;--line:#2c323c}}
 body{margin:0;font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--fg)}
 header{padding:14px 18px} h1{margin:0;font-size:18px} .sub{color:var(--muted);font-size:13px}
 #map{height:62vh;margin:0 18px;border-radius:10px;border:1px solid var(--line)}
 table{border-collapse:collapse;margin:16px 18px 28px;width:calc(100% - 36px);background:var(--card);
   border-radius:10px;overflow:hidden;border:1px solid var(--line)}
 th,td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left;font-variant-numeric:tabular-nums}
 th{font-weight:600;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.03em}
 .hop{border-radius:12px;color:#fff;font:700 12px system-ui,sans-serif;text-align:center;
   border:2px solid #fff;box-shadow:0 1px 4px rgba(0,0,0,.45);white-space:nowrap;padding:0 6px;line-height:20px}
 .dest{outline:3px solid rgba(214,69,69,.45)}
 .legend{background:var(--card);color:var(--fg);padding:6px 10px;border-radius:8px;font-size:12px;line-height:1.7}
 .legend i{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}
</style></head><body>
<header><h1>__TITLE__</h1><div class="sub">__SUB__</div></header>
<div id="map"></div>
<table><thead><tr><th>№</th><th>IP-адрес</th><th>Имя узла</th><th>Задержки, мс</th><th>Место</th><th>Провайдер</th></tr></thead>
<tbody>
__ROWS__
</tbody></table>
<script>
const D = __DATA__;
const map = L.map('map', {worldCopyJump: true});
L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom: 19,
  attribution: '&copy; OpenStreetMap contributors'}).addTo(map);
const all = [];
D.segments.forEach(s => { L.polyline(s.pts, {color: s.color, weight: 3, opacity: .85}).addTo(map); s.pts.forEach(p => all.push(p)); });
D.markers.forEach(m => {
  const w = Math.max(24, 9 * m.label.length + 12);
  const icon = L.divIcon({className: '', iconSize: [w, 24], iconAnchor: [w / 2, 12],
    html: `<div class="hop${m.dest ? ' dest' : ''}" style="background:${m.color}">${m.label}</div>`});
  L.marker([m.lat, m.lon], {icon}).addTo(map).bindPopup(m.popup);
  all.push([m.lat, m.lon]);
});
if (all.length) map.fitBounds(all, {padding: [40, 40], maxZoom: 7}); else map.setView([50, 40], 3);
const lg = L.control({position: 'bottomleft'});
lg.onAdd = () => { const d = L.DomUtil.create('div', 'legend');
  d.innerHTML = '<i style="background:#2E9D57"></i>&lt; 50 мс<br><i style="background:#E3A21A"></i>50–150 мс<br>' +
    '<i style="background:#D64545"></i>&gt; 150 мс<br><i style="background:#2B2D42"></i>старт'; return d; };
lg.addTo(map);
</script></body></html>
"""

"""Рисование значков маркеров (номера узлов на цветной «таблетке») через Pillow."""

from __future__ import annotations

import sys
from functools import lru_cache
from typing import Dict, Tuple

from PIL import Image, ImageDraw, ImageFont, ImageTk

_RESAMPLE = getattr(getattr(Image, "Resampling", Image), "LANCZOS")
_SS = 4  # суперсэмплинг для сглаживания

_FONT_CANDIDATES = [
    "segoeuib.ttf", "arialbd.ttf",                                   # Windows
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",             # macOS
    "/Library/Fonts/Arial Bold.ttf",
    "DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",          # Linux
    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
    "LiberationSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
]


@lru_cache(maxsize=16)
def _font(px: int):
    for name in _FONT_CANDIDATES:
        try:
            return ImageFont.truetype(name, px)
        except (OSError, IOError):
            continue
    try:
        return ImageFont.load_default(size=px)   # Pillow ≥ 10.1
    except TypeError:
        return ImageFont.load_default()


def _hex(color: str) -> Tuple[int, int, int]:
    color = color.lstrip("#")
    return tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]


class IconFactory:
    """Создаёт и кэширует PhotoImage (Tk требует хранить ссылки на картинки)."""

    def __init__(self, scale: float = 1.0) -> None:
        self.scale = max(1.0, scale)
        self._cache: Dict[tuple, ImageTk.PhotoImage] = {}

    def marker(self, label: str, color: str, selected: bool = False, dest: bool = False) -> ImageTk.PhotoImage:
        key = ("m", label, color, selected, dest)
        if key in self._cache:
            return self._cache[key]
        s = self.scale * _SS
        h = int((26 if selected else 21) * s)
        font = _font(int((13 if selected else 11) * s))
        bbox = font.getbbox(label)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        w = max(h, int(tw + 12 * s))
        ring = int((4 if dest else 0) * s)
        pad = int(3 * s) + ring
        img = Image.new("RGBA", (w + 2 * pad, h + 2 * pad), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        # тень
        d.rounded_rectangle((pad, pad + int(1.5 * s), pad + w, pad + h + int(1.5 * s)),
                            radius=h // 2, fill=(0, 0, 0, 70))
        if dest:
            d.rounded_rectangle((pad - ring, pad - ring, pad + w + ring, pad + h + ring),
                                radius=h // 2 + ring, fill=(*_hex("#D64545"), 110))
        if selected:
            d.rounded_rectangle((pad - int(3 * s), pad - int(3 * s), pad + w + int(3 * s), pad + h + int(3 * s)),
                                radius=h // 2 + int(3 * s), fill=(*_hex("#1A73E8"), 200))
        d.rounded_rectangle((pad, pad, pad + w, pad + h), radius=h // 2, fill=(*_hex(color), 255),
                            outline=(255, 255, 255, 255), width=max(1, int(2 * s)))
        cx, cy = pad + w / 2, pad + h / 2
        d.text((cx - tw / 2 - bbox[0], cy - th / 2 - bbox[1]), label, font=font, fill=(255, 255, 255, 255))
        final = img.resize((max(1, img.width // _SS), max(1, img.height // _SS)), _RESAMPLE)
        photo = ImageTk.PhotoImage(final)
        self._cache[key] = photo
        return photo

    def caption(self, text: str, light: bool = False, gap: int = 14) -> ImageTk.PhotoImage:
        """Подпись над точкой: текст с контрастной обводкой («гало»), читаемая на любой подложке.

        light=True — белый текст с тёмной обводкой (для спутника), иначе тёмный с белой.
        gap — прозрачный отступ снизу в пикселях, чтобы подпись встала над маркером
        (картинка ставится на карту с привязкой нижним краем к точке).
        """
        key = ("c", text, light, gap)
        if key in self._cache:
            return self._cache[key]
        s = self.scale * _SS
        font = _font(int(12 * s))
        stroke = max(1, int(2.6 * s))
        fill = (255, 255, 255, 255) if light else (*_hex("#1D2330"), 255)
        halo = (0, 0, 0, 215) if light else (255, 255, 255, 235)
        try:
            bbox = font.getbbox(text, stroke_width=stroke)
        except TypeError:                      # очень старый Pillow / растровый шрифт
            stroke = 0
            bbox = font.getbbox(text)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        pad = int(2 * s)
        bottom = int(gap * _SS)
        img = Image.new("RGBA", (tw + 2 * pad, th + 2 * pad + bottom), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.text((pad - bbox[0], pad - bbox[1]), text, font=font, fill=fill,
               stroke_width=stroke, stroke_fill=halo)
        final = img.resize((max(1, img.width // _SS), max(1, img.height // _SS)), _RESAMPLE)
        photo = ImageTk.PhotoImage(final)
        self._cache[key] = photo
        return photo

    def dot(self, color: str, size: int = 12) -> ImageTk.PhotoImage:
        key = ("d", color, size)
        if key in self._cache:
            return self._cache[key]
        px = int(size * self.scale)
        big = Image.new("RGBA", (px * _SS, px * _SS), (0, 0, 0, 0))
        d = ImageDraw.Draw(big)
        m = int(1.5 * _SS * self.scale)
        d.ellipse((m, m, px * _SS - m, px * _SS - m), fill=(*_hex(color), 255),
                  outline=(255, 255, 255, 255), width=max(1, int(_SS * self.scale)))
        photo = ImageTk.PhotoImage(big.resize((px, px), _RESAMPLE))
        self._cache[key] = photo
        return photo


def mono_font_family() -> str:
    if sys.platform == "win32":
        return "Consolas"
    if sys.platform == "darwin":
        return "Menlo"
    return "DejaVu Sans Mono"

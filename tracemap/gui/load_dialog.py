"""Диалог «Построить маршрут по готовой трассировке»."""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from ..models import TraceResult
from ..parser import decode_bytes, parse_text
from .icons import mono_font_family

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "samples")

EXAMPLE = """Трассировка маршрута к github.com [140.82.121.4]
с максимальным числом прыжков 30:

  1    <1 мс    <1 мс    <1 мс  192.168.1.1
  2     3 ms     2 ms     2 ms  100.64.0.1
  3     4 мс     3 мс     4 мс  87.226.181.89
  4    11 мс    10 мс    11 мс  87.226.183.89
  5     *        *        *     Превышен интервал ожидания для запроса.
  6    12 мс    12 мс    11 мс  195.208.208.250
  7    46 мс    45 мс    46 мс  80.81.192.123
  8    47 мс    46 мс    47 мс  lb-140-82-121-4-fra.github.com [140.82.121.4]

Трассировка завершена.
"""

FILETYPES = [("Трассировки", "*.txt *.log *.json *.out"), ("Все файлы", "*.*")]


def read_trace_file(path: str) -> str:
    with open(path, "rb") as f:
        return decode_bytes(f.read())


class LoadTraceDialog(tk.Toplevel):
    def __init__(self, master: tk.Misc, on_done: Callable[[TraceResult, bool, str], None],
                 initial_text: str = "") -> None:
        super().__init__(master)
        self.title("Построить маршрут по готовой трассировке")
        self.transient(master.winfo_toplevel())
        self.on_done = on_done
        self.source_name = "вставленный текст"
        self.minsize(640, 420)

        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, wraplength=760, justify="left", text=(
            "Вставьте вывод tracert, traceroute, tracepath, mtr --report или просто список IP-адресов "
            "(по одному в строке) — либо откройте файл. Поддерживаются русская и английская Windows, "
            "кодировки UTF-8, UTF-16 (PowerShell) и cp866 (cmd.exe), а также JSON, сохранённый этой программой."
        )).pack(fill="x", pady=(0, 8))

        box = ttk.Frame(outer)
        box.pack(fill="both", expand=True)
        self.text = tk.Text(box, wrap="none", width=96, height=20, undo=True,
                            font=(mono_font_family(), 10), relief="solid", borderwidth=1)
        ys = ttk.Scrollbar(box, orient="vertical", command=self.text.yview)
        xs = ttk.Scrollbar(box, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        box.rowconfigure(0, weight=1)
        box.columnconfigure(0, weight=1)
        if initial_text:
            self.text.insert("1.0", initial_text)

        self.from_here = tk.BooleanVar(value=True)
        ttk.Checkbutton(outer, variable=self.from_here, text=(
            "Трассировка выполнена с этого компьютера (начало маршрута — моё местоположение)")
        ).pack(anchor="w", pady=(8, 0))

        btns = ttk.Frame(outer)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Открыть файл…", command=self.open_file).pack(side="left")
        ttk.Button(btns, text="Вставить из буфера", command=self.paste).pack(side="left", padx=6)
        ttk.Button(btns, text="Пример", command=self.example).pack(side="left")
        ttk.Button(btns, text="Отмена", command=self.destroy).pack(side="right")
        build = ttk.Button(btns, text="Построить маршрут", command=self.build, style="Accent.TButton")
        build.pack(side="right", padx=6)

        self.bind("<Control-Return>", lambda e: self.build())
        self.bind("<Escape>", lambda e: self.destroy())
        self.text.focus_set()
        self.update_idletasks()
        self._center(master)
        self.grab_set()

    def _center(self, master: tk.Misc) -> None:
        top = master.winfo_toplevel()
        x = top.winfo_rootx() + (top.winfo_width() - self.winfo_reqwidth()) // 2
        y = top.winfo_rooty() + (top.winfo_height() - self.winfo_reqheight()) // 3
        self.geometry(f"+{max(0, x)}+{max(0, y)}")

    def _set_text(self, text: str) -> None:
        self.text.delete("1.0", "end")
        self.text.insert("1.0", text)

    def open_file(self) -> None:
        path = filedialog.askopenfilename(parent=self, title="Открыть трассировку", filetypes=FILETYPES,
                                          initialdir=SAMPLE_DIR if os.path.isdir(SAMPLE_DIR) else None)
        if not path:
            return
        try:
            self._set_text(read_trace_file(path))
            self.source_name = os.path.basename(path)
        except OSError as e:
            messagebox.showerror("Ошибка", f"Не удалось прочитать файл:\n{e}", parent=self)

    def paste(self) -> None:
        try:
            self._set_text(self.clipboard_get())
            self.source_name = "буфер обмена"
        except tk.TclError:
            messagebox.showinfo("Буфер обмена", "В буфере обмена нет текста.", parent=self)

    def example(self) -> None:
        self._set_text(EXAMPLE)
        self.source_name = "пример"

    def build(self) -> None:
        text = self.text.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("Нет данных", "Вставьте текст трассировки или откройте файл.", parent=self)
            return
        try:
            trace = parse_text(text)
        except ValueError as e:
            messagebox.showerror("Не удалось разобрать", str(e), parent=self)
            return
        except Exception as e:  # повреждённый JSON и т.п.
            messagebox.showerror("Не удалось разобрать", f"{type(e).__name__}: {e}", parent=self)
            return
        self.grab_release()
        self.destroy()
        self.on_done(trace, self.from_here.get(), self.source_name)

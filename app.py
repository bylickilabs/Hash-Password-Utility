import hashlib
import os
import sys
import time
import random
import string
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_TITLE_EN = "Mini Hash & Password Utility"
APP_TITLE_DE = "Mini Hash & Password Werkzeug"
APP_VERSION = "1.0.0"
GITHUB_URL = "https://github.com/bylickilabs"

I18N = {
    "en": {
        "tab_file": "File Hash",
        "tab_text": "Text Hash",
        "tab_pass": "Password Generator",
        "choose_file": "Choose File",
        "file_path": "File:",
        "hash_algs": "Algorithms",
        "compute": "Compute Hashes",
        "expected": "Expected Hash (any alg)",
        "verify": "Verify",
        "match": "Match",
        "mismatch": "Mismatch",
        "copy": "Copy",
        "save": "Save Report",
        "input_text": "Input Text",
        "clear": "Clear",
        "password": "Password",
        "length": "Length",
        "uppercase": "Uppercase",
        "lowercase": "Lowercase",
        "digits": "Digits",
        "symbols": "Symbols",
        "generate": "Generate",
        "strength": "Strength",
        "lang": "Language",
        "dark": "Dark Mode",
        "info": "Info",
        "github": "GitHub",
        "about": "A minimal, local utility by BYLICKILABS for hashing and secure password creation.",
        "no_file": "Please choose a file first.",
        "no_charset": "Select at least one character set.",
        "saved": "Report saved.",
        "save_failed": "Save failed.",
    },
    "de": {
        "tab_file": "Datei-Hash",
        "tab_text": "Text-Hash",
        "tab_pass": "Passwortgenerator",
        "choose_file": "Datei wählen",
        "file_path": "Datei:",
        "hash_algs": "Algorithmen",
        "compute": "Hashes berechnen",
        "expected": "Erwarteter Hash (beliebig)",
        "verify": "Prüfen",
        "match": "Stimmt überein",
        "mismatch": "Stimmt nicht",
        "copy": "Kopieren",
        "save": "Bericht speichern",
        "input_text": "Eingabetext",
        "clear": "Leeren",
        "password": "Passwort",
        "length": "Länge",
        "uppercase": "Großbuchstaben",
        "lowercase": "Kleinbuchstaben",
        "digits": "Ziffern",
        "symbols": "Sonderzeichen",
        "generate": "Generieren",
        "strength": "Stärke",
        "lang": "Sprache",
        "dark": "Dunkelmodus",
        "info": "Info",
        "github": "GitHub",
        "about": "Ein minimales, lokales Werkzeug von BYLICKILABS für Hashing und sichere Passworterstellung.",
        "no_file": "Bitte zuerst eine Datei wählen.",
        "no_charset": "Mindestens einen Zeichensatz auswählen.",
        "saved": "Bericht gespeichert.",
        "save_failed": "Speichern fehlgeschlagen.",
    },
}

ALGS = ["MD5", "SHA1", "SHA256", "SHA512"]

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.lang = "de"
        self.dark = False
        self.title(self._t(APP_TITLE_DE, APP_TITLE_EN))
        self.geometry("980x620")
        self.minsize(900, 560)
        self._build_style()
        self._build_header()
        self._build_tabs()
        self._apply_texts()

    def _build_style(self):
        self.style = ttk.Style(self)
        self._apply_theme()

    def _apply_theme(self):
        if self.dark:
            bg = "#111217"; fg = "#e5e7eb"; acc = "#6366f1"
            self.configure(bg=bg)
            self.style.theme_use("clam")
            self.style.configure("TFrame", background=bg)
            self.style.configure("TLabel", background=bg, foreground=fg)
            self.style.configure("TNotebook", background=bg)
            self.style.configure("TNotebook.Tab", background="#1f2230", foreground=fg)
            self.style.map("TNotebook.Tab", background=[("selected", "#2b2f44")])
            self.style.configure("TButton", background="#2b2f44", foreground=fg)
            self.style.map("TButton", background=[("active", "#3a3f5c")])
            self.style.configure("TLabelframe", background=bg, foreground=fg)
            self.style.configure("TLabelframe.Label", background=bg, foreground=fg)
            self.style.configure("TEntry", fieldbackground="#0f1117", foreground=fg)
        else:
            bg = "#f7f7fb"; fg = "#111827"
            self.configure(bg=bg)
            self.style.theme_use("clam")
            self.style.configure("TFrame", background=bg)
            self.style.configure("TLabel", background=bg, foreground=fg)
            self.style.configure("TNotebook", background=bg)
            self.style.configure("TNotebook.Tab", background="#ffffff", foreground=fg)
            self.style.map("TNotebook.Tab", background=[("selected", "#eef2ff")])
            self.style.configure("TButton", background="#eef2ff", foreground=fg)
            self.style.map("TButton", background=[("active", "#e0e7ff")])
            self.style.configure("TLabelframe", background=bg, foreground=fg)
            self.style.configure("TLabelframe.Label", background=bg, foreground=fg)
            self.style.configure("TEntry", fieldbackground="#ffffff", foreground=fg)

    def _build_header(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=(10, 6))

        self.title_label = ttk.Label(top, text=self._t(APP_TITLE_DE, APP_TITLE_EN), font=("Segoe UI", 14, "bold"))
        self.title_label.pack(side="left")

        right = ttk.Frame(top)
        right.pack(side="right")

        self.lang_var = tk.StringVar(value=self.lang)
        self.lang_combo = ttk.Combobox(right, textvariable=self.lang_var, values=["de", "en"], width=5, state="readonly")
        self.lang_combo.pack(side="left", padx=6)
        self.lang_combo.bind("<<ComboboxSelected>>", self._on_lang_change)

        self.dark_var = tk.BooleanVar(value=self.dark)
        self.dark_chk = ttk.Checkbutton(right, text=self._i18n("dark"), variable=self.dark_var, command=self._on_dark_toggle)
        self.dark_chk.pack(side="left", padx=6)

        self.github_btn = ttk.Button(right, text=self._i18n("github"), command=self._open_github)
        self.github_btn.pack(side="left", padx=6)

        self.info_btn = ttk.Button(right, text=self._i18n("info"), command=self._show_info)
        self.info_btn.pack(side="left", padx=6)

    def _build_tabs(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_file = ttk.Frame(self.nb)
        self.nb.add(self.tab_file, text=self._i18n("tab_file"))

        f_top = ttk.Frame(self.tab_file)
        f_top.pack(fill="x", pady=6)
        ttk.Label(f_top, text=self._i18n("file_path")).pack(side="left")
        self.file_var = tk.StringVar()
        self.file_entry = ttk.Entry(f_top, textvariable=self.file_var)
        self.file_entry.pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(f_top, text=self._i18n("choose_file"), command=self._choose_file).pack(side="left")

        alg_frame = ttk.Labelframe(self.tab_file, text=self._i18n("hash_algs"))
        alg_frame.pack(fill="x", pady=6)
        self.alg_vars = {alg: tk.BooleanVar(value=True) for alg in ALGS}
        for alg in ALGS:
            ttk.Checkbutton(alg_frame, text=alg, variable=self.alg_vars[alg]).pack(side="left", padx=6, pady=4)

        cmd_frame = ttk.Frame(self.tab_file)
        cmd_frame.pack(fill="x", pady=6)
        ttk.Button(cmd_frame, text=self._i18n("compute"), command=self._compute_file_hashes).pack(side="left")
        ttk.Button(cmd_frame, text=self._i18n("save"), command=self._save_report).pack(side="left", padx=6)

        self.result_text = tk.Text(self.tab_file, height=14, wrap="none")
        self.result_text.pack(fill="both", expand=True, pady=(6, 0))
        self._apply_text_widget_theme(self.result_text)

        ver_frame = ttk.Frame(self.tab_file)
        ver_frame.pack(fill="x", pady=8)
        ttk.Label(ver_frame, text=self._i18n("expected")).pack(side="left")
        self.expected_var = tk.StringVar()
        self.expected_entry = ttk.Entry(ver_frame, textvariable=self.expected_var)
        self.expected_entry.pack(side="left", fill="x", expand=True, padx=6)
        self.verify_btn = ttk.Button(ver_frame, text=self._i18n("verify"), command=self._verify_expected)
        self.verify_btn.pack(side="left")
        self.verify_status = ttk.Label(ver_frame, text="", font=("Segoe UI", 10, "bold"))
        self.verify_status.pack(side="left", padx=10)

        self.tab_text = ttk.Frame(self.nb)
        self.nb.add(self.tab_text, text=self._i18n("tab_text"))

        t_top = ttk.Frame(self.tab_text)
        t_top.pack(fill="x", pady=6)
        ttk.Label(t_top, text=self._i18n("input_text")).pack(side="left")
        ttk.Button(t_top, text=self._i18n("clear"), command=lambda: self.text_input.delete("1.0", "end")).pack(side="right")
        ttk.Button(t_top, text=self._i18n("copy"), command=self._copy_text_hashes).pack(side="right", padx=6)

        self.text_input = tk.Text(self.tab_text, height=8, wrap="word")
        self.text_input.pack(fill="both", expand=False, pady=(6, 6))
        self._apply_text_widget_theme(self.text_input)

        self.text_result = tk.Text(self.tab_text, height=10, wrap="none")
        self.text_result.pack(fill="both", expand=True)
        self._apply_text_widget_theme(self.text_result)

        t_btns = ttk.Frame(self.tab_text)
        t_btns.pack(fill="x", pady=6)
        ttk.Button(t_btns, text=self._i18n("compute"), command=self._compute_text_hashes).pack(side="left")

        self.tab_pass = ttk.Frame(self.nb)
        self.nb.add(self.tab_pass, text=self._i18n("tab_pass"))

        p_top = ttk.Frame(self.tab_pass)
        p_top.pack(fill="x", pady=6)
        ttk.Label(p_top, text=self._i18n("password")).pack(side="left")
        self.pass_var = tk.StringVar()
        self.pass_entry = ttk.Entry(p_top, textvariable=self.pass_var)
        self.pass_entry.pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(p_top, text=self._i18n("copy"), command=lambda: self._copy(self.pass_var.get())).pack(side="left")

        p_opts = ttk.Frame(self.tab_pass)
        p_opts.pack(fill="x", pady=6)
        self.length_var = tk.IntVar(value=16)
        ttk.Label(p_opts, text=f"{self._i18n('length')}: {self.length_var.get()}").pack(side="left")
        self.len_label = p_opts.winfo_children()[-1]
        self.len_scale = ttk.Scale(p_opts, from_=8, to=64, orient="horizontal", command=self._on_len_change)
        self.len_scale.set(self.length_var.get())
        self.len_scale.pack(side="left", fill="x", expand=True, padx=10)

        self.uc_var = tk.BooleanVar(value=True)
        self.lc_var = tk.BooleanVar(value=True)
        self.dg_var = tk.BooleanVar(value=True)
        self.sy_var = tk.BooleanVar(value=True)
        for text, var in [
            ("uppercase", self.uc_var),
            ("lowercase", self.lc_var),
            ("digits", self.dg_var),
            ("symbols", self.sy_var),
        ]:
            ttk.Checkbutton(p_opts, text=self._i18n(text), variable=var).pack(side="left", padx=6)

        p_cmds = ttk.Frame(self.tab_pass)
        p_cmds.pack(fill="x", pady=6)
        ttk.Button(p_cmds, text=self._i18n("generate"), command=self._generate_password).pack(side="left")

        s_frame = ttk.Frame(self.tab_pass)
        s_frame.pack(fill="x", pady=6)
        ttk.Label(s_frame, text=self._i18n("strength")).pack(side="left")
        self.strength_bar = ttk.Progressbar(s_frame, length=260, mode='determinate', maximum=100)
        self.strength_bar.pack(side="left", padx=10)

    def _t(self, de, en):
        return de if self.lang == "de" else en

    def _i18n(self, key):
        return I18N[self.lang].get(key, key)

    def _apply_texts(self):
        self.title(self._t(APP_TITLE_DE, APP_TITLE_EN))
        self.title_label.configure(text=self._t(APP_TITLE_DE, APP_TITLE_EN))
        self.dark_chk.configure(text=self._i18n("dark"))
        self.github_btn.configure(text=self._i18n("github"))
        self.info_btn.configure(text=self._i18n("info"))
        self.nb.tab(self.tab_file, text=self._i18n("tab_file"))
        self.nb.tab(self.tab_text, text=self._i18n("tab_text"))
        self.nb.tab(self.tab_pass, text=self._i18n("tab_pass"))
        for child in self.tab_file.winfo_children():
            if isinstance(child, ttk.Labelframe):
                child.configure(text=self._i18n("hash_algs"))
        self.len_label.configure(text=f"{self._i18n('length')}: {int(self.len_scale.get())}")

    def _apply_text_widget_theme(self, widget: tk.Text):
        if self.dark:
            widget.configure(bg="#0f1117", fg="#e5e7eb", insertbackground="#e5e7eb")
        else:
            widget.configure(bg="#ffffff", fg="#111827", insertbackground="#111827")

    def _on_lang_change(self, *_):
        self.lang = self.lang_var.get()
        self._apply_texts()

    def _on_dark_toggle(self):
        self.dark = self.dark_var.get()
        self._apply_theme()
        for w in [self.result_text, self.text_input, self.text_result]:
            self._apply_text_widget_theme(w)

    def _open_github(self):
        import webbrowser
        webbrowser.open_new_tab(GITHUB_URL)

    def _show_info(self):
        messagebox.showinfo(self._t("Info", "Info"), f"{self._t(APP_TITLE_DE, APP_TITLE_EN)}\nVersion {APP_VERSION}\n\n{self._i18n('about')}\n© BYLICKILABS")

    def _choose_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_var.set(path)

    def _compute_file_hashes(self):
        path = self.file_var.get()
        if not path or not os.path.isfile(path):
            messagebox.warning(self._t("Hinweis", "Notice"), self._i18n("no_file"))
            return
        selected = [alg for alg, v in self.alg_vars.items() if v.get()]
        if not selected:
            selected = ["SHA256"]
        self.result_text.delete("1.0", "end")
        self.result_text.insert("end", f"{os.path.basename(path)}\n")
        self.result_text.insert("end", f"Size: {os.path.getsize(path)} bytes\n\n")
        for alg in selected:
            h = self._hash_file(path, alg)
            self.result_text.insert("end", f"{alg}: {h}\n")
        self.result_text.see("end")

    def _hash_file(self, path: str, alg: str) -> str:
        alg_map = {
            "MD5": hashlib.md5,
            "SHA1": hashlib.sha1,
            "SHA256": hashlib.sha256,
            "SHA512": hashlib.sha512,
        }
        h = alg_map[alg]()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _verify_expected(self):
        expected = self.expected_var.get().strip().lower()
        content = self.result_text.get("1.0", "end").lower()
        status_lbl = self.verify_status
        if not expected:
            status_lbl.configure(text="", foreground="")
            return
        if expected and expected in content:
            status_lbl.configure(text=self._i18n("match"), foreground="#10b981")
        else:
            status_lbl.configure(text=self._i18n("mismatch"), foreground="#ef4444")

    def _save_report(self):
        content = self.result_text.get("1.0", "end").strip()
        if not content:
            return
        ts = time.strftime("%Y%m%d-%H%M%S")
        default = f"hash-report-{ts}.txt"
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=default)
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content + "\n")
            messagebox.showinfo(self._t("Erfolg", "Success"), self._i18n("saved"))
        except Exception:
            messagebox.showerror(self._t("Fehler", "Error"), self._i18n("save_failed"))

    def _compute_text_hashes(self):
        text = self.text_input.get("1.0", "end").encode("utf-8")
        res = []
        res.append(f"MD5   : {hashlib.md5(text).hexdigest()}")
        res.append(f"SHA1  : {hashlib.sha1(text).hexdigest()}")
        res.append(f"SHA256: {hashlib.sha256(text).hexdigest()}")
        res.append(f"SHA512: {hashlib.sha512(text).hexdigest()}")
        self.text_result.delete("1.0", "end")
        self.text_result.insert("end", "\n".join(res))

    def _copy_text_hashes(self):
        data = self.text_result.get("1.0", "end").strip()
        if data:
            self._copy(data)

    def _on_len_change(self, val):
        self.length_var.set(int(float(val)))
        self.len_label.configure(text=f"{self._i18n('length')}: {self.length_var.get()}")

    def _generate_password(self):
        pools = []
        if self.uc_var.get():
            pools.append(string.ascii_uppercase)
        if self.lc_var.get():
            pools.append(string.ascii_lowercase)
        if self.dg_var.get():
            pools.append(string.digits)
        if self.sy_var.get():
            pools.append("!@#$%^&*()-_=+[]{};:,<.>/?")
        if not pools:
            messagebox.warning(self._t("Hinweis", "Notice"), self._i18n("no_charset"))
            return
        length = self.length_var.get()
        password_chars = [random.choice(p) for p in pools]
        remaining = length - len(password_chars)
        all_chars = "".join(pools)
        password_chars += [random.choice(all_chars) for _ in range(remaining)]
        random.shuffle(password_chars)
        pwd = "".join(password_chars)
        self.pass_var.set(pwd)
        self._update_strength(pwd)

    def _update_strength(self, pwd: str):
        charset = 0
        if any(c.islower() for c in pwd): charset += 26
        if any(c.isupper() for c in pwd): charset += 26
        if any(c.isdigit() for c in pwd): charset += 10
        if any(c in "!@#$%^&*()-_=+[]{};:,<.>/?" for c in pwd): charset += 30
        length = len(pwd)
        score = min(100, int((length * (charset if charset else 1)) ** 0.5))
        self.strength_bar['value'] = score

    def _copy(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()


def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()

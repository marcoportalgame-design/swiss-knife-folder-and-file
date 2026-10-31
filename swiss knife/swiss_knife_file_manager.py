import os, sys, shutil, hashlib, secrets, string, platform, getpass, time, threading
import subprocess, tempfile, zipfile, ctypes, random
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# ---------------------------------------------------------------- COSTANTI
APP_NAME = "Swiss Knife"
VERSION  = "1.0"
BG       = "#0f1117"; BG2 = "#161a23"; BG3 = "#1e2430"; CARD = "#1a1f2b"
ACCENT   = "#4f8cff"; ACCENT2 = "#7c5cff"; GREEN = "#2ee6a8"; RED = "#ff5c6c"
YELLOW   = "#ffc857"; FG = "#e8ecf4"; MUTED = "#8b93a7"
FONT     = "Segoe UI" if os.name == "nt" else "Helvetica"

# ------------------------------------------------------------ CRITTOGRAFIA
MAGIC = b"SKF1"

def _keystream(key: bytes, n: int):
    out = b""; c = 0
    while len(out) < n:
        out += hashlib.sha256(key + c.to_bytes(8, "big")).digest()
        c += 1
    return out[:n]

def encrypt_file(src, dst, password):
    """Cifrario a flusso con keystream SHA-256 (password-based)."""
    salt = secrets.token_bytes(16)
    key  = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    with open(src, "rb") as f: data = f.read()
    ks = _keystream(key, len(data))
    enc = bytes(a ^ b for a, b in zip(data, ks))
    with open(dst, "wb") as f:
        f.write(MAGIC + salt + enc)

def decrypt_file(src, dst, password):
    with open(src, "rb") as f: raw = f.read()
    if not raw.startswith(MAGIC): raise ValueError("File non cifrato con questo tool")
    salt, enc = raw[4:20], raw[20:]
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    ks  = _keystream(key, len(enc))
    data = bytes(a ^ b for a, b in zip(enc, ks))
    with open(dst, "wb") as f: f.write(data)

# ----------------------------------------------------------- SVUOTA CESTINO
def empty_trash(log):
    removed = 0
    try:
        if os.name == "nt":
            flags = 0x0001 | 0x0004 | 0x0008  # SHERB_NOCONFIRMATION|NOPROGRESSUI|NOSOUND
            ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, flags)
            log("🗑️  Cestino di Windows svuotato.\n"); return
        paths = []
        if sys.platform == "darwin":
            paths = [os.path.expanduser("~/.Trash")]
        else:
            base = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
            paths = [os.path.join(base, "Trash", "files"), os.path.join(base, "Trash", "info")]
        for p in paths:
            if os.path.isdir(p):
                for item in os.listdir(p):
                    fp = os.path.join(p, item)
                    try:
                        (shutil.rmtree if os.path.isdir(fp) else os.remove)(fp); removed += 1
                    except Exception as e: log(f"  ⚠️  {item}: {e}\n")
        log(f"🗑️  Cestino svuotato ({removed} elementi rimossi).\n")
    except Exception as e:
        log(f"❌ Errore cestino: {e}\n")

# -------------------------------------------------------------- UTILS FILE
def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""): h.update(b)
    return h.hexdigest()

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"  # stringa di test EICAR
KNOWN_BAD = {EICAR_SHA256: "EICAR-Test-File (file di prova antivirus)"}

SUSPICIOUS_EXT = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".com", ".pif", ".dll", ".apk"}
DOUBLE_EXT_RE = ("pdf.exe","jpg.exe","png.exe","txt.exe","docx.exe","xlsx.exe","zip.exe","mp4.exe")

def scan_file(path, log):
    name = os.path.basename(path).lower()
    try:
        digest = sha256_file(path)
        if digest in KNOWN_BAD:
            log(f"🔴 MALWARE: {name} -> {KNOWN_BAD[digest]}\n"); return "bad"
        ext = os.path.splitext(name)[1]
        score, why = 0, []
        if ext in SUSPICIOUS_EXT: score += 2; why.append("estensione eseguibile")
        for de in DOUBLE_EXT_RE:
            if name.endswith(de): score += 3; why.append("doppia estensione ingannevole")
        if " " in name and ext in SUSPICIOUS_EXT: score += 1; why.append("spazi nel nome")
        if score >= 3:
            log(f"🟠 SOSPETTO ({', '.join(why)}): {name}\n"); return "warn"
        log(f"🟢 OK: {name}\n"); return "ok"
    except Exception as e:
        log(f"⚪ Errore {name}: {e}\n"); return "err"

CATEGORIES = {
    "Immagini":    {".jpg",".jpeg",".png",".gif",".bmp",".svg",".webp",".tiff",".ico",".heic"},
    "Video":       {".mp4",".mkv",".avi",".mov",".wmv",".flv",".webm",".m4v"},
    "Audio":       {".mp3",".wav",".flac",".ogg",".m4a",".aac",".wma"},
    "Documenti":   {".pdf",".doc",".docx",".txt",".rtf",".odt",".xls",".xlsx",".ppt",".pptx",".csv",".md"},
    "Archivi":     {".zip",".rar",".7z",".tar",".gz",".bz2",".xz"},
    "Codice":      {".py",".js",".html",".css",".java",".c",".cpp",".h",".json",".xml",".sql",".sh",".rb",".go",".rs"},
    "Eseguibili":  {".exe",".msi",".app",".deb",".rpm",".apk",".bat",".sh"},
}

def organize_folder(folder, log):
    moved = 0
    for item in os.listdir(folder):
        fp = os.path.join(folder, item)
        if not os.path.isfile(fp): continue
        ext = os.path.splitext(item)[1].lower()
        cat = next((k for k, v in CATEGORIES.items() if ext in v), "Altro")
        dest_dir = os.path.join(folder, cat)
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, item)
        if os.path.exists(dest): dest = os.path.join(dest_dir, f"{time.strftime('%H%M%S')}_{item}")
        try: shutil.move(fp, dest); moved += 1; log(f"  📁 {item} → {cat}/\n")
        except Exception as e: log(f"  ⚠️  {item}: {e}\n")
    log(f"✅ Organizzazione completata: {moved} file spostati.\n")

def find_duplicates(folder, log):
    hashes = {}
    dupes = 0
    for root, _, files in os.walk(folder):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                d = sha256_file(fp)
                if d in hashes:
                    dupes += 1; log(f"  👯 Duplicato: {fp}\n  └─ uguale a {hashes[d]}\n")
                else: hashes[d] = fp
            except Exception: pass
    log(f"✅ Scansione completata: {dupes} duplicati trovati ({len(hashes)} file unici).\n")
    return dupes

def folder_sizes(folder, log, top=20):
    sizes = {}
    for root, dirs, files in os.walk(folder):
        s = 0
        for fn in files:
            try: s += os.path.getsize(os.path.join(root, fn))
            except OSError: pass
        sizes[root] = s
    total = sum(sizes.values())
    log(f"💽 Totale cartella: {human(total)}\n\nPiù pesanti:\n")
    for p, s in sorted(sizes.items(), key=lambda x: -x[1])[:top]:
        log(f"  {human(s):>10}  {p}\n")
    log("\n")

def human(n):
    for u in ("B","KB","MB","GB","TB"):
        if n < 1024 or u == "TB": return f"{n:.1f} {u}" if u != "B" else f"{n} B"
        n /= 1024

def secure_delete(path, passes=3, log=None):
    if os.path.isdir(path): shutil.rmtree(path); return
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        for _ in range(passes):
            f.seek(0); f.write(os.urandom(size)); f.flush(); os.fsync(f.fileno())
    os.remove(path)

def gen_password(length=16, symbols=True):
    chars = string.ascii_letters + string.digits + ("!@#$%^&*-_=+?" if symbols else "")
    while True:
        p = "".join(secrets.choice(chars) for _ in range(length))
        if (any(c.islower() for c in p) and any(c.isupper() for c in p)
                and any(c.isdigit() for c in p)): return p

def sys_info(log):
    un = platform.uname()
    log(f"🖥️  Sistema: {un.system} {un.release} ({un.machine})\n")
    log(f"👤 Utente: {getpass.getuser()} | Nodo: {un.node}\n")
    log(f"🐍 Python: {platform.python_version()}\n")
    try:
        import psutil  # opzionale
        vm = psutil.virtual_memory()
        log(f"🧠 RAM: {human(vm.used)} usati / {human(vm.total)} ({vm.percent}%)\n")
        for part in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(part.mountpoint)
                log(f"💽 {part.device} ({part.mountpoint}): {human(u.free)} liberi su {human(u.total)}\n")
            except Exception: pass
    except ImportError:
        log("💽 (installa 'psutil' per i dettagli su RAM/disco)\n")
    log("\n")

def clean_temp(log):
    targets = [tempfile.gettempdir()]
    freed = 0
    for t in targets:
        for item in os.listdir(t):
            fp = os.path.join(t, item)
            try:
                if os.path.isdir(fp): continue
                freed += os.path.getsize(fp); os.remove(fp)
            except Exception: pass
    log(f"🧹 Pulizia temporanei completata: liberati ~{human(freed)} in {targets[0]}\n")

def checksum_file(path, log):
    h1, h2 = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h1.update(b); h2.update(b)
    log(f"📄 {os.path.basename(path)}\n  MD5:    {h1.hexdigest()}\n  SHA256: {h2.hexdigest()}\n\n")

def zip_folder(src, dst, log):
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
        if os.path.isdir(src):
            for root, _, files in os.walk(src):
                for fn in files:
                    fp = os.path.join(root, fn)
                    z.write(fp, os.path.relpath(fp, src))
        else: z.write(src, os.path.basename(src))
    log(f"🤐 Creato archivio: {dst}\n")

def unzip(src, dst, log):
    with zipfile.ZipFile(src) as z: z.extractall(dst)
    log(f"📦 Estratto in: {dst}\n")

def batch_rename(folder, prefix, log):
    n = 1
    for item in sorted(os.listdir(folder)):
        fp = os.path.join(folder, item)
        if not os.path.isfile(fp): continue
        ext = os.path.splitext(item)[1]
        new = os.path.join(folder, f"{prefix}_{n:03d}{ext}")
        while os.path.exists(new): n += 1; new = os.path.join(folder, f"{prefix}_{n:03d}{ext}")
        os.rename(fp, new); n += 1; log(f"  ✏️  {item} → {os.path.basename(new)}\n")
    log(f"✅ Rinominati {n-1} file con prefisso '{prefix}'.\n")

# ------------------------------------------------------------------- GUI
class Splash(tk.Toplevel):
    def __init__(self, master, on_done):
        super().__init__(master)
        self.overrideredirect(True)
        self.configure(bg=BG)
        w, h = 460, 260
        x = (self.winfo_screenwidth() - w) // 2; y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")
        tk.Label(self, text="🛠️", font=(FONT, 42), bg=BG).pack(pady=(30, 0))
        tk.Label(self, text=APP_NAME.upper(), font=(FONT, 22, "bold"), bg=BG, fg=FG).pack()
        tk.Label(self, text=f"File Utility Suite v{VERSION}", font=(FONT, 11), bg=BG, fg=MUTED).pack()
        self.bar = ttk.Progressbar(self, length=340, mode="determinate")
        self.bar.pack(pady=24)
        self.status = tk.Label(self, text="Inizializzazione...", font=(FONT, 9), bg=BG, fg=ACCENT)
        self.status.pack()
        self.on_done = on_done; self.p = 0
        self._step()

    def _step(self):
        steps = ["Caricamento moduli...", "Scansione periferiche...", "Preparazione GUI...",
                 "Caricamento firme malware...", "Calibrazione interfacce...", "Quasi pronto..."]
        if self.p < 100:
            self.p += random.randint(3, 9)
            self.bar["value"] = self.p
            self.status.config(text=steps[min(len(steps)-1, self.p // 18)])
            self.after(90, self._step)
        else:
            self.destroy(); self.on_done()

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} — File Utility Suite")
        self.configure(bg=BG)
        self.geometry("1060x660"); self.minsize(960, 600)
        self._style()
        self._layout()

    # ------- stile moderno -------
    def _style(self):
        s = ttk.Style(self); s.theme_use("clam")
        s.configure("TFrame", background=BG)
        s.configure("Card.TFrame", background=CARD)
        s.configure("TLabel", background=BG, foreground=FG, font=(FONT, 10))
        s.configure("Card.TLabel", background=CARD, foreground=FG, font=(FONT, 10))
        s.configure("Title.TLabel", font=(FONT, 16, "bold"), background=CARD, foreground=FG)
        s.configure("Sub.TLabel", font=(FONT, 9), background=CARD, foreground=MUTED)
        s.configure("TEntry", fieldbackground=BG3, foreground=FG, insertcolor=FG, bordercolor=BG3)
        s.configure("TProgressbar", troughcolor=BG3, background=ACCENT, bordercolor=BG3)
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=BG2, foreground=MUTED, padding=(14, 7), font=(FONT, 9, "bold"))
        s.map("TNotebook.Tab", background=[("selected", ACCENT)], foreground=[("selected", "white")])

    def _layout(self):
        # Sidebar
        side = tk.Frame(self, bg=BG2, width=230)
        side.pack(side="left", fill="y"); side.pack_propagate(False)
        tk.Label(side, text="🛠️", font=(FONT, 26), bg=BG2).pack(pady=(18, 0))
        tk.Label(side, text=APP_NAME, font=(FONT, 15, "bold"), bg=BG2, fg=FG).pack()
        tk.Label(side, text=f"v{VERSION} | {platform.system()}", font=(FONT, 8), bg=BG2, fg=MUTED).pack(pady=(0, 12))

        self.nav = tk.Listbox(side, bg=BG2, fg=FG, selectbackground=ACCENT, selectforeground="white",
                              activestyle="none", highlightthickness=0, bd=0,
                              font=(FONT, 10, "bold"), height=15, exportselection=False)
        self.nav.pack(fill="both", expand=True, padx=10, pady=6)
        tk.Label(side, text="© 2026 — Solo uso personale", font=(FONT, 7), bg=BG2, fg=MUTED).pack(pady=8)

        # Area principale: notebook (tab per ogni funzione)
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=10)

        self.logs = {}
        self._tab("📁 Organizza", self._ui_organize)
        self._tab("🗑️ Cestino",  self._ui_trash)
        self._tab("🔐 Crittografia", self._ui_crypto)
        self._tab("🛡️ Antivirus", self._ui_scan)
        self._tab("👯 Duplicati", self._ui_dupes)
        self._tab("💽 Spazio disco", self._ui_sizes)
        self._tab("🔑 Password", self._ui_password)
        self._tab("⚰️ Cancellazione sicura", self._ui_secure)
        self._tab("ℹ️ Sistema", self._ui_sysinfo)
        self._tab("🧹 Pulizia temp", self._ui_clean)
        self._tab("#️⃣ Checksum", self._ui_checksum)
        self._tab("🤐 ZIP", self._ui_zip)
        self._tab("✏️ Rinomina batch", self._ui_rename)

        for i, t in enumerate(self.nb.tabs()):
            self.nb.tab(t, text=self.nav_items[i])

    nav_items = []

    def _tab(self, title, builder):
        f = ttk.Frame(self.nb, style="Card.TFrame"); self.nb.add(f)
        App.nav_items.append(title)
        self.nav.insert("end", f"   {title}")
        self.nav.bind("<<ListboxSelect>>", lambda e: self.nb.select(self.nav.curselection()[0]))
        builder(f)

    def _logbox(self, parent):
        box = scrolledtext.ScrolledText(parent, bg=BG, fg=FG, insertbackground=FG,
                                        font=("Consolas" if os.name == "nt" else "Monospace", 9),
                                        relief="flat", bd=6)
        box.pack(fill="both", expand=True, pady=(8, 0))
        return box

    def _worker(self, fn):
        def run():
            try: fn()
            except Exception as e: self._cur_log(f"\n❌ Errore: {e}\n")
        threading.Thread(target=run, daemon=True).start()

    def _cur_log(self, msg):
        for w in self.logs.values():
            w.insert("end", msg); w.see("end")

    # ------------------------------------------------ TAB builders
    def _head(self, p, title, sub):
        ttk.Label(p, text=title, style="Title.TLabel").pack(anchor="w", padx=14, pady=(12, 0))
        ttk.Label(p, text=sub, style="Sub.TLabel").pack(anchor="w", padx=14)

    def _btn(self, p, text, cmd):
        tk.Button(p, text=text, command=cmd, bg=ACCENT, fg="white", relief="flat",
                  font=(FONT, 9, "bold"), cursor="hand2", activebackground=ACCENT2,
                  activeforeground="white", padx=14, pady=6).pack(side="left", padx=4)

    def _ui_organize(self, p):
        self._head(p, "Organizza file", "Sposta i file di una cartella in sottocartelle per categoria")
        bar = tk.Frame(p, bg=CARD); bar.pack(fill="x", padx=14, pady=10)
        self.org_dir = tk.StringVar(value=os.path.expanduser("~"))
        tk.Entry(bar, textvariable=self.org_dir, width=60, bg=BG3, fg=FG, relief="flat",
                 insertbackground=FG).pack(side="left", padx=4)
        self._btn(bar, "Sfoglia…", lambda: self.org_dir.set(filedialog.askdirectory() or self.org_dir.get()))
        self._btn(bar, "▶ Organizza", lambda: self._worker(lambda: organize_folder(self.org_dir.get(), self._cur_log)))
        self.logs["org"] = self._logbox(p)

    def _ui_trash(self, p):
        self._head(p, "Svuota cestino", "Elimina definitivamente tutto il contenuto del cestino di sistema")
        bar = tk.Frame(p, bg=CARD); bar.pack(fill="x", padx=14, pady=10)
        self._btn(bar, "🗑️ Svuota cestino ora", lambda: self._worker(lambda: empty_trash(self._cur_log)))
        self.logs["trash"] = self._logbox(p)

    def _ui_crypto(self, p):
        self._head(p, "Crittografia file", "Cifra/decifra un file con una password (keystream SHA-256 + PBKDF2)")
        bar = tk.Frame(p, bg=CARD); bar.pack(fill="x", padx=14, pady=6)
        self.cr_src = tk.StringVar(); self.cr_pass = tk.StringVar()
        tk.Entry(bar, textvariable=self.cr_src, width=55, bg=BG3, fg=FG, relief="flat",
                 insertbackground=FG).pack(side="left", padx=4)
        self._btn(bar, "Sfoglia…", lambda: self.cr_src.set(filedialog.askopenfilename() or self.cr_src.get()))
        bar2 = tk.Frame(p, bg=CARD); bar2.pack(fill="x", padx=14, pady=4)
        ttk.Label(bar2, text="Password:", style="Card.TLabel").pack(side="left", padx=4)
        tk.Entry(bar2, textvariable=self.cr_pass, show="•", width=25, bg=BG3, fg=FG,
                 relief="flat", insertbackground=FG).pack(side="left", padx=4)
        self._btn(bar2, "🔒 Cifra", lambda: self._worker(self._do_encrypt))
        self._btn(bar2, "🔓 Decifra", lambda: self._worker(self._do_decrypt))
        self.logs["cr"] = self._logbox(p)

    def _do_encrypt(self):
        s = self.cr_src.get(); p = self.cr_pass.get()
        if not (s and p): self._cur_log("⚠️  Seleziona un file e inserisci una password.\n"); return
        d = s + ".locked"; encrypt_file(s, d, p)
        self._cur_log(f"🔒 Cifrato: {os.path.basename(d)}\n")

    def _do_decrypt(self):
        s = self.cr_src.get(); p = self.cr_pass.get()
        if not (s and p): self._cur_log("⚠️  Seleziona un file e inserisci una password.\n"); return
        d = s.replace(".locked", "") + ".unlocked"
        try: decrypt_file(s, d, p); self._cur_log(f"🔓 Decifrato: {os.path.basename(d)}\n")
        except Exception: self._cur_log("❌ Password errata o file non valido.\n")

    def _ui_scan(self, p):
        self._head(p, "Scansione antivirus", "Controllo firme hash note + analisi euristica dei nomi file")
        bar = tk.Frame(p, bg=CARD); bar.pack(fill="x", padx=14, pady=10)
        self.sc_dir = tk.StringVar(value=os.path.expanduser("~"))
        tk.Entry(bar, textvariable=self.sc_dir, width=60, bg=BG3, fg=FG, relief="flat",
                 insertbackground=FG).pack(side="left", padx=4)
        self._btn(bar, "Sfoglia…", lambda: self.sc_dir.set(filedialog.askdirectory() or self.sc_dir.get()))
        def run():
            root = self.sc_dir.get()
            self._cur_log(f"🛡️  Scansione di {root}...\n")
            bad = warn = 0
            for r, _, files in os.walk(root):
                for fn in files:
                    res = scan_file(os.path.join(r, fn), self._cur_log)
                    bad += res == "bad"; warn += res == "warn"
            self._cur_log(f"\n✅ Finito: {bad} minacce, {warn} sospetti.\n")
        self._btn(bar, "▶ Scansiona", lambda: self._worker(run))
        self.logs["scan"] = self._logbox(p)

    def _ui_dupes(self, p):
        self._head(p, "Trova duplicati", "Confronta gli hash SHA-256 di tutti i file della cartella")
        bar = tk.Frame(p, bg=CARD); bar.pack(fill="x", padx=14, pady=10)
        self.dp_dir = tk.StringVar(value=os.path.expanduser("~"))
        tk.Entry(bar, textvariable=self.dp_dir, width=60, bg=BG3, fg=FG, relief="flat",
                 insertbackground=FG).pack(side="left", padx=4)
        self._btn(bar, "Sfoglia…", lambda: self.dp_dir.set(filedialog.askdirectory() or self.dp_dir.get()))
        self._btn(bar, "▶ Cerca", lambda: self._worker(lambda: find_duplicates(self.dp_dir.get(), self._cur_log)))
        self.logs["dup"] = self._logbox(p)

    def _ui_sizes(self, p):
        self._head(p, "Analisi spazio disco", "Le sottocartelle più pesanti, ordinate per dimensione")
        bar = tk.Frame(p, bg=CARD); bar.pack(fill="x", padx=14, pady=10)
        self.sz_dir = tk.StringVar(value=os.path.expanduser("~"))
        tk.Entry(bar, textvariable=self.sz_dir, width=60, bg=BG3, fg=FG, relief="flat",
                 insertbackground=FG).pack(side="left", padx=4)
        self._btn(bar, "Sfoglia…", lambda: self.sz_dir.set(filedialog.askdirectory() or self.sz_dir.get()))
        self._btn(bar, "▶ Analizza", lambda: self._worker(lambda: folder_sizes(self.sz_dir.get(), self._cur_log)))
        self.logs["sz"] = self._logbox(p)

    def _ui_password(self, p):
        self._head(p, "Generatore di password", "Password crittograficamente sicure con 'secrets'")
        bar = tk.Frame(p, bg=CARD); bar.pack(fill="x", padx=14, pady=10)
        ttk.Label(bar, text="Lunghezza:", style="Card.TLabel").pack(side="left", padx=4)
        self.pw_len = tk.IntVar(value=16)
        tk.Spinbox(bar, from_=8, to=64, textvariable=self.pw_len, width=5, bg=BG3, fg=FG,
                   relief="flat", buttonbackground=BG3).pack(side="left")
        self.pw_sym = tk.BooleanVar(value=True)
        tk.Checkbutton(bar, text="Simboli", variable=self.pw_sym, bg=CARD, fg=FG, selectcolor=BG3,
                       activebackground=CARD, activeforeground=FG).pack(side="left", padx=8)
        self.pw_out = tk.StringVar()
        self._btn(bar, "🎲 Genera", lambda: self.pw_out.set(gen_password(self.pw_len.get(), self.pw_sym.get())))
        tk.Entry(p, textvariable=self.pw_out, font=("Consolas", 13), bg=BG3, fg=GREEN,
                 relief="flat", justify="center").pack(fill="x", padx=14, ipady=8)

    def _ui_secure(self, p):
        self._head(p, "Cancellazione sicura", "Sovrascrive il file con dati casuali (3 passaggi) prima di eliminarlo")
        bar = tk.Frame(p, bg=CARD); bar.pack(fill="x", padx=14, pady=10)
        self.sd_path = tk.StringVar()
        tk.Entry(bar, textvariable=self.sd_path, width=60, bg=BG3, fg=FG, relief="flat",
                 insertbackground=FG).pack(side="left", padx=4)
        self._btn(bar, "Sfoglia…", lambda: self.sd_path.set(filedialog.askopenfilename() or self.sd_path.get()))
        def run():
            s = self.sd_path.get()
            if not s: self._cur_log("⚠️  Seleziona un file.\n"); return
            secure_delete(s, log=self._cur_log)
            self._cur_log(f"⚰️  Cancellato in sicurezza: {os.path.basename(s)}\n")
        self._btn(bar, "⚰️ Elimina", lambda: self._worker(run))
        self.logs["sd"] = self._logbox(p)

    def _ui_sysinfo(self, p):
        self._head(p, "Informazioni di sistema", "Dettagli su OS, hardware e risorse")
        bar = tk.Frame(p, bg=CARD); bar.pack(fill="x", padx=14, pady=10)
        self._btn(bar, "ℹ️ Carica info", lambda: self._worker(lambda: sys_info(self._cur_log)))
        self.logs["sys"] = self._logbox(p)

    def _ui_clean(self, p):
        self._head(p, "Pulizia file temporanei", "Svuota la cartella temp dell'utente corrente")
        bar = tk.Frame(p, bg=CARD); bar.pack(fill="x", padx=14, pady=10)
        self._btn(bar, "🧹 Pulisci ora", lambda: self._worker(lambda: clean_temp(self._cur_log)))
        self.logs["cl"] = self._logbox(p)

    def _ui_checksum(self, p):
        self._head(p, "Calcolatore checksum", "MD5 e SHA-256 di un file (verifica integrità)")
        bar = tk.Frame(p, bg=CARD); bar.pack(fill="x", padx=14, pady=10)
        self.cs_path = tk.StringVar()
        tk.Entry(bar, textvariable=self.cs_path, width=60, bg=BG3, fg=FG, relief="flat",
                 insertbackground=FG).pack(side="left", padx=4)
        self._btn(bar, "Sfoglia…", lambda: self.cs_path.set(filedialog.askopenfilename() or self.cs_path.get()))
        self._btn(bar, "#️⃣ Calcola", lambda: self._worker(lambda: checksum_file(self.cs_path.get(), self._cur_log)))
        self.logs["cs"] = self._logbox(p)

    def _ui_zip(self, p):
        self._head(p, "Comprimi / Estrai ZIP", "Crea archivi ZIP da file o cartelle, o estraili")
        bar = tk.Frame(p, bg=CARD); bar.pack(fill="x", padx=14, pady=6)
        self.zp_src = tk.StringVar(); self.zp_dst = tk.StringVar()
        tk.Entry(bar, textvariable=self.zp_src, width=48, bg=BG3, fg=FG, relief="flat",
                 insertbackground=FG).pack(side="left", padx=4)
        self._btn(bar, "Sorgente…", lambda: self.zp_src.set(filedialog.askopenfilename() or filedialog.askdirectory() or self.zp_src.get()))
        bar2 = tk.Frame(p, bg=CARD); bar2.pack(fill="x", padx=14, pady=4)
        tk.Entry(bar2, textvariable=self.zp_dst, width=48, bg=BG3, fg=FG, relief="flat",
                 insertbackground=FG).pack(side="left", padx=4)
        self._btn(bar2, "Destinazione…", lambda: self.zp_dst.set(filedialog.asksaveasfilename(defaultextension=".zip") or self.zp_dst.get()))
        self._btn(bar2, "🤐 Comprimi", lambda: self._worker(lambda: zip_folder(self.zp_src.get(), self.zp_dst.get(), self._cur_log)))
        self._btn(bar2, "📦 Estrai qui…", lambda: self._worker(lambda: unzip(
            self.zp_src.get(), filedialog.askdirectory() or self.zp_src.get(), self._cur_log)))
        self.logs["zip"] = self._logbox(p)

    def _ui_rename(self, p):
        self._head(p, "Rinomina batch", "Rinomina tutti i file di una cartella con un prefisso e numero progressivo")
        bar = tk.Frame(p, bg=CARD); bar.pack(fill="x", padx=14, pady=6)
        self.rn_dir = tk.StringVar(value=os.path.expanduser("~")); self.rn_prefix = tk.StringVar(value="file")
        tk.Entry(bar, textvariable=self.rn_dir, width=45, bg=BG3, fg=FG, relief="flat",
                 insertbackground=FG).pack(side="left", padx=4)
        tk.Entry(bar, textvariable=self.rn_prefix, width=14, bg=BG3, fg=FG, relief="flat",
                 insertbackground=FG).pack(side="left", padx=4)
        self._btn(bar, "Sfoglia…", lambda: self.rn_dir.set(filedialog.askdirectory() or self.rn_dir.get()))
        self._btn(bar, "▶ Rinomina", lambda: self._worker(lambda: batch_rename(self.rn_dir.get(), self.rn_prefix.get(), self._cur_log)))
        self.logs["rn"] = self._logbox(p)

def main():
    app = App(); app.withdraw()
    Splash(app, lambda: app.deiconify())
    app.mainloop()

if __name__ == "__main__":
    main()

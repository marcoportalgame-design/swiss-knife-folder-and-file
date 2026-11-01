import os
import sys
import shutil
import hashlib
import secrets
import string
import platform
import getpass
import time
import threading
import subprocess
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

# GUI Imports
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Optional dependency for better system info
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ---------------------------------------------------------------- COSTANTI & CONFIGURAZIONE
APP_NAME = "Swiss Knife Pro"
VERSION  = "2.2" # Updated with Smart Organization

# Color Palette (Modern Dark Mode - Catppuccin Mocha inspired)
BG_MAIN   = "#1e1e2e"      # Base background
BG_CARD   = "#2a2b3c"      # Card/Panel background
BG_INPUT  = "#313244"      # Input fields
ACCENT    = "#89b4fa"      # Primary Blue
SUCCESS   = "#a6e3a1"      # Green
WARNING   = "#f9e2af"      # Yellow
DANGER    = "#f38ba8"      # Red
TEXT_MAIN = "#cdd6f4"      # Main Text
TEXT_MUTED= "#6c7086"      # Secondary Text
FONT_UI   = "Segoe UI" if os.name == "nt" else "Helvetica Neue"
FONT_MONO = "Consolas" if os.name == "nt" else "Monaco"

# Crypto Constants
MAGIC = b"SKF2" 

# Determine Root Directory based on OS
if os.name == 'nt':
    ROOT_DIR = "C:\\"
else:
    ROOT_DIR = "/"

# ------------------------------------------------------------ CRITTOGRAFIA AVANZATA
def _derive_key(password: str, salt: bytes, iterations: int = 150_000):
    return hashlib.pbkdf2_hmac("sha256", password.encode('utf-8'), salt, iterations)

def encrypt_file(src_path, dst_path, password, progress_callback=None):
    if not os.path.isfile(src_path):
        raise FileNotFoundError(f"Il percorso {src_path} non è un file valido.")
        
    salt = secrets.token_bytes(16)
    key = _derive_key(password, salt)
    block_size = 1024 * 1024
    
    try:
        file_size = os.path.getsize(src_path)
        processed = 0
        with open(src_path, "rb") as f_in, open(dst_path, "wb") as f_out:
            header = MAGIC + salt + file_size.to_bytes(8, 'big')
            f_out.write(header)
            while True:
                data = f_in.read(block_size)
                if not data: break
                extended_ks = b""
                counter = 0
                while len(extended_ks) < len(data):
                    extended_ks += hashlib.sha256(key + processed.to_bytes(8,'big') + counter.to_bytes(4,'big')).digest()
                    counter += 1
                extended_ks = extended_ks[:len(data)]
                enc_data = bytes(a ^ b for a, b in zip(data, extended_ks))
                f_out.write(enc_data)
                processed += len(data)
                if progress_callback and file_size > 0:
                    progress_callback(processed / file_size)
    except Exception as e:
        raise IOError(f"Errore durante la cifratura: {e}")

def decrypt_file(src_path, dst_path, password, progress_callback=None):
    if not os.path.isfile(src_path):
        raise FileNotFoundError(f"Il percorso {src_path} non è un file valido.")

    block_size = 1024 * 1024
    try:
        with open(src_path, "rb") as f_in:
            header = f_in.read(len(MAGIC) + 16 + 8)
            if not header.startswith(MAGIC):
                raise ValueError("Formato file non riconosciuto o corrotto.")
            
            salt = header[len(MAGIC):len(MAGIC)+16]
            orig_size_int = int.from_bytes(header[-8:], 'big')
            key = _derive_key(password, salt)
            
            with open(dst_path, "wb") as f_out:
                processed = 0
                while True:
                    data = f_in.read(block_size)
                    if not data: break
                    extended_ks = b""
                    counter = 0
                    while len(extended_ks) < len(data):
                        extended_ks += hashlib.sha256(key + processed.to_bytes(8,'big') + counter.to_bytes(4,'big')).digest()
                        counter += 1
                    extended_ks = extended_ks[:len(data)]
                    dec_data = bytes(a ^ b for a, b in zip(data, extended_ks))
                    f_out.write(dec_data)
                    processed += len(data)
                    if progress_callback and orig_size_int > 0:
                        progress_callback(min(processed / orig_size_int, 1.0))
    except Exception as e:
        raise IOError(f"Errore durante la decifratura (Password errata?): {e}")

# ----------------------------------------------------------- UTILITIES CORE
class Logger:
    def __init__(self, widget):
        self.widget = widget
        self.lock = threading.Lock()
        
    def log(self, msg, tag="INFO"):
        colors = {"INFO": TEXT_MAIN, "OK": SUCCESS, "WARN": WARNING, "ERROR": DANGER, "HEADER": ACCENT, "MUTED": TEXT_MUTED}
        color = colors.get(tag, TEXT_MAIN)
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        def update_ui():
            with self.lock:
                self.widget.configure(state='normal')
                self.widget.insert(tk.END, f"[{timestamp}] ", TEXT_MUTED)
                self.widget.insert(tk.END, f"{msg}\n", color)
                self.widget.see(tk.END)
                self.widget.configure(state='disabled')
        self.widget.after(0, update_ui)

def human_readable(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def sha256_chunked(path, chunk_size=1024*1024):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            data = f.read(chunk_size)
            if not data: break
            h.update(data)
    return h.hexdigest()

# ------------------------------------------------------------- FUNZIONALITÀ BACKEND

def task_empty_trash(logger):
    logger.log("Inizio svuotamento cestino...", "HEADER")
    removed_count = 0
    errors = []
    try:
        if os.name == "nt":
            try:
                import ctypes
                flags = 0x0001 | 0x0004 | 0x0008 
                result = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, flags)
                if result == 0:
                    logger.log("✅ Cestino Windows svuotato.", "OK")
                else:
                    logger.log("⚠️ Operazione completata ma con avvisi di sistema.", "WARN")
                return
            except Exception as e:
                logger.log(f"❌ Errore API Windows: {e}. Tentativo manuale...", "ERROR")

        trash_paths = []
        if sys.platform == "darwin":
            trash_paths.append(os.path.expanduser("~/.Trash"))
        elif os.name == "posix":
            xdg_home = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
            trash_paths.append(os.path.join(xdg_home, "Trash", "files"))
            trash_paths.append(os.path.join(xdg_home, "Trash", "info"))
            
        for t_path in trash_paths:
            if os.path.exists(t_path):
                for item in os.listdir(t_path):
                    full_item = os.path.join(t_path, item)
                    try:
                        if os.path.isdir(full_item):
                            shutil.rmtree(full_item)
                        else:
                            os.remove(full_item)
                        removed_count += 1
                    except PermissionError:
                        errors.append(item)
                    except Exception as e:
                        errors.append(f"{item}: {e}")
                        
        if removed_count > 0:
            logger.log(f"✅ Svuotato manualmente: {removed_count} elementi rimossi.", "OK")
        if errors:
            logger.log(f"⚠️ Alcuni elementi non eliminabili: {len(errors)}", "WARN")
    except Exception as e:
        logger.log(f"❌ Errore critico cestino: {e}", "ERROR")

def task_scan_malware(folder, logger):
    logger.log(f"Inizio Scansione Sistema Completo: {folder}", "HEADER")
    suspicious_exts = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".com", ".pif", ".dll"}
    double_ext_patterns = ["pdf.exe", "jpg.exe", "png.exe", "txt.exe", "docx.exe"]
    threats_found = 0
    warnings_found = 0
    files_scanned = 0
    permission_denied = 0
    known_hashes = {"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR Test File"}

    try:
        for root, _, files in os.walk(folder):
            if os.name != 'nt':
                if '/proc' in root or '/sys' in root or '/dev' in root: continue
            
            for filename in files:
                filepath = os.path.join(root, filename)
                if not os.path.isfile(filepath): continue
                try:
                    sz = os.path.getsize(filepath)
                    if sz > 50 * 1024 * 1024: continue
                    files_scanned += 1
                    ext = os.path.splitext(filename)[1].lower()
                    score = 0
                    reasons = []
                    if ext in suspicious_exts:
                        score += 2; reasons.append("Estensione eseguibile sospetta")
                    lower_name = filename.lower()
                    for pattern in double_ext_patterns:
                        if lower_name.endswith(pattern):
                            score += 3; reasons.append("Doppia estensione ingannevole")
                    
                    if score > 0 or ext in ['.tmp', '.dat']: 
                         try:
                             digest = sha256_chunked(filepath)
                             if digest in known_hashes:
                                 logger.log(f"🔴 MALWARE RILEVATO: {filepath}", "ERROR")
                                 threats_found += 1
                                 continue
                         except PermissionError:
                             permission_denied += 1; continue
                         except Exception: pass

                    if score >= 3:
                        logger.log(f"🟠 SOSPETTO ({', '.join(reasons)}): {filepath}", "WARN")
                        warnings_found += 1
                except PermissionError: permission_denied += 1
                except OSError: pass
                except Exception as e: logger.log(f"⚪ Errore lettura {filename}: {str(e)[:30]}", "MUTED")

        logger.log(f"--- Scan Completato ---", "HEADER")
        logger.log(f"File analizzati: {files_scanned}", "INFO")
        logger.log(f"Minacce: {threats_found}", "ERROR" if threats_found else "OK")
        logger.log(f"Avvisi: {warnings_found}", "WARN" if warnings_found else "OK")
        if permission_denied > 0: logger.log(f"Ignorati (Permesso Negato): ~{permission_denied}", "MUTED")
    except KeyboardInterrupt: logger.log("Scansione interrotta.", "WARN")
    except Exception as e: logger.log(f"Errore fatale: {e}", "ERROR")

def task_find_duplicates(folder, logger):
    logger.log(f"Cerca duplicati in: {folder}", "HEADER")
    hashes = {}; duplicates = []; total_files = 0; skipped_perm = 0
    try:
        for root, _, files in os.walk(folder):
            if os.name != 'nt':
                if '/proc' in root or '/sys' in root or '/dev' in root: continue
            for fn in files:
                fp = os.path.join(root, fn)
                try:
                    if not os.path.isfile(fp): continue
                    total_files += 1
                    d = sha256_chunked(fp)
                    if d in hashes: duplicates.append((fp, hashes[d]))
                    else: hashes[d] = fp
                except PermissionError: skipped_perm += 1
                except Exception: pass
                    
        if not duplicates: logger.log("✅ Nessun duplicato trovato.", "OK")
        else:
            logger.log(f"👯 Trovati {len(duplicates)} gruppi di duplicati:", "WARN")
            for i, (dup, original) in enumerate(duplicates[:20]):
                logger.log(f"  DUP: {dup}", "INFO"); logger.log(f"  ORIG:{original}", "MUTED")
            if len(duplicates) > 20: logger.log(f"  ... e altri {len(duplicates)-20}.", "MUTED")
        if skipped_perm > 0: logger.log(f"(Ignorati {skipped_perm} file)", "MUTED")
    except Exception as e: logger.log(f"Errore ricerca duplicati: {e}", "ERROR")

def task_secure_delete(paths, passes=3, logger=None):
    if isinstance(paths, str): paths = [paths]
    deleted_count = 0
    for path in paths:
        if not os.path.exists(path): continue
        if path == ROOT_DIR:
            if logger: logger.log("❌ Impossibile eliminare la radice!", "ERROR")
            continue
        try:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path, topdown=False):
                    for name in files: _secure_file(os.path.join(root, name), passes)
                    for name in dirs:
                        try: os.rmdir(os.path.join(root, name))
                        except OSError: pass
                try: os.rmdir(path)
                except OSError: pass
            else: _secure_file(path, passes)
            deleted_count += 1
            if logger: logger.log(f"⚰️ Eliminato sicuro: {os.path.basename(path)}", "OK")
        except Exception as e:
            if logger: logger.log(f"❌ Errore eliminazione {path}: {e}", "ERROR")
    if logger: logger.log(f"Completato. Rimossi: {deleted_count}", "HEADER")

def _secure_file(file_path, passes):
    size = os.path.getsize(file_path)
    with open(file_path, 'r+b') as f:
        for _ in range(passes):
            f.seek(0); remaining = size
            while remaining > 0:
                chunk = min(remaining, 1024 * 1024)
                f.write(os.urandom(chunk)); remaining -= chunk
            f.flush(); os.fsync(f.fileno())
    os.remove(file_path)

def task_get_system_info(logger):
    logger.log("--- Informazioni Sistema ---", "HEADER")
    uname = platform.uname()
    logger.log(f"Sistema Operativo: {uname.system} {uname.release}", "INFO")
    logger.log(f"Architettura: {uname.machine}", "INFO")
    logger.log(f"Nodo Host: {uname.node}", "INFO")
    logger.log(f"Utente Corrente: {getpass.getuser()}", "INFO")
    logger.log(f"Versione Python: {platform.python_version()}", "INFO")
    if HAS_PSUTIL:
        vm = psutil.virtual_memory()
        logger.log(f"RAM Totale: {human_readable(vm.total)}", "INFO")
        logger.log(f"RAM Libera: {human_readable(vm.available)} ({vm.percent}% usata)", "INFO")
        logger.log("--- Dispositivi di Archiviazione ---", "HEADER")
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                logger.log(f"Mount: {part.mountpoint} | Device: {part.device}", "MUTED")
                logger.log(f"  Spazio: {human_readable(usage.used)} / {human_readable(usage.total)} ({usage.percent}% usato)", "INFO")
            except Exception: pass
    else: logger.log("Nota: Installa 'psutil' per dettagli hardware avanzati.", "WARN")

# NEW: SMART ORGANIZER LOGIC
def smart_organize_folder(folder, strategy, logger):
    """
    Strategy can be:
    - 'name': Group by filename stem (without extension)
    - 'date': Group by modification year/month/day
    - 'year': Group by modification year
    - 'type': Standard category grouping only
    """
    logger.log(f"Inizio organizzazione intelligente in: {folder}", "HEADER")
    logger.log(f"Strategia selezionata: {strategy.upper()}", "INFO")
    
    categories = {
        "Immagini": {".jpg",".jpeg",".png",".gif",".bmp",".svg",".webp",".tiff",".ico",".heic"},
        "Video":    {".mp4",".mkv",".avi",".mov",".wmv",".flv",".webm",".m4v"},
        "Audio":    {".mp3",".wav",".flac",".ogg",".m4a",".aac",".wma"},
        "Documenti":{".pdf",".doc",".docx",".txt",".rtf",".odt",".xls",".xlsx",".ppt",".pptx",".csv",".md"},
        "Archivi":  {".zip",".rar",".7z",".tar",".gz",".bz2",".xz"},
        "Codice":   {".py",".js",".html",".css",".java",".c",".cpp",".h",".json",".xml",".sql",".sh",".rb",".go",".rs"},
        "Eseguibili":{".exe",".msi",".app",".deb",".rpm",".apk",".bat",".sh"},
    }
    
    moved = 0
    errors = 0
    
    # Get list of items first to avoid issues if we move them during iteration
    try:
        items = os.listdir(folder)
    except PermissionError:
        logger.log("Accesso negato alla cartella principale.", "ERROR")
        return

    for item in items:
        src_path = os.path.join(folder, item)
        
        # Skip directories created by previous runs to avoid recursion mess
        if os.path.isdir(src_path):
            continue
            
        if not os.path.isfile(src_path):
            continue

        try:
            # 1. Determine Category
            ext = os.path.splitext(item)[1].lower()
            cat = next((k for k, v in categories.items() if ext in v), "Altro")
            
            # 2. Determine Sub-folder Name based on Strategy
            sub_dir_name = ""
            if strategy == 'name':
                # Remove extension, replace spaces/special chars with underscore for safety
                base_name = os.path.splitext(item)[0]
                # Sanitize: keep alphanumeric, space, dash, underscore. Replace others with _
                sanitized = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' for c in base_name)
                sub_dir_name = sanitized.strip() or "Unnamed_File"
                
            elif strategy == 'date':
                mtime = os.path.getmtime(src_path)
                dt = datetime.fromtimestamp(mtime)
                # Format: YYYY-MM-DD
                sub_dir_name = dt.strftime("%Y-%m-%d")
                
            elif strategy == 'year':
                 mtime = os.path.getmtime(src_path)
                 dt = datetime.fromtimestamp(mtime)
                 sub_dir_name = dt.strftime("%Y")
                 
            else: # 'type' or fallback
                 sub_dir_name = "" # No subfolder, just put in category root

            # 3. Construct Destination Path
            dest_root = os.path.join(folder, cat)
            if sub_dir_name:
                dest_final_dir = os.path.join(dest_root, sub_dir_name)
            else:
                dest_final_dir = dest_root
                
            os.makedirs(dest_final_dir, exist_ok=True)
            
            # Handle duplicate filenames within the specific bucket
            dest_filename = item
            dest_full_path = os.path.join(dest_final_dir, dest_filename)
            
            counter = 1
            while os.path.exists(dest_full_path):
                name_part, ext_part = os.path.splitext(item)
                dest_filename = f"{name_part}_copy_{counter}{ext_part}"
                dest_full_path = os.path.join(dest_final_dir, dest_filename)
                counter += 1
                
            # Move file
            shutil.move(src_path, dest_full_path)
            moved += 1
            
            # Log briefly (limit verbosity for large scans)
            if moved % 10 == 0 or moved <= 5:
                rel_path = os.path.relpath(dest_full_path, folder)
                logger.log(f"  📁 {rel_path}", "OK")
                
        except Exception as e:
            errors += 1
            logger.log(f"  ⚠️ Errore su {item}: {e}", "ERROR")

    summary_msg = f"✅ Organizzazione completata: {moved} file spostati."
    if errors > 0:
        summary_msg += f" ({errors} errori)"
    logger.log(summary_msg, "HEADER")


# ------------------------------------------------------------------- GUI CLASS

class ModernApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1100x700")
        self.minsize(900, 600)
        self.configure(bg=BG_MAIN)
        
        self.current_thread = None
        self.is_busy = False
        
        self._setup_styles()
        self._create_layout()
        self.logger = Logger(self.log_box)
        
        self.logger.log(f"Benvvenuto in {APP_NAME} v{VERSION}", "HEADER")
        self.logger.log("Nuova funzione: Organizzazione Gerarchica Intelligente.", "INFO")

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        
        style.configure('.', background=BG_MAIN, foreground=TEXT_MAIN, font=(FONT_UI, 10))
        style.configure('TFrame', background=BG_MAIN)
        style.configure('Card.TFrame', background=BG_CARD, borderwidth=0)
        style.configure('Sidebar.TFrame', background="#181825", borderwidth=0)
        
        style.configure('TLabel', background=BG_MAIN, foreground=TEXT_MAIN, font=(FONT_UI, 10))
        style.configure('Header.TLabel', font=(FONT_UI, 14, 'bold'), foreground=ACCENT, background=BG_MAIN)
        style.configure('Subheader.TLabel', font=(FONT_UI, 9), foreground=TEXT_MUTED, background=BG_MAIN)
        style.configure('Card.TLabel', background=BG_CARD, foreground=TEXT_MAIN)
        
        style.configure('TButton', 
                        background=ACCENT, foreground="#11111b", 
                        font=(FONT_UI, 10, 'bold'), 
                        padding=(10, 5), borderwidth=0, relief='flat')
        style.map('TButton', background=[('active', '#74c7ec'), ('pressed', '#89b4fa')])
        
        style.configure('Danger.TButton', background=DANGER, foreground="#11111b")
        style.map('Danger.TButton', background=[('active', '#eba0ac')])
        
        style.configure('Success.TButton', background=SUCCESS, foreground="#11111b")
        style.map('Success.TButton', background=[('active', '#94e2d5')])
        
        style.configure('TEntry', 
                        fieldbackground=BG_INPUT, foreground=TEXT_MAIN, 
                        insertcolor=TEXT_MAIN, bordercolor=BG_INPUT, 
                        lightcolor=BG_INPUT, darkcolor=BG_INPUT)
        
        style.configure('Vertical.TScrollbar', background=BG_INPUT, troughcolor=BG_MAIN, arrowcolor=TEXT_MUTED)
        style.configure('Horizontal.TScrollbar', background=BG_INPUT, troughcolor=BG_MAIN, arrowcolor=TEXT_MUTED)
        
        style.configure('Treeview', rowheight=25, background=BG_CARD, fieldbackground=BG_CARD, foreground=TEXT_MAIN)
        style.configure('Treeview.Heading', background=BG_INPUT, foreground=TEXT_MAIN, font=(FONT_UI, 9, 'bold'))
        style.map('Treeview', background=[('selected', ACCENT)], foreground=[('selected', '#11111b')])
        
        # Combobox styling
        style.configure('TCombobox', 
                        fieldbackground=BG_INPUT, foreground=TEXT_MAIN, 
                        background=BG_INPUT, arrowsize=15)
        style.map('TCombobox', 
                  fieldbackground=[('readonly', BG_INPUT)],
                  selectbackground=[('readonly', BG_INPUT)],
                  selectforeground=[('readonly', TEXT_MAIN)])

    def _create_layout(self):
        container = ttk.Frame(self, style='TFrame')
        container.pack(fill='both', expand=True, padx=0, pady=0)
        
        sidebar_frame = ttk.Frame(container, style='Sidebar.TFrame', width=220)
        sidebar_frame.pack(side='left', fill='y')
        sidebar_frame.pack_propagate(False)
        
        logo_area = ttk.Frame(sidebar_frame, style='Sidebar.TFrame')
        logo_area.pack(fill='x', pady=20, padx=15)
        ttk.Label(logo_area, text="🛠️ Swiss Knife", font=(FONT_UI, 16, 'bold'), foreground=ACCENT, background="#181825").pack(anchor='w')
        ttk.Label(logo_area, text=f"Utility Suite v{VERSION}", font=(FONT_UI, 8), foreground=TEXT_MUTED, background="#181825").pack(anchor='w')
        
        nav_buttons = ttk.Frame(sidebar_frame, style='Sidebar.TFrame')
        nav_buttons.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.tools = [
            ("📁 Organizza (Smart)", self.show_organizer_tab),
            ("🛡️ Scanzia Sicurezza", self.show_scanner_tab),
            ("🔐 Crittografia", self.show_crypto_tab),
            ("👯 Trova Duplicati", self.show_dupe_tab),
            ("⚰️ Cancellazione Sicura", self.show_secure_tab),
            ("💽 Analisi Disco", self.show_disk_tab),
            ("ℹ️ Info Sistema", self.show_sysinfo_tab),
            ("🧹 Pulizia Temp", self.show_clean_tab),
            ("🤐 Compressore ZIP", self.show_zip_tab),
        ]
        
        self.nav_btns = []
        for i, (label, cmd) in enumerate(self.tools):
            btn = ttk.Button(nav_buttons, text=label, command=lambda c=cmd: self.switch_view(c), style='TButton')
            btn.pack(fill='x', pady=2, ipady=5)
            self.nav_btns.append(btn)
            
        footer = ttk.Frame(sidebar_frame, style='Sidebar.TFrame')
        footer.pack(fill='x', side='bottom', pady=10, padx=15)
        ttk.Label(footer, text="© 2026 Personal Use", font=(FONT_UI, 7), foreground=TEXT_MUTED, background="#181825").pack()

        content_frame = ttk.Frame(container, style='TFrame')
        content_frame.pack(side='right', fill='both', expand=True)
        
        top_bar = ttk.Frame(content_frame, style='Card.TFrame', height=40)
        top_bar.pack(fill='x', side='top')
        top_bar.pack_propagate(False)
        
        self.status_label = ttk.Label(top_bar, text="Pronto", style='Card.TLabel', font=(FONT_UI, 9))
        self.status_label.pack(side='left', padx=15, pady=10)
        
        self.progress_bar = ttk.Progressbar(top_bar, orient='horizontal', mode='indeterminate', length=200)
        self.progress_bar.pack(side='right', padx=15, pady=10)
        
        self.view_container = ttk.Frame(content_frame, style='TFrame')
        self.view_container.pack(fill='both', expand=True, padx=15, pady=15)
        
        log_frame = ttk.Frame(content_frame, style='Card.TFrame')
        log_frame.pack(fill='x', side='bottom', padx=15, pady=(0, 15))
        
        log_header = ttk.Frame(log_frame, style='Card.TFrame')
        log_header.pack(fill='x')
        ttk.Label(log_header, text="Console Output", style='Card.TLabel', font=(FONT_UI, 9, 'bold')).pack(side='left', padx=10, pady=5)
        ttk.Button(log_header, text="Clear", command=self.clear_log, style='TButton').pack(side='right', padx=5, pady=2)
        
        self.log_box = scrolledtext.ScrolledText(
            log_frame, 
            height=8, 
            bg="#11111b", 
            fg=TEXT_MAIN, 
            font=(FONT_MONO, 9),
            wrap=tk.WORD,
            state='disabled',
            relief='flat',
            padx=10, pady=5
        )
        self.log_box.pack(fill='both', expand=True)
        
        # FIX: Pass self.view_container explicitly when initializing the first tab
        self.show_organizer_tab(self.view_container) 

    def switch_view(self, builder_func):
        for widget in self.view_container.winfo_children():
            widget.destroy()
        # Call the builder function passing the current view container
        builder_func(self.view_container)

    def clear_log(self):
        self.log_box.configure(state='normal')
        self.log_box.delete('1.0', tk.END)
        self.log_box.configure(state='disabled')

    def set_busy(self, busy_text="Lavorando..."):
        self.is_busy = True
        self.status_label.config(text=busy_text, foreground=WARNING)
        self.progress_bar.start(interval=10)

    def set_idle(self):
        self.is_busy = False
        self.status_label.config(text="Pronto", foreground=SUCCESS)
        self.progress_bar.stop()

    def run_async(self, target, args=(), kwargs={}):
        if self.is_busy:
            messagebox.showwarning("Attenzione", "Un'altra operazione è in corso.")
            return
            
        self.set_busy()
        
        def wrapper():
            try:
                target(*args, **kwargs)
            except Exception as e:
                self.logger.log(f"Eccezione non gestita: {e}", "ERROR")
            finally:
                self.after(0, self.set_idle)
                
        self.current_thread = threading.Thread(target=wrapper, daemon=True)
        self.current_thread.start()

    # ----------------------- TAB BUILDERS -----------------------

    def show_organizer_tab(self, parent):
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill='both', expand=True)
        
        ttk.Label(frame, text="Organizzatore Gerarchico Intelligente", style='Header.TLabel').pack(anchor='w', padx=20, pady=(20, 5))
        ttk.Label(frame, text="Raggruppa i file per Categoria e poi per Nome/Data.", style='Subheader.TLabel').pack(anchor='w', padx=20)
        
        controls = ttk.Frame(frame, style='Card.TFrame')
        controls.pack(fill='x', padx=20, pady=20)
        
        # Row 1: Folder Selection
        folder_row = ttk.Frame(controls, style='Card.TFrame')
        folder_row.pack(fill='x', pady=5)
        ttk.Label(folder_row, text="Cartella Sorgente:", style='Card.TLabel', width=15).pack(side='left')
        self.org_dir_var = tk.StringVar(value=os.path.expanduser("~/Downloads"))
        entry = ttk.Entry(folder_row, textvariable=self.org_dir_var, width=40)
        entry.pack(side='left', fill='x', expand=True, padx=10)
        ttk.Button(folder_row, text="Sfoglia...", command=lambda: self.browse_folder(self.org_dir_var)).pack(side='left')
        
        # Row 2: Strategy Selection
        strat_row = ttk.Frame(controls, style='Card.TFrame')
        strat_row.pack(fill='x', pady=10)
        ttk.Label(strat_row, text="Metodo Raggruppamento:", style='Card.TLabel', width=15).pack(side='left')
        
        self.strategy_var = tk.StringVar(value="name")
        strategies = [
            ("Per Nome File (Base)", "name"),
            ("Per Data Modifica (Giorno)", "date"),
            ("Per Anno", "year"),
            ("Solo per Tipo (Standard)", "type")
        ]
        
        combo = ttk.Combobox(strat_row, textvariable=self.strategy_var, values=[s[0] for s in strategies], state='readonly', width=30)
        combo.pack(side='left', padx=10)
        
        # Map display names back to keys
        self.strat_map = {disp: val for disp, val in strategies}
        combo.bind("<<ComboboxSelected>>", lambda e: self._update_strategy_desc())
        
        desc_lbl = ttk.Label(strat_row, text="", style='Subheader.TLabel', foreground=ACCENT)
        desc_lbl.pack(side='left', padx=10)
        self.desc_label = desc_lbl
        self._update_strategy_desc()

        # Action Button
        action_row = ttk.Frame(controls, style='Card.TFrame')
        action_row.pack(fill='x', pady=20)
        ttk.Button(action_row, text="▶ Avvia Organizzazione", command=self.start_smart_organize, style='Success.TButton').pack(side='left')
        ttk.Label(action_row, text="⚠️ Assicurati che la cartella sia vuota o contenga solo file da organizzare.", style='Subheader.TLabel').pack(side='left', padx=15)

    def _update_strategy_desc(self):
        val = self.strategy_var.get()
        descriptions = {
            "name": "Es: Immagini/foto_vacanza/foto_vacanza.jpg",
            "date": "Es: Documenti/2026-11-01/report.pdf",
            "year": "Es: Video/2026/movie.mp4",
            "type": "Es: Audio/song.mp3 (nessuna sottocartella dinamica)"
        }
        self.desc_label.config(text=descriptions.get(val, ""))

    def browse_folder(self, var):
        path = filedialog.askdirectory(initialdir=var.get() if var.get() else "/")
        if path: var.set(path)

    def start_smart_organize(self):
        folder = self.org_dir_var.get()
        if not os.path.exists(folder):
            messagebox.showerror("Errore", "Cartella non trovata.")
            return
        
        # Convert display value to internal key
        selected_display = self.strategy_var.get()
        # Find the key that matches this display
        actual_strategy = "name"
        for disp, val in self.strat_map.items():
            if disp == selected_display:
                actual_strategy = val
                break
        
        self.run_async(smart_organize_folder, args=(folder, actual_strategy, self.logger))

    def show_scanner_tab(self, parent):
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill='both', expand=True)
        
        ttk.Label(frame, text="Scansione Antivirus Euristica", style='Header.TLabel').pack(anchor='w', padx=20, pady=(20, 5))
        ttk.Label(frame, text="Default: Intero Sistema. Può richiedere molto tempo.", style='Subheader.TLabel').pack(anchor='w', padx=20)
        
        input_row = ttk.Frame(frame, style='Card.TFrame')
        input_row.pack(fill='x', padx=20, pady=20)
        
        self.scan_dir_var = tk.StringVar(value=ROOT_DIR)
        entry = ttk.Entry(input_row, textvariable=self.scan_dir_var, width=50)
        entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        ttk.Button(input_row, text="Sfoglia...", command=lambda: self.browse_folder(self.scan_dir_var)).pack(side='left', padx=5)
        ttk.Button(input_row, text="▶ Avvia Scansione Sistema", command=self.start_scan, style='Success.TButton').pack(side='left', padx=5)

    def start_scan(self):
        folder = self.scan_dir_var.get()
        if not os.path.exists(folder):
            messagebox.showerror("Errore", "Cartella non trovata.")
            return
        self.run_async(task_scan_malware, args=(folder, self.logger))

    def show_crypto_tab(self, parent):
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill='both', expand=True)
        
        ttk.Label(frame, text="Crittografia File", style='Header.TLabel').pack(anchor='w', padx=20, pady=(20, 5))
        ttk.Label(frame, text="Usa password forte. Il formato è proprietario SKF2.", style='Subheader.TLabel').pack(anchor='w', padx=20)
        
        form = ttk.Frame(frame, style='Card.TFrame')
        form.pack(fill='x', padx=20, pady=20)
        
        ttk.Label(form, text="File Sorgente:", style='Card.TLabel').grid(row=0, column=0, sticky='w', pady=5)
        self.crypto_src_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.crypto_src_var, width=40).grid(row=0, column=1, sticky='ew', padx=10, pady=5)
        ttk.Button(form, text="Browse", command=lambda: self.browse_file(self.crypto_src_var)).grid(row=0, column=2, pady=5)
        
        ttk.Label(form, text="Password:", style='Card.TLabel').grid(row=1, column=0, sticky='w', pady=5)
        self.crypto_pass_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.crypto_pass_var, show="•", width=40).grid(row=1, column=1, sticky='ew', padx=10, pady=5)
        
        actions = ttk.Frame(form, style='Card.TFrame')
        actions.grid(row=2, column=0, columnspan=3, sticky='w', pady=15)
        ttk.Button(actions, text="🔒 Cifra (.skf)", command=self.do_encrypt).pack(side='left', padx=5)
        ttk.Button(actions, text="🔓 Decifra", command=self.do_decrypt).pack(side='left', padx=5)
        
        form.columnconfigure(1, weight=1)

    def browse_file(self, var):
        path = filedialog.askopenfilename()
        if path: var.set(path)

    def do_encrypt(self):
        src = self.crypto_src_var.get()
        pwd = self.crypto_pass_var.get()
        if not src or not pwd:
            messagebox.showwarning("Input", "Seleziona file e password.")
            return
        dst = src + ".skf"
        
        def task():
            self.logger.log(f"Cifratura {src}...", "INFO")
            try:
                encrypt_file(src, dst, pwd)
                self.logger.log(f"Creato: {dst}", "OK")
            except Exception as e:
                self.logger.log(f"Errore: {e}", "ERROR")
        self.run_async(task)

    def do_decrypt(self):
        src = self.crypto_src_var.get()
        pwd = self.crypto_pass_var.get()
        if not src or not pwd:
            messagebox.showwarning("Input", "Seleziona file .skf e password.")
            return
        if not src.endswith(".skf"):
             messagebox.showwarning("Formato", "Il file deve avere estensione .skf")
             return
             
        dst = src[:-4]
        if os.path.exists(dst):
            if not messagebox.askyesno("Sovrascrivere?", f"Il file {dst} esiste già. Sovrascrivere?"):
                return

        def task():
            self.logger.log(f"Decifratura {src}...", "INFO")
            try:
                decrypt_file(src, dst, pwd)
                self.logger.log(f"Estratto: {dst}", "OK")
            except Exception as e:
                self.logger.log(f"Errore (Password sbagliata?): {e}", "ERROR")
        self.run_async(task)

    def show_dupe_tab(self, parent):
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text="Trova Duplicati", style='Header.TLabel').pack(anchor='w', padx=20, pady=(20, 5))
        ttk.Label(frame, text="Default: Intero Sistema. Molto lento.", style='Subheader.TLabel').pack(anchor='w', padx=20)
        
        input_row = ttk.Frame(frame, style='Card.TFrame')
        input_row.pack(fill='x', padx=20, pady=20)
        self.dupe_dir_var = tk.StringVar(value=ROOT_DIR)
        ttk.Entry(input_row, textvariable=self.dupe_dir_var, width=50).pack(side='left', fill='x', expand=True, padx=(0,10))
        ttk.Button(input_row, text="Sfoglia...", command=lambda: self.browse_folder(self.dupe_dir_var)).pack(side='left', padx=5)
        ttk.Button(input_row, text="▶ Cerca", command=lambda: self.run_async(task_find_duplicates, args=(self.dupe_dir_var.get(), self.logger))).pack(side='left', padx=5)

    def show_secure_tab(self, parent):
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text="Cancellazione Sicura", style='Header.TLabel').pack(anchor='w', padx=20, pady=(20, 5))
        ttk.Label(frame, text="ATTENZIONE: Irreversibile. Non usare sulla Radice (/ o C:\\)!.", style='Subheader.TLabel', foreground=DANGER).pack(anchor='w', padx=20)
        
        input_row = ttk.Frame(frame, style='Card.TFrame')
        input_row.pack(fill='x', padx=20, pady=20)
        self.secure_path_var = tk.StringVar()
        ttk.Entry(input_row, textvariable=self.secure_path_var, width=50).pack(side='left', fill='x', expand=True, padx=(0,10))
        ttk.Button(input_row, text="Scegli File/Cartella", command=lambda: self.pick_secure_target()).pack(side='left', padx=5)
        ttk.Button(input_row, text="⚰️ ELIMINA ORA", command=self.confirm_secure_delete, style='Danger.TButton').pack(side='left', padx=5)

    def pick_secure_target(self):
        path = filedialog.askopenfilename()
        if not path:
            path = filedialog.askdirectory()
        if path:
            self.secure_path_var.set(path)

    def confirm_secure_delete(self):
        path = self.secure_path_var.get()
        if not path: return
        if path == ROOT_DIR:
            messagebox.showerror("Bloccato", "Non puoi eliminare la directory radice del sistema!")
            return
            
        if messagebox.askyesno("Conferma Eliminazione", f"Eliminare definitivamente:\n{path}\n\nQuesta azione NON può essere annullata."):
            self.run_async(task_secure_delete, args=([path], 3, self.logger))

    def show_disk_tab(self, parent):
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text="Analisi Spazio Disco", style='Header.TLabel').pack(anchor='w', padx=20, pady=(20, 5))
        ttk.Label(frame, text="Calcola peso delle sottocartelle. Default: Radice Sistema.", style='Subheader.TLabel').pack(anchor='w', padx=20)
        
        input_row = ttk.Frame(frame, style='Card.TFrame')
        input_row.pack(fill='x', padx=20, pady=20)
        self.disk_dir_var = tk.StringVar(value=ROOT_DIR)
        ttk.Entry(input_row, textvariable=self.disk_dir_var, width=50).pack(side='left', fill='x', expand=True, padx=(0,10))
        ttk.Button(input_row, text="Sfoglia...", command=lambda: self.browse_folder(self.disk_dir_var)).pack(side='left', padx=5)
        ttk.Button(input_row, text="Analizza", command=self.analyze_disk).pack(side='left')

    def analyze_disk(self):
        folder = self.disk_dir_var.get()
        if not os.path.exists(folder): return
        
        def task():
            sizes = {}
            logger = self.logger
            logger.log(f"Calcolo dimensioni per {folder}...", "INFO")
            try:
                for root, dirs, files in os.walk(folder):
                    if os.name != 'nt':
                        if '/proc' in root or '/sys' in root or '/dev' in root: continue
                    s = 0
                    for f in files:
                        try: s += os.path.getsize(os.path.join(root, f))
                        except OSError: pass
                    sizes[root] = s
                
                sorted_items = sorted(sizes.items(), key=lambda x: x[1], reverse=True)
                logger.log("--- Top 10 Cartelle Più Grandi ---", "HEADER")
                for path, size in sorted_items[:10]:
                    logger.log(f"{human_readable(size):>10} : {path}", "INFO")
            except Exception as e:
                logger.log(f"Errore analisi disco: {e}", "ERROR")
                
        self.run_async(task)

    def show_sysinfo_tab(self, parent):
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text="Informazioni Sistema", style='Header.TLabel').pack(anchor='w', padx=20, pady=(20, 5))
        ttk.Button(frame, text="Aggiorna Dati", command=lambda: self.run_async(task_get_system_info, args=(self.logger,))).pack(padx=20, pady=10)

    def show_clean_tab(self, parent):
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text="Pulizia Temporanei", style='Header.TLabel').pack(anchor='w', padx=20, pady=(20, 5))
        
        def clean_temp_task():
            temp_dir = tempfile.gettempdir()
            freed = 0
            count = 0
            self.logger.log(f"Pulizia {temp_dir}...", "INFO")
            for item in os.listdir(temp_dir):
                fp = os.path.join(temp_dir, item)
                if os.path.isfile(fp):
                    try:
                        sz = os.path.getsize(fp)
                        os.remove(fp)
                        freed += sz
                        count += 1
                    except: pass
            self.logger.log(f"Liberati: {human_readable(freed)} ({count} file)", "OK")
            
        ttk.Button(frame, text="🧹 Pulisci Ora", command=lambda: self.run_async(clean_temp_task)).pack(padx=20, pady=10)

    def show_zip_tab(self, parent):
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text="Gestore Archivio ZIP", style='Header.TLabel').pack(anchor='w', padx=20, pady=(20, 5))
        
        create_frm = ttk.LabelFrame(frame, text="Crea Archive", style='Card.TFrame')
        create_frm.pack(fill='x', padx=20, pady=10)
        self.zip_src_var = tk.StringVar()
        self.zip_dst_var = tk.StringVar()
        
        ttk.Label(create_frm, text="Sorgente:", style='Card.TLabel').grid(row=0, col=0, padx=5, pady=5)
        ttk.Entry(create_frm, textvariable=self.zip_src_var, width=30).grid(row=0, col=1, padx=5)
        ttk.Button(create_frm, text="...", command=lambda: self.pick_zip_source()).grid(row=0, col=2)
        
        ttk.Label(create_frm, text="Destinazione:", style='Card.TLabel').grid(row=1, col=0, padx=5, pady=5)
        ttk.Entry(create_frm, textvariable=self.zip_dst_var, width=30).grid(row=1, col=1, padx=5)
        ttk.Button(create_frm, text="Salva Come...", command=lambda: self.save_zip_dest()).grid(row=1, col=2)
        
        ttk.Button(create_frm, text="Comprimi", command=self.create_zip).grid(row=2, col=0, columnspan=3, pady=10)

        extract_frm = ttk.LabelFrame(frame, text="Estrai Archive", style='Card.TFrame')
        extract_frm.pack(fill='x', padx=20, pady=10)
        self.unzip_src_var = tk.StringVar()
        self.unzip_dst_var = tk.StringVar()
        
        ttk.Label(extract_frm, text="Archive ZIP:", style='Card.TLabel').grid(row=0, col=0, padx=5, pady=5)
        ttk.Entry(extract_frm, textvariable=self.unzip_src_var, width=30).grid(row=0, col=1, padx=5)
        ttk.Button(extract_frm, text="...", command=lambda: self.browse_file(self.unzip_src_var)).grid(row=0, col=2)
        
        ttk.Label(extract_frm, text="Cartella Destinazione:", style='Card.TLabel').grid(row=1, col=0, padx=5, pady=5)
        ttk.Entry(extract_frm, textvariable=self.unzip_dst_var, width=30).grid(row=1, col=1, padx=5)
        ttk.Button(extract_frm, text="...", command=lambda: self.browse_folder(self.unzip_dst_var)).grid(row=1, col=2)
        
        ttk.Button(extract_frm, text="Estrai", command=self.extract_zip).grid(row=2, col=0, columnspan=3, pady=10)

    def pick_zip_source(self):
        p = filedialog.askopenfilename() or filedialog.askdirectory()
        if p: self.zip_src_var.set(p)
        
    def save_zip_dest(self):
        p = filedialog.asksaveasfilename(defaultextension=".zip")
        if p: self.zip_dst_var.set(p)
        
    def create_zip(self):
        src = self.zip_src_var.get()
        dst = self.zip_dst_var.get()
        if not src or not dst: return
        
        def task():
            try:
                with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as zf:
                    if os.path.isdir(src):
                        for root, _, files in os.walk(src):
                            for file in files:
                                fp = os.path.join(root, file)
                                arcname = os.path.relpath(fp, src)
                                zf.write(fp, arcname)
                    else:
                        zf.write(src, os.path.basename(src))
                self.logger.log(f"Archivio creato: {dst}", "OK")
            except Exception as e:
                self.logger.log(f"Errore ZIP: {e}", "ERROR")
        self.run_async(task)
        
    def extract_zip(self):
        src = self.unzip_src_var.get()
        dst = self.unzip_dst_var.get()
        if not src or not dst: return
        
        def task():
            try:
                with zipfile.ZipFile(src, 'r') as zf:
                    zf.extractall(dst)
                self.logger.log(f"Estratto in: {dst}", "OK")
            except Exception as e:
                self.logger.log(f"Errore Estrazione: {e}", "ERROR")
        self.run_async(task)


def main():
    app = ModernApp()
    app.mainloop()

if __name__ == "__main__":
    main()
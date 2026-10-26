import os
import sys
import json
import hmac
import time
import shutil
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from tkinter import ttk
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

IS_MAC = sys.platform == "darwin"
APP_NAME = "Vault 1.1 (Mac)" if IS_MAC else "Vault 1.1"
COPY_KEYS = "Cmd+C" if IS_MAC else "Ctrl+C"    # shown in the help texts

# --- where the program lives ----------------------------------------------
def base_dir():
    """The folder the program sits in (vault files next to it are listed)."""
    if getattr(sys, "frozen", False):          # True when running as a built .exe / .app
        exe_dir = os.path.dirname(sys.executable)
        # on a Mac the program is inside "Vault 1.1.app/Contents/MacOS"
        contents = os.path.dirname(exe_dir)
        bundle = os.path.dirname(contents)
        if IS_MAC and os.path.basename(exe_dir) == "MacOS" \
                and os.path.basename(contents) == "Contents" and bundle.endswith(".app"):
            return os.path.dirname(bundle)
        return exe_dir
    return os.path.dirname(os.path.abspath(__file__))

def default_save_dir():
    """Where a new vault is saved unless the user picks another folder."""
    if IS_MAC:
        docs = os.path.expanduser("~/Documents")
        if os.path.isdir(docs):
            return docs
    return base_dir()

def config_dir():
    """Where the recent-files list is kept, the usual place on each system."""
    if IS_MAC:
        return os.path.expanduser("~/Library/Application Support/Vault")
    if os.environ.get("APPDATA"):
        return os.path.join(os.environ["APPDATA"], "Vault")
    return os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "Vault")

def resource_path(name):
    # bundled files (the icon) live in a temp dir when frozen, beside the script otherwise
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)

# The vault in use is picked on the login screen, so these start empty.
VAULT = None
BACKUP = None
file_paths = {}      # name shown in the dropdown -> full path on disk
file_combo = None    # the dropdown widget, set when the login screen is built
CREATE_OPTION = "+ Create new vault..."   # dropdown entry that opens the create window

def set_vault_path(path):
    global VAULT, BACKUP
    VAULT = path
    # the one-step-back backup, named clearly: e.g. "vault (backup).enc"
    stem, ext = os.path.splitext(path)
    BACKUP = stem + " (backup)" + ext

def list_vault_files():
    # every .enc file next to the program, except the automatic backups
    try:
        names = os.listdir(base_dir())
    except OSError:
        return []
    return sorted(n for n in names
                  if n.lower().endswith(".enc") and not n.lower().endswith("(backup).enc"))

# Vaults opened from other folders (e.g. Google Drive) are remembered here, so
# they show up in the dropdown next time. Only file locations are stored.
CONFIG_DIR = config_dir()
RECENT_FILE = os.path.join(CONFIG_DIR, "recent.json")
EXTRA_FILES = []     # files opened this session by double-click or Browse

def load_recent():
    try:
        with open(RECENT_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):       # damaged settings must never stop the app
        return []
    return [p for p in data if isinstance(p, str) and os.path.isfile(p)]

def remember_file(path):
    key_ = os.path.normcase(os.path.abspath(path))
    recent = [p for p in load_recent() if os.path.normcase(os.path.abspath(p)) != key_]
    recent.insert(0, os.path.abspath(path))
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(RECENT_FILE, "w", encoding="utf-8") as f:
            json.dump(recent[:10], f)
    except OSError:
        pass

def display_name(path):
    # files next to the program show just their name, others also their folder
    if os.path.normcase(os.path.dirname(os.path.abspath(path))) == os.path.normcase(base_dir()):
        return os.path.basename(path)
    return os.path.basename(path) + "   (" + os.path.basename(os.path.dirname(path)) + ")"

def refresh_file_list(select=None):
    """Fill the dropdown: most recently used first, then the files next to the
    program, then anything opened this session. `select` picks one by path."""
    global file_paths
    local = [os.path.join(base_dir(), n) for n in list_vault_files()]
    file_paths = {}
    seen = set()
    for p in load_recent() + local + EXTRA_FILES:
        k = os.path.normcase(os.path.abspath(p))
        if k in seen:
            continue
        seen.add(k)
        file_paths.setdefault(display_name(p), p)
    names = list(file_paths)
    file_combo["values"] = names + [CREATE_OPTION]    # "create" is always the last option
    if select and display_name(select) in file_paths:
        file_combo.set(display_name(select))
    elif file_combo.get() not in names:
        file_combo.set(names[0] if names else CREATE_OPTION)

MAGIC = b"PVLT1\n"          # file starts with this so we can recognise our own format
SCRYPT_N = 2 ** 20
IDLE_LOCK_MS = 5 * 60 * 1000   # auto-lock after 5 minutes of no activity
CLIP_CLEAR_MS = 20 * 1000      # wipe a copied password after 20 seconds


# --- clipboard ------------------------------------------------------------
# Copied secrets are marked as private so clipboard history and sync skip them:
#   Windows: the official flags for clipboard history (Win+V) and cloud sync
#   Mac:     the "concealed" / "transient" markers clipboard managers respect
# Tk's own clipboard can't do either, so it is only the fallback.
_MAC_PB = None
if IS_MAC:
    try:
        from AppKit import NSPasteboard, NSPasteboardTypeString
        _MAC_PB = NSPasteboard.generalPasteboard()
    except Exception:          # pyobjc missing: fall back to Tk's clipboard
        _MAC_PB = None

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes
    _u32 = ctypes.WinDLL("user32", use_last_error=True)
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _u32.OpenClipboard.argtypes = [wintypes.HWND]
    _u32.OpenClipboard.restype = wintypes.BOOL
    _u32.CloseClipboard.restype = wintypes.BOOL
    _u32.EmptyClipboard.restype = wintypes.BOOL
    _u32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    _u32.SetClipboardData.restype = wintypes.HANDLE
    _u32.GetClipboardData.argtypes = [wintypes.UINT]
    _u32.GetClipboardData.restype = wintypes.HANDLE
    _u32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    _u32.RegisterClipboardFormatW.restype = wintypes.UINT
    _k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    _k32.GlobalAlloc.restype = wintypes.HGLOBAL
    _k32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    _k32.GlobalLock.restype = ctypes.c_void_p
    _k32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    _k32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    _k32.GlobalFree.restype = wintypes.HGLOBAL
    CF_UNICODETEXT = 13

def _open_clipboard():
    if sys.platform != "win32":
        return False
    for _ in range(10):                  # another program may hold it for a moment
        if _u32.OpenClipboard(None):
            return True
        time.sleep(0.02)
    return False

def _global_bytes(data):
    h = _k32.GlobalAlloc(0x0002, len(data))        # GMEM_MOVEABLE
    if h:
        p = _k32.GlobalLock(h)
        ctypes.memmove(p, data, len(data))
        _k32.GlobalUnlock(h)
    return h

def clipboard_put_private(text):
    """Put text on the clipboard, kept out of clipboard history and cloud sync.
    Returns False if that isn't possible (the caller then uses Tk's clipboard)."""
    if _MAC_PB is not None:
        try:
            _MAC_PB.declareTypes_owner_([NSPasteboardTypeString,
                                         "org.nspasteboard.ConcealedType",
                                         "org.nspasteboard.TransientType"], None)
            _MAC_PB.setString_forType_(text, NSPasteboardTypeString)
            _MAC_PB.setString_forType_("", "org.nspasteboard.ConcealedType")
            _MAC_PB.setString_forType_("", "org.nspasteboard.TransientType")
            return True
        except Exception:
            return False
    if not _open_clipboard():
        return False
    try:
        _u32.EmptyClipboard()
        h = _global_bytes(text.encode("utf-16-le") + b"\0\0")
        if not h or not _u32.SetClipboardData(CF_UNICODETEXT, h):
            if h:
                _k32.GlobalFree(h)
            return False
        for fmt, data in (("ExcludeClipboardContentFromMonitorProcessing", b"\0"),
                          ("CanIncludeInClipboardHistory", b"\0\0\0\0"),
                          ("CanUploadToCloudClipboard", b"\0\0\0\0")):
            h = _global_bytes(data)
            if h and not _u32.SetClipboardData(_u32.RegisterClipboardFormatW(fmt), h):
                _k32.GlobalFree(h)
        return True
    finally:
        _u32.CloseClipboard()

def clipboard_text():
    if _MAC_PB is not None:
        try:
            return _MAC_PB.stringForType_(NSPasteboardTypeString) or ""
        except Exception:
            return None
    if sys.platform != "win32":
        try:
            return root.clipboard_get()
        except tk.TclError:          # clipboard empty or not text
            return ""
    if not _open_clipboard():
        return None
    try:
        h = _u32.GetClipboardData(CF_UNICODETEXT)
        if not h:
            return ""
        p = _k32.GlobalLock(h)
        try:
            return ctypes.wstring_at(p) if p else ""
        finally:
            _k32.GlobalUnlock(h)
    finally:
        _u32.CloseClipboard()

def clipboard_clear_if(text):
    """Empty the clipboard, but only if it still holds `text` - something copied
    from another program in the meantime is left alone."""
    if text is None or clipboard_text() != text:
        return
    if _MAC_PB is not None:
        try:
            _MAC_PB.clearContents()
        except Exception:
            pass
    elif sys.platform != "win32":
        try:
            root.clipboard_clear()
            root.clipboard_append("")
        except tk.TclError:
            pass
    elif _open_clipboard():
        try:
            _u32.EmptyClipboard()
        finally:
            _u32.CloseClipboard()


CLIP = {"secret": None}      # the last password/notes text the app copied

def quit_app():
    clipboard_clear_if(CLIP["secret"])   # never leave a copied password behind
    root.destroy()

root = tk.Tk()
root.title(APP_NAME)
root.geometry("300x180")
root.minsize(300, 180)
try:
    root.iconbitmap(default=resource_path("vault.ico"))   # Windows taskbar / window icon
except Exception:
    pass                       # the Mac uses the .app's own icon instead
root.protocol("WM_DELETE_WINDOW", quit_app)
if IS_MAC:
    root.createcommand("tk::mac::Quit", quit_app)        # Cmd+Q and the menu's Quit

entries = []
key = None
salt = None


# --- crypto ---------------------------------------------------------------
def make_key(password, s):
    kdf = Scrypt(salt=s, length=32, n=SCRYPT_N, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def read_vault():
    """Return (salt, nonce, ciphertext). Raises ValueError on a damaged/short file."""
    with open(VAULT, "rb") as f:
        blob = f.read()
    if blob.startswith(MAGIC):
        blob = blob[len(MAGIC):]
    if len(blob) < 16 + 12 + 16:   # salt + nonce + at least a GCM tag
        raise ValueError("vault file is too short or empty")
    return blob[:16], blob[16:28], blob[28:]


def save_vault(use_key, use_salt):
    """Write safely: temp file, fsync, back up the old vault, then atomically replace.
    A crash or Drive sync mid-write can no longer destroy the real file."""
    nonce = os.urandom(12)
    data = json.dumps(entries).encode("utf-8")
    ciphertext = AESGCM(use_key).encrypt(nonce, data, None)
    payload = MAGIC + use_salt + nonce + ciphertext

    tmp = VAULT + ".tmp"
    with open(tmp, "wb") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())

    if os.path.exists(VAULT):                 # keep one rolling backup
        try:
            shutil.copy2(VAULT, BACKUP)
        except OSError:
            pass
    os.replace(tmp, VAULT)                     # atomic on the same drive


def clean_entries(data):
    """Check that decrypted contents look like a list of entries. Returns the
    list with every field as text, or None. Nothing is dropped, because the next
    save would otherwise delete it for good."""
    if not isinstance(data, list) or not all(isinstance(e, dict) for e in data):
        return None
    out = []
    for e in data:
        e = dict(e)
        for f in ("name", "username", "password", "notes"):
            v = e.get(f)
            e[f] = "" if v is None else (v if isinstance(v, str) else str(v))
        out.append(e)
    return out


def weak_password_ok(parent, pw):
    """True if we may use this password. Warns (but allows) short ones."""
    if len(pw) >= 12:
        return True
    return messagebox.askyesno(
        "Weak password",
        "A short password is the single biggest weakness of this vault.\n"
        "A copied vault file can be guessed offline very fast.\n\n"
        "Use a long passphrase instead (e.g. four random words).\n"
        "Continue with this one anyway?",
        parent=parent)


def show_instead_of(parent, dlg):
    """Open `dlg` in place of `parent`: the parent hides, the dialog appears where
    it was, and the parent comes back when the dialog closes. So only one window
    is ever on screen."""
    parent.update_idletasks()
    x, y = parent.winfo_x(), parent.winfo_y()
    parent.withdraw()
    dlg.geometry("+%d+%d" % (max(x, 0), max(y, 0)))
    dlg.lift()
    dlg.focus_force()
    dlg.wait_window()
    if parent.winfo_exists():        # it is gone if the vault auto-locked meanwhile
        parent.deiconify()


# --- add / edit form ------------------------------------------------------
def entry_dialog(parent, title, entry=None):
    dlg = tk.Toplevel(parent)
    dlg.title(title)
    dlg.resizable(False, False)

    fields = {}
    rows = [("name", "Name:"), ("username", "Username:"), ("password", "Password:")]
    for row, (field, text) in enumerate(rows):
        tk.Label(dlg, text=text).grid(row=row, column=0, sticky="e", padx=10, pady=5)
        box = tk.Entry(dlg, width=35, show="•" if field == "password" else "")
        box.grid(row=row, column=1, padx=10, pady=5)
        if entry:
            box.insert(0, entry.get(field, ""))
        fields[field] = box

    dlg_show = tk.BooleanVar()
    def dlg_toggle():
        fields["password"].config(show="" if dlg_show.get() else "•")
    tk.Checkbutton(dlg, text="Show password", variable=dlg_show,
                   command=dlg_toggle).grid(row=3, column=1, sticky="w", padx=10)

    # free-text notes (multi-line)
    tk.Label(dlg, text="Notes:").grid(row=4, column=0, sticky="ne", padx=10, pady=5)
    notes_box = tk.Text(dlg, width=35, height=6, wrap="word")
    notes_box.grid(row=4, column=1, padx=10, pady=5)
    if entry:
        notes_box.insert("1.0", entry.get("notes", ""))

    result = {}
    def ok():
        if not fields["name"].get().strip():
            messagebox.showwarning(title, "Name can't be empty", parent=dlg)
            return
        for field, box in fields.items():
            result[field] = box.get()
        result["notes"] = notes_box.get("1.0", "end-1c")   # drop the trailing newline
        dlg.destroy()

    bar = tk.Frame(dlg)
    bar.grid(row=5, column=0, columnspan=2, pady=10)
    tk.Button(bar, text="OK", width=10, command=ok).pack(side="left", padx=5)
    tk.Button(bar, text="Cancel", width=10, command=dlg.destroy).pack(side="left", padx=5)

    fields["name"].focus_set()
    show_instead_of(parent, dlg)
    return result or None


# --- change master password ----------------------------------------------
def change_master_dialog(parent):
    dlg = tk.Toplevel(parent)
    dlg.title("Change master password")
    dlg.resizable(False, False)

    boxes = []
    for row, text in enumerate(["Current password:", "New password:", "New password again:"]):
        tk.Label(dlg, text=text).grid(row=row, column=0, sticky="e", padx=10, pady=5)
        box = tk.Entry(dlg, width=30, show="•")
        box.grid(row=row, column=1, padx=10, pady=5)
        boxes.append(box)

    def ok():
        global key, salt
        current, new, again = (b.get() for b in boxes)

        if not hmac.compare_digest(make_key(current, salt), key):
            messagebox.showerror("Error", "Current password is wrong", parent=dlg)
            return
        if not new:
            messagebox.showerror("Error", "New password can't be empty", parent=dlg)
            return
        if new != again:
            messagebox.showerror("Error", "The new passwords don't match", parent=dlg)
            return
        if not weak_password_ok(dlg, new):
            return

        new_salt = os.urandom(16)
        new_key = make_key(new, new_salt)
        try:
            save_vault(new_key, new_salt)
        except OSError as err:
            messagebox.showerror("Error", "Could not save the vault:\n" + str(err), parent=dlg)
            return
        key, salt = new_key, new_salt
        # The backup still holds the vault locked with the OLD password. Replace
        # it, otherwise whoever knew the old password could still open the backup.
        try:
            shutil.copy2(VAULT, BACKUP)
        except OSError:
            try:
                os.remove(BACKUP)
            except OSError:
                pass
        messagebox.showinfo("Done",
                            "Master password changed.\nTell everyone the new one in person.",
                            parent=dlg)
        dlg.destroy()

    bar = tk.Frame(dlg)
    bar.grid(row=3, column=0, columnspan=2, pady=10)
    tk.Button(bar, text="Change", width=10, command=ok).pack(side="left", padx=5)
    tk.Button(bar, text="Cancel", width=10, command=dlg.destroy).pack(side="left", padx=5)

    boxes[0].focus_set()
    show_instead_of(parent, dlg)


# --- the main list window -------------------------------------------------
def open_list():
    win = tk.Toplevel(root)
    win.title(APP_NAME + " - Passwords")
    win.geometry("640x540")
    win.protocol("WM_DELETE_WINDOW", quit_app)

    # --- search by name ---------------------------------------------------
    search_bar = tk.Frame(win)
    search_bar.pack(fill="x", padx=10, pady=(10, 0))
    tk.Label(search_bar, text="Search name:").pack(side="left")
    search_var = tk.StringVar()
    search_entry = tk.Entry(search_bar, textvariable=search_var)
    search_entry.pack(side="left", fill="x", expand=True, padx=6)
    tk.Button(search_bar, text="Clear",
              command=lambda: search_var.set("")).pack(side="left")
    search_var.trace_add("write", lambda *a: refresh())

    table = ttk.Treeview(win, columns=("name", "username", "password"), show="headings")
    table.heading("name", text="Name")
    table.heading("username", text="Username")
    table.heading("password", text="Password")
    table.pack(fill="both", expand=True, padx=10, pady=10)

    # --- notes: read-only but selectable; shows the picked entry's notes ---
    notes_frame = tk.LabelFrame(win, text="Notes  (select text and press " + COPY_KEYS + " to copy)")
    notes_frame.pack(fill="x", padx=10, pady=(0, 6))
    notes_box = tk.Text(notes_frame, height=6, wrap="word")
    notes_box.pack(fill="x", padx=4, pady=4)

    def block_edit(event):
        ctrl = event.state & (0x0008 if IS_MAC else 0x0004)    # Cmd on a Mac, Ctrl elsewhere
        if ctrl and event.keysym.lower() in ("c", "a", "insert"):
            return                      # allow copy and select-all
        if not ctrl and event.keysym in ("Left", "Right", "Up", "Down", "Home",
                                          "End", "Prior", "Next", "Shift_L",
                                          "Shift_R", "Control_L", "Control_R"):
            return                      # allow selecting with the keyboard
        return "break"                  # block anything that would edit the text
    notes_box.bind("<Key>", block_edit)

    def copy_notes_selection(_event=None):
        try:
            text = notes_box.get("sel.first", "sel.last")
        except tk.TclError:             # nothing selected
            return "break"
        copy_value(text, auto_clear=True)
        return "break"
    notes_box.bind("<<Copy>>", copy_notes_selection)

    def update_notes(_event=None):
        sel = table.selection()
        text = entries[int(sel[0])].get("notes", "") if sel else ""
        notes_box.delete("1.0", "end")
        notes_box.insert("1.0", text)
    table.bind("<<TreeviewSelect>>", update_notes)

    lock_timer = {"id": None}

    def lock():
        global entries, key, salt
        entries = []
        key = None
        salt = None
        clipboard_clear_if(CLIP["secret"])
        win.destroy()
        refresh_file_list(select=VAULT)    # back to the login, same file picked
        root.deiconify()

    def reset_idle(_event=None):
        if lock_timer["id"] is not None:
            win.after_cancel(lock_timer["id"])
        lock_timer["id"] = win.after(IDLE_LOCK_MS, lock)

    for ev in ("<Key>", "<Button>", "<Motion>"):
        win.bind(ev, reset_idle)
    reset_idle()

    def copy_value(value, auto_clear):
        if not clipboard_put_private(value):
            win.clipboard_clear()               # not Windows: plain Tk clipboard
            win.clipboard_append(value)
        if auto_clear:
            CLIP["secret"] = value
            # wiped after 20 s, unless something else was copied in the meantime
            win.after(CLIP_CLEAR_MS, lambda: clipboard_clear_if(value))

    def refresh():
        query = search_var.get().strip().lower()
        table.delete(*table.get_children())
        for i, e in enumerate(entries):
            # iid stays the real index in `entries`, so Copy/Edit/Delete still
            # point at the right entry even when the list is filtered
            if query in e["name"].lower():
                table.insert("", "end", iid=str(i),
                             values=(e["name"], e["username"], "••••••"))
        update_notes()        # selection is cleared, so this empties the notes box

    def selected_index(action):
        selected = table.selection()
        if not selected:
            messagebox.showwarning(action, "Click an entry first", parent=win)
            return None
        return int(selected[0])

    def save():
        try:
            save_vault(key, salt)
        except OSError as err:
            messagebox.showerror("Error", "Could not save the vault:\n" + str(err), parent=win)

    def copy_pw():
        i = selected_index("Copy")
        if i is not None:
            copy_value(entries[i]["password"], auto_clear=True)

    def copy_user():
        i = selected_index("Copy")
        if i is not None:
            copy_value(entries[i]["username"], auto_clear=False)

    def add_entry():
        new = entry_dialog(win, "Add entry")
        if new:
            entries.append(new)
            save()
            refresh()

    def edit_entry():
        i = selected_index("Edit")
        if i is None:
            return
        new = entry_dialog(win, "Edit entry", entries[i])
        if new:
            entries[i].update(new)
            save()
            refresh()

    def delete_entry():
        i = selected_index("Delete")
        if i is None:
            return
        if messagebox.askyesno("Delete", 'Delete "' + entries[i]["name"] + '"?', parent=win):
            del entries[i]
            save()
            refresh()

    def show_help():
        messagebox.showinfo(
            "How to use " + APP_NAME,
            "Add       - store a new name / username / password\n"
            "Edit      - change the selected entry\n"
            "Delete    - remove the selected entry\n"
            "Copy      - put the username or password on the clipboard\n"
            "            (a copied password is wiped after 20 seconds)\n"
            "Notes     - the box under the list shows the selected entry's\n"
            "            notes; select text there and press " + COPY_KEYS + " to copy part\n"
            "Lock now  - lock the vault immediately\n\n"
            "The vault locks itself after 5 minutes of no activity.\n"
            "Every change is saved straight away.\n\n"
            "There is no password recovery. If the master password is lost,\n"
            "the passwords cannot be recovered. Keep a backup of the vault file.",
            parent=win)

    bar = tk.Frame(win)
    bar.pack(pady=5)
    tk.Button(bar, text="Copy username", command=copy_user).pack(side="left", padx=4)
    tk.Button(bar, text="Copy password", command=copy_pw).pack(side="left", padx=4)
    tk.Button(bar, text="Add", command=add_entry).pack(side="left", padx=4)
    tk.Button(bar, text="Edit", command=edit_entry).pack(side="left", padx=4)
    tk.Button(bar, text="Delete", command=delete_entry).pack(side="left", padx=4)
    tk.Button(bar, text="Lock now", command=lock).pack(side="left", padx=4)
    tk.Button(bar, text="Change master password",
              command=lambda: change_master_dialog(win)).pack(side="left", padx=4)
    tk.Button(bar, text="Help", command=show_help).pack(side="left", padx=4)

    refresh()


# --- create a new vault ---------------------------------------------------
def create_vault_dialog(parent):
    """Ask for a name, a folder and a master password, and create the vault.
    Shown in place of `parent`. Returns the new vault's path, or None on Cancel."""
    dlg = tk.Toplevel(parent)
    dlg.title("Create new vault")
    dlg.resizable(False, False)

    info = (
        "Everything in a vault is locked with one master password.\n\n"
        "• There is no reset and no recovery. If you forget it, the\n"
        "  passwords in this vault are gone for good.\n"
        "• Use a long passphrase, e.g. copper-village-lantern-dusk.\n"
        "• Keep a backup copy of the vault file somewhere safe."
    )
    tk.Label(dlg, text=info, justify="left").grid(
        row=0, column=0, columnspan=3, sticky="w", padx=12, pady=(12, 8))

    tk.Label(dlg, text="Vault name:").grid(row=1, column=0, sticky="e", padx=10, pady=4)
    name_box = tk.Entry(dlg, width=30)
    name_box.grid(row=1, column=1, columnspan=2, sticky="w", padx=10, pady=4)

    folder = {"path": default_save_dir()}
    tk.Label(dlg, text="Save in:").grid(row=2, column=0, sticky="e", padx=10, pady=4)
    folder_label = tk.Label(dlg, text=folder["path"], width=30, anchor="w")
    folder_label.grid(row=2, column=1, sticky="w", padx=10, pady=4)
    def pick_folder():
        chosen = filedialog.askdirectory(parent=dlg, initialdir=folder["path"],
                                         title="Where should the vault file go?")
        if chosen:
            folder["path"] = os.path.normpath(chosen)
            folder_label.config(text=folder["path"])
    tk.Button(dlg, text="Change...", command=pick_folder).grid(row=2, column=2, padx=(0, 10))

    tk.Label(dlg, text="Master password:").grid(row=3, column=0, sticky="e", padx=10, pady=4)
    pw1 = tk.Entry(dlg, show="•", width=30)
    pw1.grid(row=3, column=1, columnspan=2, sticky="w", padx=10, pady=4)
    tk.Label(dlg, text="Repeat password:").grid(row=4, column=0, sticky="e", padx=10, pady=4)
    pw2 = tk.Entry(dlg, show="•", width=30)
    pw2.grid(row=4, column=1, columnspan=2, sticky="w", padx=10, pady=4)

    show_var = tk.BooleanVar()
    def toggle_show():
        s = "" if show_var.get() else "•"
        pw1.config(show=s)
        pw2.config(show=s)
    tk.Checkbutton(dlg, text="Show password", variable=show_var,
                   command=toggle_show).grid(row=5, column=1, sticky="w", padx=10)

    created = {"path": None}

    def create():
        global entries
        name = name_box.get().strip()
        if name.lower().endswith(".enc"):
            name = name[:-4].strip()
        if not name:
            messagebox.showwarning(APP_NAME, "Give the vault a name", parent=dlg)
            return
        if any(c in name for c in '<>:"/\\|?*') or name.lower().endswith("(backup)"):
            messagebox.showwarning(APP_NAME,
                                   'The name can\'t contain < > : " / \\ | ? *\n'
                                   'or end with "(backup)".', parent=dlg)
            return
        path = os.path.join(folder["path"], name + ".enc")
        if os.path.exists(path):
            messagebox.showwarning(APP_NAME,
                                   'A vault called "' + name + '" already exists there.\n'
                                   "Pick another name, or unlock it from the list.", parent=dlg)
            return

        p1, p2 = pw1.get(), pw2.get()
        if not p1:
            messagebox.showwarning(APP_NAME, "Password can't be empty", parent=dlg)
            return
        if p1 != p2:
            messagebox.showwarning(APP_NAME, "The two passwords don't match", parent=dlg)
            return
        if not weak_password_ok(dlg, p1):
            return

        # write an empty vault; it is opened from the login screen like any other
        set_vault_path(path)
        entries = []
        new_salt = os.urandom(16)
        try:
            save_vault(make_key(p1, new_salt), new_salt)
        except OSError as err:
            messagebox.showerror("Error", "Could not create the vault:\n" + str(err), parent=dlg)
            return

        remember_file(path)
        created["path"] = path
        dlg.destroy()

    bar = tk.Frame(dlg)
    bar.grid(row=6, column=0, columnspan=3, pady=12)
    tk.Button(bar, text="Create vault", width=12, command=create).pack(side="left", padx=5)
    tk.Button(bar, text="Cancel", width=12, command=dlg.destroy).pack(side="left", padx=5)

    name_box.focus_set()
    show_instead_of(parent, dlg)
    return created["path"]


# --- login screen ---------------------------------------------------------
def build_login_screen():
    """Build the login screen. Returns the function that opens the create window."""
    global file_combo
    root.geometry("380x270")
    root.minsize(380, 270)

    tk.Label(root, text=APP_NAME, font=("Segoe UI", 14, "bold")).pack(pady=(14, 2))
    status = tk.Label(root, text="", fg="#1a7f37", justify="center")
    status.pack()

    last = {"name": ""}      # what was picked before the dropdown was opened
    def remember_choice():
        if file_combo.get() != CREATE_OPTION:
            last["name"] = file_combo.get()

    tk.Label(root, text="Vault file:").pack(pady=(4, 0))
    file_row = tk.Frame(root)
    file_row.pack(padx=16, pady=(2, 8))
    file_combo = ttk.Combobox(file_row, state="readonly", width=34, postcommand=remember_choice)
    file_combo.pack(side="left")

    def browse():
        path = filedialog.askopenfilename(parent=root, title="Open a vault file",
                                          filetypes=[("Vault files", "*.enc"), ("All files", "*.*")])
        if path:
            path = os.path.normpath(path)
            EXTRA_FILES.append(path)
            refresh_file_list(select=path)
            status.config(text="")
            pw_box.focus_set()
    tk.Button(file_row, text="Browse...", command=browse).pack(side="left", padx=(6, 0))

    tk.Label(root, text="Master password:").pack()
    pw_box = tk.Entry(root, show="•", width=40)
    pw_box.pack(padx=16, pady=2)

    show_var = tk.BooleanVar()
    def toggle_show():
        pw_box.config(show="" if show_var.get() else "•")
    tk.Checkbutton(root, text="Show password", variable=show_var,
                   command=toggle_show).pack(pady=2)

    def open_create():
        status.config(text="")
        # don't leave "Create new vault" showing in the box behind the dialog
        if last["name"] in file_combo["values"]:
            file_combo.set(last["name"])
        path = create_vault_dialog(root)
        if path:
            refresh_file_list(select=path)
            status.config(text='Vault "' + os.path.splitext(os.path.basename(path))[0]
                               + '" created. Enter its password to open it.')
        remember_choice()
        pw_box.focus_set()

    def on_pick(_event=None):
        if file_combo.get() == CREATE_OPTION:
            open_create()
        else:
            status.config(text="")
            pw_box.focus_set()
    file_combo.bind("<<ComboboxSelected>>", on_pick)

    def do_unlock():
        global entries, key, salt
        name = file_combo.get()
        if not name or name == CREATE_OPTION:
            open_create()
            return
        status.config(text="")
        set_vault_path(file_paths[name])

        try:
            salt, nonce, ciphertext = read_vault()
        except FileNotFoundError:
            messagebox.showerror("Error", "That vault file is no longer there:\n" + VAULT)
            refresh_file_list()
            return
        except (ValueError, OSError) as err:
            messagebox.showerror("Error", "The vault file looks damaged:\n" + str(err))
            return

        key = make_key(pw_box.get(), salt)
        pw_box.delete(0, tk.END)

        try:
            data = AESGCM(key).decrypt(nonce, ciphertext, None)
        except InvalidTag:
            key = None
            messagebox.showerror("Error", "Wrong password (or the file was damaged)")
            return

        try:
            loaded = clean_entries(json.loads(data.decode("utf-8")))
        except (ValueError, UnicodeDecodeError):
            loaded = None
        if loaded is None:
            key = None
            messagebox.showerror("Error", "The vault opened but its contents are unreadable.")
            return
        entries = loaded

        remember_file(VAULT)
        root.withdraw()
        open_list()

    pw_box.bind("<Return>", lambda e: do_unlock())
    tk.Button(root, text="Unlock", width=14, command=do_unlock).pack(pady=(6, 12))

    pw_box.focus_set()
    return open_create


# --- start up -------------------------------------------------------------
open_create = build_login_screen()
opened = os.path.normpath(sys.argv[1]) if len(sys.argv) > 1 else None   # double-clicked file
if opened:
    EXTRA_FILES.append(opened)
refresh_file_list(select=opened)
if not file_paths:
    # nothing to unlock yet, so go straight to creating the first vault
    root.after(200, open_create)

root.mainloop()

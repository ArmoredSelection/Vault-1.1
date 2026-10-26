# Building Vault 1.1 into a Windows .exe

## 1. Install the tools (once)
```
pip install -r requirements.txt
```

## 2. Build
Run this from the `source` folder (where `window.py` and `vault.ico` are):
```
pyinstaller --onefile --windowed --name "Vault 1.1" --icon vault.ico --add-data "vault.ico;." window.py
```
- `--onefile`   : one single `Vault 1.1.exe` (easier to hand out)
- `--windowed`  : no black console window behind the GUI
- `--name`      : what the .exe is called
- `--icon`      : the logo shown on the .exe file and taskbar
- `--add-data`  : bundles the icon so the running window shows it too

The finished program appears at `dist\Vault 1.1.exe`.

## 3. How the .exe finds vaults
The login screen's "Vault file" list is filled from:
1. vaults used recently (their locations are kept in
   `%APPDATA%\Vault\recent.json`; no passwords or contents are stored there),
2. every `*.enc` file next to the .exe (automatic `(backup).enc` copies are
   left out), and
3. a vault passed on the command line (what a double-click on an `.enc` file
   does once the file type is associated) or picked with "Browse...".

If no vault is found at all, the "Create new vault" window opens by itself.

## 4. IMPORTANT — where to put the .exe (security)
Do **NOT** put `Vault 1.1.exe` in the shared Google Drive folder next to the
vaults. Anyone who can write to that folder could replace it with a fake copy
that steals the master password when a coworker types it.

- Give each person the .exe through a channel only you control.
- Only the **encrypted .enc vault files** belong in Google Drive.

## 5. Expected warnings (normal)
- Windows SmartScreen: "Windows protected your PC" -> More info -> Run anyway.
  (Happens because the .exe is not signed by a registered company.)
- Some antivirus flags PyInstaller .exe files by mistake. To avoid this for a
  real rollout, consider code-signing the .exe with a certificate.

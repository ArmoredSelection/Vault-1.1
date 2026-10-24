============================================================
  Vault 1.1  -  encrypted password vault
============================================================

WHAT IT IS
  A small program that keeps passwords in encrypted vault files
  (*.enc). A vault file is useless to anyone without its master
  password, so it is safe to keep in shared cloud storage such as
  Google Drive. You can have several vaults, each with its own
  master password.

OPENING A VAULT
  1. Pick the vault in the "Vault file" list.
     The list shows the vaults you used recently and any .enc
     files next to the program. Use "Browse..." to open one from
     somewhere else (e.g. your Google Drive folder) - after that
     it stays in the list.
  2. Type its master password and press Enter or "Unlock".

CREATING A VAULT
  Open the "Vault file" list and pick "+ Create new vault..." (the
  last option). Give it a name, choose where to save it and set the
  master password. You then return to the login screen with the new
  vault picked - type its password to open it. The first time you
  start Vault 1.1 with no vaults around, this opens by itself.

  Choose a LONG passphrase, for example four random words
  (copper-village-lantern-dusk). The master password is the only
  way in - there is no reset and no recovery.

INSIDE A VAULT
    Search name          - filter the list by name
    Add / Edit / Delete  - manage entries (each has a Notes box)
    Copy username / password - puts the value on the clipboard
                               (a copied password is wiped after 20s)
    Notes box            - shows the selected entry's notes; select
                           text there and press Ctrl+C to copy it
    Lock now             - lock and go back to the vault list
    Change master password
    Help                 - this summary
  The vault locks itself after 5 minutes of no activity, and every
  change is saved straight away. A one-step-back copy is kept as
  "<name> (backup).enc" next to the vault.

WHERE TO PUT THE FILES (IMPORTANT)
  - Put "Vault 1.1.exe" somewhere only the administrator controls and
    hand it to each person directly.
  - Do NOT put the .exe in the shared Drive folder next to the vaults.
    Someone could replace it with a fake that steals master
    passwords. Only the .enc files belong in shared storage.

BACKUP
  Keep a copy of each vault file somewhere outside the cloud folder
  (a USB stick, another drive). A damaged or deleted vault file
  cannot be opened by anyone, including you.

WINDOWS WARNINGS (NORMAL)
  SmartScreen may say "Windows protected your PC" -> More info ->
  Run anyway. The .exe is not signed by a registered company.
============================================================

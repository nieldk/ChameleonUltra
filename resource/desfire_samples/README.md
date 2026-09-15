# DESFire sample credentials

Test files for DESFire EV1, EV2, and EV3 credential formats. Load one with either front end:

    hf des eload -f resource/desfire_samples/01_ev1_stddata.dfc

or import it in the GUI's saved-cards view and drop it on a slot.

| File | Generation & Storage | Contents & Application Setup |
|---|---|---|
| `01_ev1_stddata.dfc` | EV1 (2 KB) | Baseline configuration. **App `000001`** (AES auth mode) containing 1 Standard Data file (32 B allocated, partial data `DE AD BE EF`). Access rights `EEEE` allow free access without prior authentication. |
| `02_ev1_value_backup.dfc` | EV1 (4 KB) | **App `F51001`** (D40 auth mode) containing 2 files: a Value file (Current value: 1000, Limits: 0–100000) and a Backup Data file (16 B, fully populated). |
| `03_ev2_records.dfc` | EV2 (4 KB) | **App `000002`** (ISO 3K3DES auth mode, 24-byte key) containing 1 Linear Record file (Record Size: 16 B, Max: 8 records, 2 records present). |
| `04_ev3_multiapp.dfc` | EV3 (8 KB) | Multi-application setup with 2 apps: **App `000001`** (AES mode, 1 Standard Data file with encrypted communication settings `03`) and **App `F51001`** (D40 mode, 1 Standard Data file holding `CA FE BA BE 00 00 00 00`). |
| `05_blank_ev1.dfc` | EV1 (2 KB) | Blank/unformatted card representation with 0 applications, 0 PICC files, and factory default PICC Master Key (`00`s). |

> **Security Note:** Keys inside `.dfc` files are stored in plaintext. Always treat real credential files as sensitive secrets.

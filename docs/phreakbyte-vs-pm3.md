# Phreakbyte ChameleonUltra Fork vs Proxmark3 (Iceman)

> **Use only on cards/systems you own or are authorized to test.** See
> [Legal / responsible use](../README.md#legal--responsible-use) in the
> top-level README.

The two devices overlap heavily on RFID auditing workflows but sit on
different RF architectures, so "parity" is stated per task as **Full**,
**Partial**, or **N/A** with the reason, not as a percentage. Where the
Phreakbyte fork matches Proxmark3 it is on **commands, workflows, and file
formats**, not on the raw-RF layer (see Bottom line).

| Feature / Capability | Phreakbyte ChameleonUltra Fork | Proxmark3 (Iceman) | Parity |
|---|---|---|---|
| **File interoperability** | PM3 `mfc v2`/`mfdes v1` JSON, `.eml`, `.dic`, `.key`, `.dfc`, `.dfcb`, `.trace` (import/export, no device needed). | Native, and a wider set (EMV JSON, `.mct`, iCESERE, etc.). | **Full for MFC/DESFire dumps + keys + traces.** PM3 supports more container types overall. |
| **Card identification (`hf 14a info`)** | Deep scan: UID/ATQA/SAK/ATS, SAK-based type guess, MIFARE Classic+PRNG detect, Gen1A/2/3 magic probes, "what to run next" recommendation. | `hf 14a info` identifies the tag and prints detected features/fingerprint. | **Full.** Comparable identify, plus guided next-step hints. |
| **MIFARE Classic recovery** | Full attack chain: check-keys, darkside, nested, hardnested, static-nested, autopwn (chains + resumes + dumps to slot/JSON). Emulation-side key capture via mfkey32/64. | Full recovery suite (darkside, nested, hardnested, staticnested, autopwn, sim+mfkey). | **Full.** Same algorithms, same workflow. |
| **MIFARE Classic magic cards** | Gen1A full backdoor suite (`hf mf c*`), no keys needed, plus Gen1A/Gen2 emulation and clone. Gen3 UID/block-0 write, permanent UID lock. Gen4-GTU full password-gated block/UID/password/config read-write. Gen4-GDM config and public-block get/set, wakeup auto-detect across gen1a/GDM-alt/WUPA styles. `identify_magic_gen` distinguishes all four generations. Hidden blocks, signature, UID-set, wipe, and config field-level flags not yet implemented. | Gen1A/Gen2/Gen3/Gen4 (ultimate magic / GTU and GDM) read, write, and config, including GDM hidden blocks and signature. | **Full for Gen1A–Gen4-GTU. Partial for Gen4-GDM:** core config/block read-write and all three wakeup styles are implemented. |
| **MIFARE Plus** | SL1 emulation on the same Classic core. SL0→SL3 personalization (`WritePerso`/`CommitPerso`), per-sector AES keys plus admin keys, SL0 gating enforced both ways. SL3: `AuthenticateFirst`/`AuthenticateNonFirst`, CMAC-verified AES-CBC `ReadBlock`/`WriteBlock`, `GetVersion`, keyed per-sector. Protocol cross-checked against RRG proxmark3's `mifare4.c`/`cmdhfmfp.c`. | Full SL0–SL3 including personalization, hardnested on SL1, non-first auth, and broader SL3 secure-messaging coverage. | **Full.** SL0-SL3.Hidden blocks, signature, and UID-set/wipe aren't implemented yet. |
| **DESFire** | EV1/EV2 emulation (DES/2TDEA/3TDEA/AES), key-version semantics, v6 credential format, PM3-compatible dump/keys. Reader-side: info, AID/file enumeration, key check, ISO 7816 auth, `auth-trace`. | Full read/enumerate/auth/key-dictionary, plus EV3 features (SDM/LRP, originality signatures). | **Partial.** No EV3 (SDM/LRP/originality) and no signature emulation: gated on purpose, not zero-filled. |
| **MIFARE Ultralight / NTAG** | Full read/write (pages, counters, signature, version), NDEF read/write, dump/eload/esave, UL-C key gen, PWD/PACK detection logging. | Full UL/NTAG suite plus tearoff/glitch attacks. | **Partial.** Protocol/workflow full; tearoff needs precise power glitching the CU hardware cannot do. |
| **Other HF protocols** | SEOS (eload/keys), ST25TA (NDEF read/write, access-rights config), EMV APDU scan/relay, ISO14443-4 (T=CL) raw/APDU passthrough. | Full, plus iCLASS/PICOPASS, FeliCa, Legic, Topaz, ISO15693, and more. | **Partial.** CU covers the common auditing set; PM3 covers more HF families. ISO15693 is N/A (hardware; see below). |
| **Low Frequency (LF)** | 125 kHz (EM410x, HID Prox, ioProx, PAC, Viking, Jablotron: read+emulate; Indala, IDTECK: read + T55xx only) and 134.2 kHz FDX-B (read only). Full T55xx toolset (detect/read/write/wipe/dump/restore/chk/bruteforce/config/protect/recoverpw), PM3-compatible dumps. Passive LF sniff. | Full 125/134.2 kHz decode, raw modulation synthesis, T55xx, and a larger LF protocol set. | **Partial.** Common tags covered; PM3 decodes more and synthesizes arbitrary LF waveforms. |
| **Raw RF capture & DSP** | Frame/bit-level HF capture via the MFRC522; some LF raw/`--adc` sampling. No HF raw-sample capture or arbitrary waveform synthesis. | FPGA + ADC: raw sample-level capture, sample-level sniffing, arbitrary modulation synthesis, antenna tuning. | **N/A (hardware).** The Ultra's HF path is a MFRC522 reader IC (framing/decoded frames) plus the nRF52840 NFC peripheral for emulation: there is no ADC/FPGA to pull raw sample windows from. Sample-level RF work and ISO15693 (needs a different reader IC) are out of scope. |
| **Sniffing & relaying** | Passive (`hf 14a sniff --tap`) and active (`hf 14a sniff`) HF sniff via the MFRC522, exact-slot nonce tracking, PM3 `.trace` export/import. LF sniff. Live T=CL/EMV relay (`emv apdu`) and standalone `relay` mode with WTX handling. | Sample-level FPGA sniffing and interactive card/reader relay, incl. MIFARE Classic relay over a low-latency link. | **Full.** Frame-level HF sniffing via the MFRC522. |
| **Field portability & emulation** | 8 HF + 8 LF slots, host-less standalone modes (`authtrace`, `emul-trace`, `hf14a-tap-sniff`, `relay`, `slot-cycle`, `autoclone`, `dict_check`, `read-replay`), BLE 5.0, battery powered, pocketable. | Powerful but typically tethered; more limited standalone/emulation profile. | **CU advantage.** This is where the ChameleonUltra clearly wins. |

## Bottom line

For **everyday RFID auditing**, cracking and cloning MIFARE Classic,
emulating and key-handling DESFire EV1/EV2 and MIFARE Plus, common LF tags,
protocol-level sniffing and relaying, and moving dumps and traces to/from a
Proxmark3, the Phreakbyte fork gives you **command, workflow, and
file-format parity** in a battery-powered, multi-slot, standalone pocket
device.

The real, unavoidable difference is the **RF front end**. Proxmark3 pairs an
FPGA with an ADC, so it can capture and synthesize raw RF at the sample
level. The ChameleonUltra
handles HF two ways: the nRF52840's built-in NFC peripheral for card
**emulation**, and a dedicated **MFRC522** reader IC for HF **read, write,
and sniffing** (passive and active), the MFRC522 is what the Ultra and
DevKit have and the Lite does not.


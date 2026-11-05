# Abim Guard

*Formerly Bimbo Guard. The app was renamed Abim Guard, after the developer's name Abimbola. Old links to the project still work, and settings, rules and quarantine from the old version are carried over automatically.*

[![Build](https://github.com/ladiran/Abim_Guard/actions/workflows/build.yml/badge.svg)](https://github.com/ladiran/Abim_Guard/actions/workflows/build.yml) [![Microsoft Store](https://img.shields.io/badge/Microsoft%20Store-Get%20Abim%20Guard-0078D4)](https://apps.microsoft.com/detail/9NK2W2GCF37Q)

A companion malware scanner for Windows 10 and 11. It runs **alongside Microsoft Defender**, not in place of it, and adds a second set of eyes on the places malware usually lands.

## What it does

| Feature | How it works |
|---|---|
| Pattern detection | YARA-X rules (VirusTotal's Rust engine). 13 bundled rules, plus any `.yar` files you add |
| Known-bad hashes | SHA-256 list you can grow from MalwareBazaar or any text/CSV/zip feed |
| Heuristics | Double extensions (`invoice.pdf.exe`), hidden right-to-left filename tricks, programs disguised as documents, packed executables |
| Real-time watch | Downloads and Desktop by default, plus any USB drive you plug in. Files are checked about 2 seconds after they are saved |
| Second opinion | Each detection is re-checked with Defender's own scanner (`MpCmdRun.exe -DisableRemediation`), so you see whether Defender agrees |
| Quarantine | Malicious files are moved, scrambled so they cannot run, and can be restored |
| Startup audit | Registry Run keys, Startup folders, Winlogon and scheduled tasks, flagged for common persistence tricks |
| Defender health | Warns you if Defender's real-time protection has been switched off |
| USB ports | Counts the computer's physical USB sockets, shows which are USB 3.x, USB 2.0 or USB-C, which are in use and which are free, and what is plugged into each. Updates every 2 seconds and logs every plug and unplug |
| System tray | Keeps protecting in the background when the window is closed. The shield icon by the clock opens the app, pauses or resumes protection, or quits |
| Camera & microphone | Shows, within about a second, any program that switches on the camera or microphone, whether or not it was given permission, and announces it with a small tray notification (marked "trusted" for apps you trust). Warns when the program has no visible window, runs from a temporary folder, or is flagged by the scanner |

Severity levels: **Malicious** (auto-quarantined), **Test file** (EICAR, auto-quarantined), **Suspicious** and **Unwanted (PUA)** (reported only, you decide).

## Getting started

**Easiest: get it from the Microsoft Store.** [Abim Guard on the Microsoft Store](https://apps.microsoft.com/detail/9NK2W2GCF37Q) is free, signed by Microsoft (no SmartScreen warning) and updates automatically.

Or download it from GitHub:

1. Download `abim-guard.exe` (and, for terminal use, `abim-guard-cli.exe`) from the [latest release](https://github.com/ladiran/Abim_Guard/releases/latest), keep them in the same folder, and double-click `abim-guard.exe`. `SHA256SUMS.txt` on the release page lets you check the files are exactly what GitHub built. Windows SmartScreen may say "Windows protected your PC" because the program is not code-signed yet. Click **More info**, then **Run anyway**.
2. The Overview page shows Defender's status and starts real-time protection.
3. Click **Quick scan** for a first check.
4. Optional: Settings, then tick **Open Abim Guard minimised when I sign in**.

No installer and no administrator rights are needed. Data lives in `%LOCALAPPDATA%\AbimGuard` (rules, quarantine, logs, settings).

## Testing it safely

Use the industry-standard EICAR test file, which is harmless text that every antivirus treats as a "virus" by agreement:

```
abim-guard-cli.exe eicar C:\Users\Public\eicar.com
abim-guard-cli.exe scan C:\Users\Public --no-quarantine
```

Microsoft Defender will probably grab the file first. That is expected and shows Defender is working. To test Abim Guard on its own, add `C:\Users\Public\eicar.com` as a temporary exclusion in Windows Security, then remove the exclusion afterwards.

## Command line

Use **`abim-guard-cli.exe`** in Command Prompt or PowerShell. It shares the engine with the app but prints normally and returns proper exit codes, so it also works in scripts.

```
abim-guard-cli scan <path>...        scan files or folders (exit code 1 if anything found)
abim-guard-cli quick                 quick scan
abim-guard-cli startup               startup audit
abim-guard-cli status                Defender and engine status
abim-guard-cli quarantine list | restore <id> | delete <id>
abim-guard-cli import-hashes <file>  add SHA-256 hashes (txt, csv or zip)
abim-guard-cli usb                   USB ports: count, type, in use / free, devices
abim-guard-cli camera-mic            programs using the camera or microphone now, plus history
abim-guard-cli monitor               live USB and camera/microphone events (Ctrl+C to stop)
```

## Keeping detections current

The bundled rules catch well-known patterns, not new malware families. To stay current:

* **Hash feed:** create a free account at abuse.ch, get an Auth-Key, copy your MalwareBazaar SHA-256 export link into Settings, and press **Download feed now**. The recent export is regenerated every few minutes and covers the last 48 hours; do not fetch more often than that.
* **Rules:** drop `.yar` files into the rules folder (Settings, then **Open rules folder**) and press **Reload rules**. A broken file is skipped and reported instead of stopping the app.

## How the USB and camera/microphone watch works

**USB.** Windows lists every port on every USB hub. A USB 3 socket appears twice (a USB 2 lane and a SuperSpeed lane) and Windows links the pair, so Abim Guard merges them and counts each socket once. Ports wired inside the case (webcam, Bluetooth, fingerprint reader) are reported separately as "internal". Windows says whether a port is USB-C, but it does not distinguish full-size Type-A from Mini or Micro, so non-C ports are shown as "Type-A or other". Whether a port counts as built-in or internal comes from the computer's firmware, which is occasionally wrong.

**Camera and microphone.** Windows records every app that opens the camera or microphone (the same record behind its privacy indicator). An app that is using a device right now has a start time but no stop time. Abim Guard reads this every second. Pop-ups can be switched off per app with **Trust this app**; use is still logged in History.

## Honest limits

* It runs in user mode. It cannot block a program before it starts, protect itself from malware running as administrator, or see inside memory. That kernel-level work is what Defender does, so keep Defender on.
* Camera and microphone monitoring relies on Windows' own usage record. Malware with its own kernel driver could bypass it.
* Detection is only as good as its rules and hashes. Treat it as an extra layer.
* The GitHub downloads are not code-signed, so SmartScreen warns on first run. The [Microsoft Store version](https://apps.microsoft.com/detail/9NK2W2GCF37Q) is signed by Microsoft.

## Building from source

Written in Rust. Every push is built and tested on Windows by GitHub Actions, and when a release is published on the Releases page, GitHub builds both programs from this source and attaches them to it.

On Windows: install Rust from https://rustup.rs, then in this folder:

```
cargo build --release
```

The programs appear at `target\release\abim-guard.exe` (the app) and `target\release\abim-guard-cli.exe` (terminal commands). (The icon and version details are embedded with the `winresource` crate, which uses the Windows SDK's `rc.exe` or MinGW's `windres`.)

## Project layout

```
src/main.rs        the windowed program (abim-guard.exe)
src/bin/           the terminal program (abim-guard-cli.exe)
src/lib.rs         shared start-up code and terminal commands
src/engine.rs      detection engine: YARA-X, hashes, heuristics
src/scan.rs        multi-threaded folder scans
src/watcher.rs     real-time folder and USB watching
src/quarantine.rs  quarantine and restore
src/startup.rs     startup audit
src/usb.rs         USB port inventory and change tracking
src/av.rs          camera and microphone use
src/devmon.rs      live USB and camera/microphone monitor
src/system.rs      Defender, drives, alerts, downloads
src/gui.rs         desktop window
rules/core.yar     bundled detection rules
```

## Microsoft Store version

Abim Guard is published on the [Microsoft Store](https://apps.microsoft.com/detail/9NK2W2GCF37Q). The same code is packaged for it (`packaging/msix/`). The Store version keeps its data in its own package folder, starts at sign-in through Windows' startup settings (**Settings > Apps > Startup**), and is signed by Microsoft. Submission steps, listing text and test instructions are in [docs/microsoft-store.md](docs/microsoft-store.md).

## Code signing policy

Release programs are built from this repository's source by GitHub Actions on Windows (see `.github/workflows/build.yml`) and published on the [Releases](https://github.com/ladiran/Abim_Guard/releases) page together with `SHA256SUMS.txt`. Signing of release builds through the [SignPath Foundation](https://signpath.org) programme has been requested; until it is approved, release files are unsigned.

**Team roles**

| Role | Member |
|---|---|
| Author (committer) | [Oladiran Johnson Abimbola](https://github.com/ladiran) |
| Reviewer | [Oladiran Johnson Abimbola](https://github.com/ladiran) |
| Approver (approves every release for signing) | [Oladiran Johnson Abimbola](https://github.com/ladiran) |

* All team accounts use multi-factor authentication.
* Anthropic's Claude (an AI assistant) helps write code. It has no account or access of its own: every change it drafts arrives as a pull request that the reviewer reads and merges, and every release is approved by the approver.
* Only programs built automatically from this repository's source are released.

## Privacy

Abim Guard does not transfer any information to other networked systems unless specifically requested by the user. Its only network access is downloading a malware hash list, and only when the user presses **Download feed now** with a feed address they entered. The camera and microphone record, USB device list, scan results and logs stay on the computer, in `%LOCALAPPDATA%\AbimGuard`.

## Developer

**Oladiran Johnson Abimbola**
Department of Physics, Faculty of Physical Sciences, Federal University of Lafia
abimbola.oladiran@science.fulafia.edu.ng

Anthropic's Claude was used to assist in building this application.

Licence: MIT. Copyright (c) 2026 Oladiran Johnson Abimbola.

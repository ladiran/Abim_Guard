# Bimbo Guard

[![Build](https://github.com/ladiran/Bimbo_Guard/actions/workflows/build.yml/badge.svg)](https://github.com/ladiran/Bimbo_Guard/actions/workflows/build.yml)

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
| Camera & microphone | Shows, within about a second, any program that switches on the camera or microphone, whether or not it was given permission. Warns when the program has no visible window, runs from a temporary folder, or is flagged by the scanner |

Severity levels: **Malicious** (auto-quarantined), **Test file** (EICAR, auto-quarantined), **Suspicious** and **Unwanted (PUA)** (reported only, you decide).

## Getting started

1. Download `bimbo-guard.exe` from the [latest release](https://github.com/ladiran/Bimbo_Guard/releases/latest) and double-click it. Windows SmartScreen may say "Windows protected your PC" because the program is not code-signed yet. Click **More info**, then **Run anyway**.
2. The Overview page shows Defender's status and starts real-time protection.
3. Click **Quick scan** for a first check.
4. Optional: Settings, then tick **Open Bimbo Guard minimised when I sign in**.

No installer and no administrator rights are needed. Data lives in `%LOCALAPPDATA%\BimboGuard` (rules, quarantine, logs, settings).

## Testing it safely

Use the industry-standard EICAR test file, which is harmless text that every antivirus treats as a "virus" by agreement:

```
bimbo-guard.exe eicar C:\Users\Public\eicar.com
bimbo-guard.exe scan C:\Users\Public --no-quarantine
```

Microsoft Defender will probably grab the file first. That is expected and shows Defender is working. To test Bimbo Guard on its own, add `C:\Users\Public\eicar_test` as a temporary exclusion in Windows Security, then remove the exclusion afterwards.

## Command line

```
bimbo-guard scan <path>...        scan files or folders (exit code 1 if anything found)
bimbo-guard quick                 quick scan
bimbo-guard startup               startup audit
bimbo-guard status                Defender and engine status
bimbo-guard quarantine list | restore <id> | delete <id>
bimbo-guard import-hashes <file>  add SHA-256 hashes (txt, csv or zip)
bimbo-guard usb                   USB ports: count, type, in use / free, devices
bimbo-guard camera-mic            programs using the camera or microphone now, plus history
bimbo-guard monitor               live USB and camera/microphone events (Ctrl+C to stop)
```

## Keeping detections current

The bundled rules catch well-known patterns, not new malware families. To stay current:

* **Hash feed:** create a free account at abuse.ch, get an Auth-Key, copy your MalwareBazaar SHA-256 export link into Settings, and press **Download feed now**. The recent export is regenerated every few minutes and covers the last 48 hours; do not fetch more often than that.
* **Rules:** drop `.yar` files into the rules folder (Settings, then **Open rules folder**) and press **Reload rules**. A broken file is skipped and reported instead of stopping the app.

## How the USB and camera/microphone watch works

**USB.** Windows lists every port on every USB hub. A USB 3 socket appears twice (a USB 2 lane and a SuperSpeed lane) and Windows links the pair, so Bimbo Guard merges them and counts each socket once. Ports wired inside the case (webcam, Bluetooth, fingerprint reader) are reported separately as "internal". Windows says whether a port is USB-C, but it does not distinguish full-size Type-A from Mini or Micro, so non-C ports are shown as "Type-A or other". Whether a port counts as built-in or internal comes from the computer's firmware, which is occasionally wrong.

**Camera and microphone.** Windows records every app that opens the camera or microphone (the same record behind its privacy indicator). An app that is using a device right now has a start time but no stop time. Bimbo Guard reads this every second. Pop-ups can be switched off per app with **Trust this app**; use is still logged in History.

## Honest limits

* It runs in user mode. It cannot block a program before it starts, protect itself from malware running as administrator, or see inside memory. That kernel-level work is what Defender does, so keep Defender on.
* Camera and microphone monitoring relies on Windows' own usage record. Malware with its own kernel driver could bypass it.
* Detection is only as good as its rules and hashes. Treat it as an extra layer.
* Before giving it to others, plan to **code-sign** the .exe (otherwise SmartScreen warns every user) and to test on a few machines.

## Building from source

Written in Rust. Every push is built and tested on Windows by GitHub Actions, and each tagged version (`v*`) is published on the Releases page with the .exe built by GitHub from this source.

On Windows: install Rust from https://rustup.rs, then in this folder:

```
cargo build --release
```

The program appears at `target\release\bimbo-guard.exe`. (The icon and version details are embedded with the `winresource` crate, which uses the Windows SDK's `rc.exe` or MinGW's `windres`.)

## Project layout

```
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

## Developer

**Oladiran Johnson Abimbola**
Department of Physics, Faculty of Physical Sciences, Federal University of Lafia
abimbola.oladiran@science.fulafia.edu.ng

Anthropic's Claude was used to assist in building this application.

Licence: MIT. Copyright (c) 2026 Oladiran Johnson Abimbola.

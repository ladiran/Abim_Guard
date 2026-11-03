# Publishing Abim Guard on the Microsoft Store

Everything needed for the Partner Center submission, ready to copy.

## 1. Connect the package to your Store listing (once)

In Partner Center, open **Abim Guard > Product management > Product identity** and copy three values into the repository's Actions variables (**Settings > Secrets and variables > Actions > Variables > New repository variable**):

| Variable name | Copy from Partner Center |
|---|---|
| `MSIX_IDENTITY_NAME` | Package/Identity/Name |
| `MSIX_PUBLISHER` | Package/Identity/Publisher (starts with `CN=`) |
| `MSIX_PUBLISHER_DISPLAY_NAME` | Package/Properties/PublisherDisplayName |

These are not secret. Every build after that produces a Store-ready package in the **abim-guard-microsoft-store** artifact: `AbimGuard_<version>_x64.msix`. Upload that file in the submission's **Packages** step. You do not sign it; Microsoft signs it when it is published.

## 2. Test the package on your own PC first (optional, recommended)

1. Windows **Settings > System > For developers**: turn on **Developer Mode**.
2. Download the **abim-guard-microsoft-store** artifact from the build and unzip it.
3. In PowerShell, inside the unzipped folder:
   ```powershell
   Add-AppxPackage -Register .\msix-layout\AppxManifest.xml
   ```
4. Start **Abim Guard** from the Start menu and check: the tray icon, a camera notification, and **Settings > Start Abim Guard in the system tray when I sign in** (it should then appear under Windows **Settings > Apps > Startup**).
5. Remove the test copy afterwards: **Settings > Apps > Installed apps > Abim Guard > Uninstall**.

## 3. Store listing (Properties and Store listing pages)

**Category:** Security (if unavailable: Utilities & tools)

**Privacy policy URL:** https://github.com/ladiran/Abim_Guard#privacy

**Website:** https://github.com/ladiran/Abim_Guard

**Support contact:** abimbola.oladiran@science.fulafia.edu.ng

**Short description** (shown in search results):

> A free second layer of protection that works alongside Microsoft Defender, with live alerts when any app turns on your camera or microphone.

**Description:**

> Abim Guard is a free, open-source companion scanner for Windows that works alongside Microsoft Defender. It does not replace Defender; it adds a second set of eyes on the places threats usually arrive and tells you clearly what is happening on your computer.
>
> What it does:
> • Scans files with malware detection rules, known-bad file fingerprints and checks for disguised files such as "invoice.pdf.exe"
> • Watches your Downloads and Desktop, and any USB drive you plug in, and checks new files within seconds
> • Moves dangerous files into a safe quarantine that you can review and restore
> • Asks Microsoft Defender for a second opinion on every detection
> • Shows how many USB ports your computer has, which are USB 2.0, USB 3 or USB-C, which are in use, and what is plugged into each
> • Notifies you whenever any app turns on your camera or microphone, and warns you when it is a hidden background program
> • Lists programs that start automatically with Windows and flags suspicious ones
> • Runs quietly in the system tray
>
> Everything stays on your computer. Abim Guard does not send your files, camera or microphone information, or scan results anywhere.
>
> Developed by Oladiran Johnson Abimbola, Department of Physics, Federal University of Lafia, Nigeria. Anthropic's Claude was used to assist in building this application. Source code: https://github.com/ladiran/Abim_Guard

**Search terms** (up to 7): antivirus, malware scanner, USB security, camera privacy, microphone privacy, Defender companion, quarantine

**Screenshots:** at least one, 1366×768 or larger, of the real app on your PC. Good choices: the Overview page, the USB ports page, and the Camera & mic page showing a notification.

**Age rating questionnaire:** the app has no user-to-user communication, no purchases, no violence or mature content.

## 4. Notes for certification (Submission options > Notes for certification)

Copy this so the reviewers understand why a security tool reads this information:

> Abim Guard is an open-source (MIT) companion malware scanner that runs alongside Microsoft Defender; it never disables or replaces Defender. Source: https://github.com/ladiran/Abim_Guard. Every package is built from that source by GitHub Actions.
>
> runFullTrust: required because this is a desktop security tool that must read files in user folders and on removable drives to scan them, and query USB hubs for its port report.
>
> Behaviours reviewers may notice, all user-facing and documented in the app:
> • Reads HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore (read-only) to tell the user which app is using the camera or microphone. It never accesses the camera or microphone itself.
> • Reads USB hub information through the standard Windows USB IOCTLs (read-only) for the USB port report.
> • Runs Microsoft Defender's MpCmdRun.exe with -DisableRemediation to get a second opinion on a detection; no settings are changed.
> • Runs powershell.exe Get-MpComputerStatus and Get-ScheduledTask (read-only) for the Defender status and startup audit.
> • Uses curl.exe only when the user presses "Download feed now" with a hash-list address they entered.
> • Quarantine moves a detected file into the app's own data folder, scrambled; the user can restore or delete it.
> • Starting at sign-in uses the manifest startup task (off by default, enabled only when the user ticks the option).
> • Notifications are standard tray notifications and respect Windows notification settings.
>
> To test detection safely, use the industry-standard EICAR test file: run "abim-guard-cli eicar C:\Users\Public\eicar.com" (Defender may remove it first, which is expected).
> No account, sign-in, purchase or network service is required.

### Restricted capability (runFullTrust)

When the package is uploaded, Partner Center warns that `runFullTrust` needs approval. That is normal for every desktop (Win32) app. On the **Submission options** page, under **Restricted capabilities**, paste:

> Abim Guard is a classic Win32 desktop application (Rust, packaged as MSIX), not a UWP app, so it needs runFullTrust to run at all. As a companion malware scanner it must read files in the user's folders and on USB drives to scan them, query USB hub information for its port report, read the camera and microphone usage records in the registry to alert the user, and start Microsoft Defender's MpCmdRun.exe for a second opinion. It never disables Defender and sends no data off the device. Source code: https://github.com/ladiran/Abim_Guard

## 5. Pricing and availability

Free, all markets. No in-app purchases.

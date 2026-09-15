---
title: "Hiding in plain batch: Inside the SAMA Multi-Stage XWorm Loader C2"
date: 2026-09-15 09:00:00 +0300
categories: [Malware Analysis, Loaders]
tags: [xworm, dll-side-loading, batch-loader, powershell, fileless, dotnet, static-analysis, threat-intelligence, sigma, yara]
image:
  path: /assets/img/sama-xworm-multistage-loader-analysis/cover.png
  alt: SAMA.zip multi-stage loader analysis
---

## Executive Summary

This analysis looks at a malicious archive, `SAMA.zip`, that delivers a multi-stage Windows infostealer/RAT. The lure is built around **"SAMA Customer services"** — SAMA being the acronym of the Saudi Central Bank — and both the payload naming and a Saudi-hosted command-and-control server point to a campaign aimed at Saudi users.

The archive follows a pattern that keeps coming back in modern crimeware: a **legitimately signed binary, a side-loaded malicious DLL, and a huge obfuscated batch loader** all shipped together. Each piece has a job. The signed executable gives the chain a trusted face, the DLL rides in on that trust through search-order hijacking, and the batch file carries the real payload — encrypted, encoded, and reassembled entirely at runtime so that almost nothing malicious is visible on disk.

When the chain runs it ends in **fileless, in-memory execution** of a VB.NET payload family the author branded **"SAMA" / "SAMAClient101"**, whose capabilities (screen and webcam capture, synthetic input, sockets, AES crypto, WMI/registry recon) line up with an infostealer / remote-access trojan. A crowdsourced Snort rule classified the live traffic as an **XWorm-variant infostealer C2**, beaconing to **`130.94.59.139:7000/TCP`**, hosted in Saudi Arabia.

In this part we walk the three archive members and go deep on the batch loader, which turned out to be the most interesting component: a self-decoding, self-verifying, seven-module in-memory loader that the author internally calls **"KARMO."**

## Key Findings

- Signed **`AdobeARM.exe`** (clean) + fake-Microsoft **`SensApi.dll`** (malicious) = a classic DLL side-loading pair.
- The **~933 KB `.bat`** is a full **file-less multi-stage loader** that stores its own encrypted payloads inside itself and uses **environment variables as a pointer table** between stages.
- Final payloads are VB.NET assemblies internally named **`SAMA-Kbat.exe` / `SAMA-K2.exe`** ("SAMAClient101"), injected fileless into living-off-the-land processes.
- **C2:** `130.94.59.139:7000/TCP` (LightNode, ASN 154177, country **SA**); Snort labelled the traffic **XWorm**.
- Persistence via **HKCU Run** keys and a **hidden scheduled task**, executed through the signed `conhost.exe --headless` LOLBin.

## Sample Information (Archive)

| Field | Value |
|---|---|
| Filename | `SAMA.zip` |
| File type | ZIP archive (deflate) |
| Size | 2,183,399 bytes |
| MD5 | `e7d8372fc39a1739692d9c9395e59eed` |
| SHA-1 | `62c51e37214c9a1a61c7b7c3851170d243903061` |
| SHA-256 | `6745899253115a295a86554127264a1d76e24f4aa2d6f2879e7284b1538b53ad` |
| First submission | 2026-09-09 12:32:59 UTC |
| Detections | 22 / 68 (VT) |
| Suggested label | `trojan.draftor/alien` |

The three members share build/submission timestamps clustered around **27 Aug – 9 Sep 2026**, consistent with a single, freshly assembled campaign.

| Role | File | SHA-256 | Verdict |
|---|---|---|---|
| Trusted host | `AdobeARM.exe` | `69469a3b…b3eed` | **Clean / signed — do not block** |
| Side-loaded DLL | `SensApi.dll` | `766fe987…268a` | Malicious (21/71) |
| Loader | `SAMA-Kbat_0909267uvr09-09.bat` | `94407c72…2d73` | Malicious (5/63) |

## The Delivery Chain at a Glance

Before we take the members apart individually, here is how they fit together when the archive is detonated as a whole:

```
SAMA.zip
 ├─ AdobeARM.exe   (signed, clean)  ──►  side-loads  SensApi.dll   [DLL search-order hijack]
 └─ SAMA-Kbat_…​.bat  ──►  reassembles PowerShell stages from itself
                                    ──►  decrypts + verifies 7 embedded modules
                                    ──►  runs them fileless in-memory
                                    ──►  injects the VB.NET "SAMA" payload into LOLBins
                                    ──►  beacon to 130.94.59.139:7000  (XWorm C2)
```

Two independent execution paths (the side-loading pair and the batch loader) converge on the same fileless .NET payload and the same persistence artifacts.

---

## 1. AdobeARM.exe — The Trusted Host

`AdobeARM.exe` is a **genuine, Adobe-signed** executable — the real Adobe Reader / Acrobat Manager updater, with an intact Authenticode chain. It is **not malicious**, and the whole point of including it is exactly that: it is a clean, widely-distributed binary that no reputation engine will flag.

### Threat Intelligence (facts only)

| Field | Value |
|---|---|
| SHA-256 | `69469a3b807d8751966a3d6cd78f17c8b368a6760718805997e751e3ab2b3eed` |
| MD5 | `89a8351928db28453ff500562ec1d059` |
| Type | PE32 EXE (GUI), 32-bit |
| Product | Adobe Reader and Acrobat Manager, v1.824.460.1180 |
| Signature | Signed & verified — **Adobe Inc.** (DigiCert Trusted G4 Code Signing), valid 2025-10-06 → 2027-10-05 |
| Detections | **0 / 70** (clean) |
| Sandbox verdict | Zenbox: CLEAN (99% confidence) |

The trick lives in its import table: `AdobeARM.exe` legitimately imports `IsNetworkAlive` from `SensApi.dll`. When Windows resolves that import it searches the application's own directory first, so an attacker-supplied `SensApi.dll` sitting next to the Adobe binary gets loaded in place of the real system DLL. Nothing in `AdobeARM.exe` is patched or tampered with — the binary is abused purely by placement.

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-01.png)

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-02.png)

**Do not block this hash.** `AdobeARM.exe` is a clean, legitimately-signed Adobe binary that exists on millions of endpoints. Detection must focus on *where* it loads `SensApi.dll` from, not on the executable itself.
{: .prompt-warning }

We keep this section shallow on purpose — the loader is a trusted vehicle, not the malware. The interesting components are the next two.

---

## 2. SensApi.dll — The Side-Loaded Trojan

This is the DLL that `AdobeARM.exe` is tricked into loading. It **impersonates the Microsoft "SENS Connectivity API DLL"** — it carries fake Microsoft version metadata but is unsigned and is not a real Microsoft file. It exports the same three symbols as the genuine `SensApi.dll` (`IsDestinationReachableA/W`, `IsNetworkAlive`) so that the Adobe host resolves its imports cleanly and never notices the swap.

### Malware Analysis

The genuine Microsoft `SensApi.dll` beside the attacker's copy, note the 32-bit header, the 2026 compile stamp and the extra sections in the copy:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-03.png)

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-04.png)

Section and resource layout — the non-standard `.fptable` section and roughly 2 MB of high-entropy `RT_RCDATA` split into 262,144-byte blobs:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-05.png)

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-06.png)

Imports — 93 implicit `KERNEL32.dll` entries and nothing else; every other API is resolved by hand at runtime:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-07.png)

bcrypt.dll being pulled in by name inside the signed host process — the load that comes just before the resource is decrypted:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-30.png)

The embedded resource coming apart in the debugger — `BCryptDecrypt` called on the high-entropy blob, and the decrypted buffer in memory:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-08.png)

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-09.png)

Capabilities flagged at runtime by the API-signature plugin — resource extraction, process creation, mutex, registry, thread and memory operations:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-10.png)

Mutex handling — the rule hit first, then the live `CreateMutexW` call with the name `Local\CC7CE79A6BD9423F`:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-11.png)

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-12.png)

Registry reconnaissance APIs:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-13.png)

Resource extraction — the `FindResourceW` signature, the matching rule hit, and the breakpoints firing in the live process:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-14.png)

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-15.png)

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-16.png)

Runtime API resolution through `GetProcAddress`:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-17.png)

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-18.png)

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-19.png)

The host process the DLL lands in, with PowerShell as its child:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-20.png)

### Threat Intelligence

| Field | Value |
|---|---|
| SHA-256 | `766fe987b73f77d3e4fb5ca07aa5392993451d3cefdda293ba92443e1a6f268a` |
| MD5 | `7b5b6bc88ae1886d6e228d1d48e5cc72` |
| Type | PE32 DLL (GUI), 32-bit, MSVC 2022 (v17.6) |
| Masquerade | Claims **"SENS Connectivity API DLL", "© Microsoft Corporation", 10.0.19041.1** — but unsigned and not a real Microsoft binary |
| Exports | `IsDestinationReachableA`, `IsDestinationReachableW`, `IsNetworkAlive` |
| Detections | **21 / 71** malicious |
| Suggested label | `trojan.draftor/abrisk` |

Pestudio's VirusTotal view for the copy we analysed — 32-bit DLL, `SENS Connectivity` version metadata, no certificate:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-21.png)

What the intelligence sources confirm about this file:

- **Masquerading (T1036)** by name and metadata, plus **DLL side-loading (T1574)** as its execution method. Two separate Sigma rules — *"Potential System DLL Sideloading From Non System Locations"* and *"Unsigned DLL Loaded by RunDLL32/RegSvr32"* — fired on this exact hash when it was loaded from a `\Temp\` path.
- The `.rsrc` section is roughly **2 MB of high-entropy `RT_RCDATA`** (entropy ≈ 8.0), which is where the encrypted payload/config is carried; a non-standard `.fptable` section was flagged as packing.
- `capa` reports Base64 + XOR + ADD/XOR/SUB custom encoding, **runtime API resolution** via `GetProcAddress`, **PE-header parsing / section enumeration** (self-unpacking / reflective-load behaviour), mutex handling, file read/write/copy, and environment/privilege queries.
- In a **standalone** detonation (renamed `init.dll`, run via `rundll32 …,#1`) the DLL read its own image, resolved APIs from unbacked memory, and then crashed under WerFault — i.e. it is built to run as part of the full chain, not on its own.
- Its own contacted infrastructure in isolation was limited to a **`162.159.36.2:53/UDP`** Cloudflare DNS lookup. The malicious C2 beacon (§ below) appears only in the full-archive detonation, not from this member alone.
---

## 3. SAMA-Kbat_0909267uvr09-09.bat — The Multi-Stage Loader

This is the heart of the archive, and where we spent most of our time. It is a **933 KB batch file** — and despite the `.bat` extension, calling it a "batch downloader" would badly undersell it. There is no download. The file **is** the dropper *and* the encrypted container for everything it runs.

### 3.1 Malware Analysis

#### Sample identity

| Property | Value |
|---|---|
| SHA-256 | `94407c7291a95e6e5e49d54aa998cf034e2fb0d0d5af8778900034decf872d73` |
| MD5 | `43b042834190a2d015e2d6af5efa5b2a` |
| Size | 933,110 bytes |
| Type | DOS batch, ASCII, CRLF, 380 lines (up to ~6,000 chars/line) |
| Internal family name | **"KARMO"** (self-named via `KARMO_DEBUG`, `KARMO_HANDOFF_DETACH`, `KARMO_PE_*` variables) |

The filename on disk is its own SHA-256 — the tell-tale sign of a hash-named sample pulled from a sandbox, USB, or AV quarantine.

#### How it hides: obfuscation

The batch script is built to be unreadable by a human and unmatchable by a signature. A few techniques do most of the work:

- **String splicing.** Every meaningful string is assembled at runtime from 2-character slices of longer decoy strings. For example `SystemRoot` is never written literally — it's stitched together from a junk variable:

  ```bat
  set "DSWY=mG6hSystEaQgemF9nXcRSBr3xoo_8Dtglh"
  set "REIKN=!DSWY:~4,4!!DSWY:~12,2!!DSWY:~19,1!!DSWY:~25,2!!DSWY:~30,1!"   ->  SystemRoot
  ```

- **Variable-name indirection.** The *name* of the next variable to read is itself the result of a splice, so you can't just grep for a variable — you have to resolve the pointer first.
- **A `findstr` self-read.** The script searches its **own file** for marker lines and executes them, so the payload lines are never reached by normal top-to-bottom flow: `for /f … in ('findstr /c:"&rem XVTVLGKQPI" "%~f0"') do %%A`.
- **An inert data section after `exit /b 0`.** The encrypted module blobs are stored as `set "PREFIX<payload>"` lines *with no `=` sign*, so `cmd.exe` can never actually assign them. They exist purely as data for the PowerShell stages to read back by prefix. The batch is padded with **65 junk comment lines and hundreds of decoy variables** to bury them.

The most elegant trick is the **environment-variable pointer table**: the PowerShell loader stages don't contain the decryption key or even the data — they contain the *name of the variable* that holds the key, and the *name of the variable* that holds the data. The batch repoints those two names before each round, and the same tiny loader decodes a completely different stage each time.

#### The execution chain

Reduced to plain language, the chain runs like this:

1. **Batch bootstrap** resolves the path to `powershell.exe` (with a WOW64 `sysnative` fallback) and pulls the first blob out of itself with the `findstr` trick.
2. **PowerShell is launched once** and asked to run two script blocks straight from environment variables — nothing touches disk:
   ```
   powershell -NoProfile -Command "&(NewScriptBlock $env:OQQXIIA);&(NewScriptBlock $env:MWBREA)"
   ```
3. **Stage 1** re-reads the batch file, finds its blob, hex-decodes it and subtracts a key (**101**) to produce a small generic **XOR loader**.
4. **Stage 2** is that reusable XOR loader. Guided by the pointer table it decodes, in turn: a **guard stub** (single-instance mutex + console hiding), a **re-spawner** that relaunches PowerShell with `CREATE_BREAKAWAY_FROM_JOB` to escape sandbox job-objects, and finally the **module-extractor**.
5. **The module-extractor** reads all the embedded blobs, checks each one's length and SHA-256 against the manifest, and hands control to the orchestrator — all in-process, in the current runspace.
6. **The BOOT orchestrator** scrubs the environment down to a 30-name allow-list (erasing its own breadcrumbs), does an **anti-sandbox process sweep**, decrypts every module, and runs the host module.
7. **The host module** disables AMSI, rebuilds a custom **in-memory .NET assembly** with `Reflection.Emit` (never `Assembly.Load`, so nothing hits disk), and calls into it to launch the native PE loader and payload.

The re-spawned PowerShell — the command line built by the loader's own `CreateProcessW` call, and the process as it appears on the host, parent already gone:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-22.png)

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-23.png)

The XOR keys and containers we recovered for each round:

| Stage / blob | Encoding | Recovered artifact |
|---|---|---|
| `XJQSYI` | hex + **subtract 101** (mod 256) | stage-2 generic XOR loader |
| `XVTVLGKQPI` | hex + XOR **72** | guard stub (mutex / console hide) |
| `AGQDBGSGN` | hex + XOR **140** | `CreateProcessW` re-spawner |
| `JUUUNYFMPV` | hex + XOR **82** | loader for the final stage |
| `UYTIYS`+`OUFGWTCR` | hex + XOR **120** | final module-extractor |
| `FAOEOY` | hex + XOR **160** | staging / persistence scripts |
| **BOOT** | Base64 + XOR `0x16` + GZip | stage-3 orchestrator |
| **AMSI** | Base64 + XOR `0x16` + GZip | AMSI bypass |
| **PS** | Base64 + XOR `0x16` + GZip | in-memory .NET engine |

#### The seven embedded modules

Once the orchestrator runs, seven modules are lifted out of the file, each verified against the manifest:

| Tag | What it is | Notes |
|---|---|---|
| **BOOT** | stage-3 orchestrator (PowerShell) | env scrub, sandbox sweep, module dispatch |
| **AMSI** | AMSI bypass | sets `AmsiUtils.amsiInitFailed = true` |
| **PS** | in-memory .NET engine | parses a custom `HOI1` container and rebuilds an assembly via `Reflection.Emit` |
| **HCS** | the managed host assembly (`HOI1` blob) | exposes `MPHDFG.DVYXYVASXG::Run(...)` |
| **HBT** | native "boot" PE stub | custom 16-letter-alphabet encoding, starts with `MZ` |
| **RSC** | native x64 PE loader | Base64 + **AES-256-CBC** + GZip → 247,808-byte PE |
| **PLD** | final implant / config blob | 451,904 bytes, entropy 8.0, **no PE header** |

The AES key material for `RSC` is itself XOR-obfuscated in the script; recovered, it is:

```
AES-256 key : 6dfba53763005cbe3edf462234ffd7f7bd795e348ffe27c69f524b571c0b674c
AES-256 IV  : 63f9d069eba3dd631af5194488f9ebdc
```

#### Anti-analysis

The loader is defensive at almost every step:

- **Single-instance & handoff:** a mutex `Local\SBMSRCXZUY` and an event `Local\SBMSRCXZUYe` coordinate the stages.
- **Console hiding:** `FreeConsole` + `ShowWindow(SW_HIDE)` + `SetWindowPos(HWND_BOTTOM)`.
- **Sandbox process sweep:** it kills small instances of `choice`, `msiexec`, `SearchProtocolHost`, `backgroundTaskHost`, `gpupdate`, `prevhost`, `dllhost` (the helper processes automated sandboxes spin up), then sleeps 5 seconds.
- **Job-object escape:** re-spawns PowerShell with `CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_CONSOLE` via a hand-built `CreateProcessW` P/Invoke.
- **AMSI bypass:** flips `amsiInitFailed` to `true` and nulls the AMSI context/session so script content stops being scanned.
- **Fileless:** every stage is a PowerShell script block or a `Reflection.Emit` assembly — nothing malicious is written to disk in a runnable form.
- **Debugger / VM checks** *are present* in the host module (checks for `IsAttached`, `Wireshark/procmon/x64dbg/…`, and VMware/VirtualBox/QEMU/Xen manufacturer strings) but are **gated behind an options flag that is switched off in this build** — a compile-time variant setting. Worth knowing they can be turned on in another build.

#### Persistence

Persistence is the one place the loader does touch disk. It copies itself to a hidden, system-attributed file masquerading as a print-spooler component and installs two persistence mechanisms pointing at a signed LOLBin:

- **Drop location:** `%LOCALAPPDATA%\Microsoft\Windows\Caches\print_spool_m\print_spool_m.dat` (plus a hidden `print_spool_m_*.cmd` "hop" launcher). The file, the copy, and the directory are all set **Hidden + System**.
- **Trigger (LOLBin):** `conhost.exe --headless -- cmd.exe /c call "<hidden .cmd>"` — a signed Windows binary that suppresses the console, so nothing is ever shown on screen.
- **Persistence #1 — Registry Run key:** `HKCU\…\CurrentVersion\Run` value **`ClrUsageTrim_EATI`** = the `conhost --headless …` line.
- **Persistence #2 — Scheduled task:** `\CompatCatalog_CNVK`, `AtLogOn` with a 3-second delay, **Hidden**, `RunLevel Limited`. **If the task registers successfully, the Run key is deleted** — so the task is the primary mechanism and the Run key is the fallback.

The persistence stage also **cleans up prior variants of itself** (old startup-folder `.cmd`/`.bin` files, a `CLSID` key, stray `.ps1`/`.vbs` droppers), which strongly suggests this malware is designed to be **updated in place** across campaigns.

#### Dynamic evidence (full-archive detonation)

The loader's own handoff log — `pld_ready` with the payload mapped at `0x17D60000`, then the hollowing step returning `HR=0x00000001`:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-24.png)

What that step produced — `choice.exe` detected as a hollowed process, then the same image on the host with a forged build timestamp dated 1974 and no parent of its own:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-25.png)

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-26.png)

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-27.png)

The whole chain on the host, console host included:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-28.png)

### 3.2 Threat Intelligence

Where the static pass stops (at the encrypted `PLD`), the intelligence sources pick up. Because the `.bat` we analysed is the exact same file that was detonated (SHA-256 `94407c7…2d73`), we can extend our own findings with what the full-archive sandbox run and crowdsourced signatures reported.

**Classification.** GTI code-insight ("palm") verdicts label the loader **malicious**; suggested label `trojan.alien/camelot`. Detection is low (**5 / 63**) because the file is almost entirely obfuscated data — exactly the point of the design.

**Final payload (in-memory).** The sandbox extracted two 32-bit VB.NET PE images from memory during the run — the actual payload the whole chain exists to deliver:

| Internal name | SHA-256 | Detections | Label |
|---|---|---|---|
| `SAMA-Kbat.exe` | `189c85ade5e3bb132c88f925ef7cddc94d20bcef4fe5a6e6a7af9940b5e419cd` | 36/71 | `trojan.msil/basic`, popular name **xworm** |
| `SAMA-K2.exe` | `fe0e087c1ff8453b14b672158a7bf4d9e8f29d6929bf1feabafa00390d8f104c` | 37/71 | `trojan.msil/basic`, popular name **xworm** |

Both carry the product name "SAMA" (company falsely "Microsoft") and the internal branding **"SAMAClient101."**

**Command & Control.** In the full-archive detonation the chain beaconed to:

| Indicator | Detail |
|---|---|
| **`130.94.59.139:7000/TCP`** | Primary C2. Snort fired *"MALWARE-CNC Win.Infostealer.XWorm variant communication."* |
| Hosting | ASN **154177**, AS owner **LIGHT NODE LIMITED** (LightNode VPS), country **SA (Saudi Arabia)**, IP first seen 2026-08-14, VT reputation currently 0/89 (fresh, not yet widely flagged) |
| `162.159.36.2:53/UDP` | Cloudflare public DNS lookup — infrastructure, not malicious |

The beacon as captured on the host — `choice.exe` (PID 6804) reconnecting to the C2:

![SAMA XWorm analysis](/assets/img/sama-xworm-multistage-loader-analysis/img-29.png)

**Targeting.** The Saudi-hosted C2 combined with the **SAMA (Saudi Central Bank)** lure branding indicates a **campaign aimed at Saudi Arabian targets**, most likely through a banking / finance-customer-service pretext *(medium-high confidence, inferred from naming + hosting geography).*

---

## MITRE ATT&CK Mapping (loader + chain)

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Execution | PowerShell | T1059.001 | Script blocks executed from env vars via `NewScriptBlock` |
| Execution | Windows Command Shell | T1059.003 | `.bat` loader, `findstr` self-extraction |
| Execution | Native API | T1106 | `CreateProcessW` via hand-built P/Invoke |
| Defense Evasion | Hijack Execution Flow: DLL Side-Loading | T1574 | `AdobeARM.exe` loads fake `SensApi.dll` |
| Defense Evasion | Masquerading | T1036 | Fake Microsoft DLL; `print_spool_m`, `CompatCatalog_CNVK` |
| Defense Evasion | Obfuscated / Encoded Files | T1027, T1027.009, T1027.013 | String splicing, multi-scheme encoding, embedded encrypted modules |
| Defense Evasion | Deobfuscate/Decode Files | T1140 | Runtime hex/XOR/Base64/GZip/AES decoding |
| Defense Evasion | Reflective Code Loading | T1620 | In-memory .NET via `Reflection.Emit` |
| Defense Evasion | Impair Defenses: Disable Tools | T1562.001 | AMSI bypass (`amsiInitFailed`) |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497.001 | VM/debugger checks (present, disabled in this build); sandbox process sweep |
| Defense Evasion | Hide Artifacts: Hidden Window / Files | T1564.003, T1564.001 | `conhost --headless`; Hidden+System files |
| Defense Evasion | Process Injection | T1055 | (dynamic) EXE written to `msiexec.exe`; RunPE into `choice.exe` |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 | `ClrUsageTrim_EATI` |
| Persistence | Scheduled Task/Job | T1053.005 | `\CompatCatalog_CNVK` |
| Command & Control | Application Layer / Encrypted Channel | T1071, T1573 | (dynamic) TCP beacon; in-memory crypto |
| Defense Evasion | Indicator Removal | T1070.004, T1070.009 | Deletes prior variants and its own env vars |

---

## Detection & IOCs

### Host artifacts (high confidence)

```
File:   %LOCALAPPDATA%\Microsoft\Windows\Caches\print_spool_m\print_spool_m.dat
File:   %LOCALAPPDATA%\Microsoft\Windows\Caches\print_spool_m\print_spool_m_*.cmd
Run:    HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ClrUsageTrim_EATI
Task:   \CompatCatalog_CNVK   (AtLogOn, Delay PT3S, Hidden, RunLevel Limited)
Mutex:  Local\SBMSRCXZUY
Event:  Local\SBMSRCXZUYe
Trigger: conhost.exe --headless -- cmd.exe /c call "<…\print_spool_m\*.cmd>"
```

### Network (defanged, dynamic)

```
C2   130[.]94[.]59[.]139 : 7000/TCP   (XWorm infostealer C2; AS154177 LightNode; SA)
DNS  162[.]159[.]36[.]2 : 53/UDP       (Cloudflare resolver — benign infrastructure)
```

### File hashes

```
Archive     6745899253115a295a86554127264a1d76e24f4aa2d6f2879e7284b1538b53ad  SAMA.zip
Loader      94407c7291a95e6e5e49d54aa998cf034e2fb0d0d5af8778900034decf872d73  SAMA-Kbat_…​.bat
Side DLL    766fe987b73f77d3e4fb5ca07aa5392993451d3cefdda293ba92443e1a6f268a  SensApi.dll (malicious)
Payload     189c85ade5e3bb132c88f925ef7cddc94d20bcef4fe5a6e6a7af9940b5e419cd  SAMA-Kbat.exe (in-mem)
Payload     fe0e087c1ff8453b14b672158a7bf4d9e8f29d6929bf1feabafa00390d8f104c  SAMA-K2.exe (in-mem)
(clean)     69469a3b807d8751966a3d6cd78f17c8b368a6760718805997e751e3ab2b3eed  AdobeARM.exe — DO NOT BLOCK
```

### Sigma — headless conhost launching a cached CMD

```yaml
title: Conhost Headless Launching Cached CMD (SAMA/KARMO persistence)
status: experimental
tags: [attack.persistence, attack.t1547.001, attack.defense_evasion, attack.t1564.003]
logsource: {category: process_creation, product: windows}
detection:
  selection:
    CommandLine|contains|all:
      - 'conhost'
      - '--headless'
    CommandLine|contains:
      - '\Microsoft\Windows\Caches\'
      - '.cmd'
  condition: selection
falsepositives: [Low]
level: high
```

### Sigma — batch self-extraction + env-var script-block PowerShell

```yaml
title: PowerShell Script Block Executed From Environment Variables (SAMA/KARMO loader)
status: experimental
tags: [attack.execution, attack.t1059.001, attack.t1027]
logsource: {category: process_creation, product: windows}
detection:
  selection_ps:
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all:
      - 'NewScriptBlock'
      - '$env:'
  selection_findstr:
    Image|endswith: '\findstr.exe'
    CommandLine|contains: '&rem '
  condition: selection_ps or selection_findstr
falsepositives: [Some packers/installers use env-var script blocks — validate the parent .bat]
level: high
```

---

## Closing

`SAMA.zip` is a tidy example of how commodity crimeware layers trust and obfuscation to get a fileless RAT running on a target. A signed Adobe binary provides cover, a fake system DLL rides in behind it, and a 933 KB batch file quietly reassembles, verifies, and executes seven encrypted modules entirely in memory before injecting an XWorm-family stealer and beaconing to fresh Saudi-hosted infrastructure. The lure and the hosting both point squarely at Saudi users.


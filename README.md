# 🔒 Interlude Defender

**Next-Generation Threat Detection — Lightweight, Intelligent, Non-Intrusive**

> The best antivirus is one you don't notice is running.

---

## ✨ Features

- **🪶 Lightweight** — ~80-120 MB footprint, <2% CPU at idle
- **🤫 Silent** — Background operation, alerts only on ACTUAL threats
- **🧠 Intelligent** — Heuristic analysis + behavioral detection + signature matching
- **⚡ Fast** — Multi-threaded scanning, Bloom filter lookups in O(1)
- **🛡️ Trust-First** — No subscriptions, no dark patterns, no nagware
- **🔍 Transparent** — Open-source threat definitions

## 🏗️ Architecture

```mermaid
flowchart TD
    A[Interlude Defender] --> B(UI Layer - PySide6)
    A --> C(Detection Engine)
    A --> D(Real-time Protection)

    B --> B1[Dashboard]
    B --> B2[Scan Management]
    B --> B3[Quarantine Viewer]
    B --> B4[Settings]

    C --> C1[Signature Matching]
    C --> C2[Heuristic Analyzer]
    C --> C3[Entropy Detection]
    C --> C4[Quarantine Manager]

    D --> D1[File System Monitor]
    D --> D2[Process Monitor]
    D --> D3[Auto-quarantine]
```

## 🚀 Quick Start

### Releases
-Download the latest release from [Github](https://github.com/Hndrd0/Interlude-Defender/releases/tag/v.0.0.1)

### Installation

```bash
# Clone the repository
git clone https://github.com/Hndrd0/Interlude-Defender.git
cd Interlude-Defender

# Install dependencies
pip install -r requirements.txt

# Launch the dashboard
python main.py
```

### CLI Mode

```bash
# Quick scan (temp folders, downloads, startup)
python main.py --scan

# Full system scan
python main.py --full-scan

# Scan a specific directory
python main.py --scan-path "C:\Users\YourName\Downloads"

# Start in background (tray only)
python main.py --background

# Debug mode
python main.py --debug
```

## 🎯 Detection Layers

| Layer | Method | Speed | Purpose |
|-------|--------|-------|---------|
| **1** | SHA256 Signature Matching | <1ms/file | Catch known malware |
| **2** | PE Heuristic Analysis | <50ms/file | Catch variants & obfuscated threats |
| **3** | Entropy Detection | <10ms/file | Detect packed/encrypted executables |
| **4** | Import Analysis | <20ms/file | Flag suspicious API usage patterns |

## 🎨 UI Design

- **Dark glassmorphic theme** — Premium look, easy on the eyes
- **Zero dark patterns** — No fake warnings, no upsell, no nag screens
- **Minimal notifications** — Only alerts on real threats
- **System tray integration** — Runs silently in the background

## 📁 Project Structure

```mermaid
flowchart LR
    A[hermes-antivirus/] --> B[hermes/]
    A --> C[main.py - Entry point]
    A --> D[requirements.txt]

    B --> E[core/ - Detection engine]
    B --> F[monitor/ - Real-time protection]
    B --> G[ui/ - PySide6 Dashboard]
    B --> H[utils/ - Configuration & logging]

    E --> E1[scanner.py - Scan orchestrator]
    E --> E2[signatures.py - Hash matching]
    E --> E3[heuristics.py - PE analysis]
    E --> E4[quarantine.py - File isolation]
    E --> E5[database.py - SQLite operations]

    F --> F1[file_monitor.py - FS watcher]
    F --> F2[process_monitor.py]

    G --> G1[app.py - Main window]
    G --> G2[dashboard.py - Home page]
    G --> G3[scan_page.py - Scan management]
    G --> G4[quarantine_page.py]
    G --> G5[settings_page.py]
    G --> G6[theme.py - Dark theme]
    G --> G7[widgets/ - Custom UI]
```

## 🔒 Philosophy

Every antivirus company optimizes for **upsell revenue**. Interlude optimizes for **actual protection**.

- ❌ No fake "warnings" to scare you
- ❌ No "upgrade to Pro" nags
- ❌ No subscription reminders
- ❌ No upselling additional products
- ❌ No slow-down tricks

## 📜 License

MIT License — Free to use, modify, and distribute.

---

**Built with ❤️ by Interlude Security**

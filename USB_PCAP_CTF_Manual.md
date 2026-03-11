# 🔌 USB PCAP CTF Solver — User Manual

> A complete guide to solving USB packet capture challenges in CTF competitions.

---

## 📚 Table of Contents

1. [What is a PCAP File?](#1-what-is-a-pcap-file)
2. [What is USB HID?](#2-what-is-usb-hid)
3. [Types of USB CTF Challenges](#3-types-of-usb-ctf-challenges)
4. [Installation & Requirements](#4-installation--requirements)
5. [How to Use the Tool](#5-how-to-use-the-tool)
6. [Code Walkthrough](#6-code-walkthrough)
   - [Part A — Imports & Dependencies](#part-a--imports--dependencies)
   - [Part B — HID Keymaps](#part-b--hid-keymaps)
   - [Part C — Data Extraction](#part-c--data-extraction)
   - [Part D — Keyboard Decoder](#part-d--keyboard-decoder)
   - [Part E — Mouse Tracker](#part-e--mouse-tracker)
   - [Part F — Printer Extractor](#part-f--printer-extractor)
   - [Part G — Storage File Carver](#part-g--storage-file-carver)
   - [Part H — Auto Detection](#part-h--auto-detection)
   - [Part I — Main Entry Point](#part-i--main-entry-point)
7. [Output Files Reference](#7-output-files-reference)
8. [Tips & Tricks for CTFs](#8-tips--tricks-for-ctfs)
9. [Full Python Code](#9-full-python-code)

---

## 1. What is a PCAP File?

A **PCAP** (Packet Capture) file is a recording of raw data packets flowing through an interface — either a **network** interface or a **USB** bus.

In CTFs, PCAP files are used to hide flags inside captured traffic. You must analyze the packets to reconstruct what happened and extract the hidden data.

```
Computer  ──────── USB Bus ──────────  Device (Keyboard / Mouse / Drive)
               ↑ captured here
           challenge.pcap
```

**Tools to open PCAPs:**
- `Wireshark` — graphical viewer
- `tshark` — command-line version
- `scapy` — Python library (used in this tool)

---

## 2. What is USB HID?

**HID** stands for **Human Interface Device** — the USB protocol used by keyboards, mice, and game controllers to send input data to a computer.

Every key press or mouse movement is sent as a small binary **HID report packet**.

### Keyboard HID Packet (8 bytes):

```
┌──────────┬──────────┬──────────┬──────────┬─────────────────────────┐
│  Byte 0  │  Byte 1  │  Byte 2  │  Byte 3  │  Bytes 4–7              │
│ Modifier │ Reserved │ Keycode1 │ Keycode2 │  Extra keycodes (unused) │
└──────────┴──────────┴──────────┴──────────┴─────────────────────────┘

Modifier byte flags:
  0x02 = Left Shift
  0x20 = Right Shift
  0x01 = Left Ctrl
  0x04 = Left Alt
```

### Mouse HID Packet (4 bytes):

```
┌──────────┬──────────┬──────────┬──────────┐
│  Byte 0  │  Byte 1  │  Byte 2  │  Byte 3  │
│ Buttons  │  X move  │  Y move  │  Scroll  │
└──────────┴──────────┴──────────┴──────────┘

Button byte flags:
  0x01 = Left click
  0x02 = Right click
  0x04 = Middle click

X/Y are signed bytes (-128 to +127 = move left/right/up/down)
```

---

## 3. Types of USB CTF Challenges

| Type | Device | What to Extract | Output |
|------|--------|----------------|--------|
| **Keyboard** | USB Keyboard | Typed keystrokes | Text / Flag |
| **Mouse** | USB Mouse | X/Y movements | Drawn image / Flag |
| **Printer** | USB Printer | Print job data | PCL / PostScript / PDF |
| **Mass Storage** | USB Drive | Transferred files | PNG / ZIP / ELF / etc. |

---

## 4. Installation & Requirements

### Requirements:
- Python 3.6+
- `scapy` — for reading PCAP files
- `Pillow` — for plotting mouse movements as images

### Install:

```bash
pip install scapy pillow
```

### Verify:

```bash
python -c "import scapy; import PIL; print('All good!')"
```

---

## 5. How to Use the Tool

### Basic Usage:

```bash
python usb_pcap_solver.py challenge.pcap
```

> By default, the tool runs in **auto mode** — it detects the device type automatically.

### Force a Specific Mode:

```bash
# Decode keyboard keystrokes
python usb_pcap_solver.py challenge.pcap --mode keyboard

# Plot mouse movement image
python usb_pcap_solver.py challenge.pcap --mode mouse

# Extract printer data
python usb_pcap_solver.py challenge.pcap --mode printer

# Carve files from USB storage
python usb_pcap_solver.py challenge.pcap --mode storage

# Show raw hex dump of packets
python usb_pcap_solver.py challenge.pcap --mode hex
```

### Run All Decoders At Once:

```bash
python usb_pcap_solver.py challenge.pcap --all
```

---

## 6. Code Walkthrough

This section explains each part of the Python code so you understand exactly what every section does.

---

### Part A — Imports & Dependencies

```python
import sys, os, argparse, struct
from collections import defaultdict
from scapy.all import rdpcap, Raw
from PIL import Image, ImageDraw
```

**What this does:**
- `sys`, `os` — file and system operations
- `argparse` — parses command-line arguments (`--mode`, `--all`)
- `scapy` — reads and parses the `.pcap` file
- `PIL / Pillow` — draws mouse movement plots as PNG images

The code also auto-installs `scapy` and `pillow` if they are missing using `os.system("pip install ...")`.

---

### Part B — HID Keymaps

```python
KEYMAP = {
    0x04: 'a', 0x05: 'b', 0x06: 'c',
    ...
    0x28: '\n', 0x2A: '[BACKSPACE]', 0x2C: ' ',
    ...
}

SHIFT_KEYMAP = {
    0x04: 'A', 0x05: 'B',
    ...
    0x1E: '!', 0x1F: '@', 0x20: '#',
    ...
}
```

**What this does:**
- Maps raw USB HID keycodes (hex numbers) to readable characters
- `KEYMAP` — normal key presses (e.g., `0x04` → `'a'`)
- `SHIFT_KEYMAP` — same keys with Shift held (e.g., `0x04` → `'A'`, `0x1E` → `'!'`)
- Special keys like Backspace, Enter, F1–F12, arrow keys are also mapped

> 💡 **Why this matters:** Without this map, you'd only see raw hex like `04 00 00...` instead of `a`.

---

### Part C — Data Extraction

```python
def extract_usb_data(pcap_file):
    packets = rdpcap(pcap_file)
    data_list = []
    for pkt in packets:
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw])
        elif hasattr(pkt, 'load'):
            raw = bytes(pkt.load)
        if raw and len(raw) >= 4:
            data_list.append(raw)
    return data_list
```

**What this does:**
- Loads all packets from the `.pcap` file using `scapy`
- Extracts the raw binary payload from each packet
- Tries two methods: `Raw` layer and `.load` attribute (different pcap formats store data differently)
- Returns a list of byte strings — one per packet

---

### Part D — Keyboard Decoder

```python
def decode_keyboard(data_list):
    for raw in data_list:
        modifier = raw[0]   # Shift, Ctrl, Alt flags
        keycode  = raw[2]   # The actual key pressed

        shift = (modifier & 0x02) or (modifier & 0x20)

        if shift:
            char = SHIFT_KEYMAP.get(keycode, ...)
        else:
            char = KEYMAP.get(keycode, ...)

        if char == '[BACKSPACE]':
            result.pop()    # simulate backspace
        else:
            result.append(char)
```

**What this does:**

| Step | Action |
|------|--------|
| Read modifier byte | Detect if Shift/Ctrl is held |
| Read keycode byte | Look up the key in the keymap |
| Handle Backspace | Remove last character from result |
| Handle CapsLock | Toggle uppercase mode |
| Find flags | Regex search for `FLAG{...}` patterns |

**Output:** Printed text + saved to `keyboard_output.txt`

---

### Part E — Mouse Tracker

```python
def decode_mouse(data_list):
    x, y = 2000, 2000   # start at center

    for raw in data_list:
        buttons = raw[0]
        dx = signed_byte(raw[1])   # X delta (can be negative)
        dy = signed_byte(raw[2])   # Y delta (can be negative)

        x += dx
        y += dy

        if buttons & 0x01:         # left button held
            click_points.append((x, y))
```

**What this does:**

| Step | Action |
|------|--------|
| Start at center (2000, 2000) | Canvas is 4000×4000 pixels |
| Add X/Y deltas each packet | Tracks current cursor position |
| Signed byte conversion | Values > 127 become negative (left/up movement) |
| Record when left-clicked | Only draw path when button is held |
| Save 3 PNG images | All movement, click dots, click path line |

**Why 3 images?** Sometimes the flag is visible only as a connected line, sometimes only as dot clusters — generating all 3 maximizes your chance of seeing it.

---

### Part F — Printer Extractor

```python
def decode_printer(data_list):
    combined = b''.join(data_list)

    if combined[:2] in (b'\x1b\x45', b'\x1b%'):
        ext = '.pcl'       # HP Printer Language
    elif combined[:2] == b'%!':
        ext = '.ps'        # PostScript
    elif combined[:4] == b'%PDF':
        ext = '.pdf'       # PDF
    else:
        ext = '.bin'       # Unknown
```

**What this does:**
- Joins all bulk transfer data into one binary blob
- Detects format by checking **magic bytes** (file signatures at the start)
- Saves the file with the correct extension
- Extracts readable strings and searches for flags

**To render the output:**
```bash
# PostScript
gs -sDEVICE=png16m -o output.png printer_output.ps

# PCL (use GhostPCL)
gpcl6 -sDEVICE=png16m -o output.png printer_output.pcl
```

---

### Part G — Storage File Carver

```python
MAGIC = {
    b'\x89PNG':     ('png', 'PNG Image'),
    b'\xff\xd8\xff':('jpg', 'JPEG Image'),
    b'PK\x03\x04':  ('zip', 'ZIP Archive'),
    b'%PDF':        ('pdf', 'PDF Document'),
    b'\x7fELF':     ('elf', 'ELF Binary'),
    ...
}

for magic, (ext, desc) in MAGIC.items():
    pos = combined.find(magic)
    if pos != -1:
        # extract bytes from pos to next file
```

**What this does:**
- Combines all USB bulk transfer data
- Searches for known **magic bytes** (file signatures) within the binary blob
- Carves each file out and saves it separately
- Also does a raw string search for flag patterns

> 💡 **File carving** is the technique of extracting files from raw binary data without a filesystem — just by finding known file headers.

---

### Part H — Auto Detection

```python
def auto_detect(data_list):
    for raw in data_list[:100]:
        if len(raw) == 8:
            keyboard_score += 1    # Keyboard packets are 8 bytes
        elif len(raw) == 4:
            mouse_score += 1       # Mouse packets are 4 bytes
        elif len(raw) > 16:
            bulk_score += 1        # Bulk = printer/storage

    detected = max(scores, key=scores.get)
```

**What this does:**
- Samples the first 100 packets
- Scores each possible device type based on packet length and content patterns
- Picks the highest-scoring type and runs that decoder automatically

---

### Part I — Main Entry Point

```python
def main():
    parser = argparse.ArgumentParser(...)
    parser.add_argument('pcap', ...)
    parser.add_argument('--mode', choices=[
        'auto', 'keyboard', 'mouse',
        'printer', 'storage', 'hex'
    ])
    parser.add_argument('--all', action='store_true')

    data_list = extract_usb_data(args.pcap)

    if args.all:
        # run every decoder
    else:
        # run selected mode
```

**What this does:**
- Entry point when you run the script
- Parses your command-line arguments
- Calls `extract_usb_data()` first to load all packets
- Routes to the correct decoder based on `--mode`
- `--all` flag runs every decoder in sequence

---

## 7. Output Files Reference

| File | Created By | Contents |
|------|-----------|----------|
| `keyboard_output.txt` | Keyboard mode | All decoded keystrokes |
| `mouse_all_movement.png` | Mouse mode | Full cursor path (gray) |
| `mouse_clicks.png` | Mouse mode | Only click positions (dots) |
| `mouse_click_path.png` | Mouse mode | Click positions as connected line |
| `printer_output.*` | Printer mode | PCL / PostScript / PDF / binary |
| `extracted_1.png` etc. | Storage mode | Carved files from USB drive data |
| `storage_raw.bin` | Storage mode | Raw dump if no files found |

---

## 8. Tips & Tricks for CTFs

### 🔍 Always Start With Hex Dump
```bash
python usb_pcap_solver.py challenge.pcap --mode hex
```
Look at packet lengths and byte patterns before committing to a mode.

### ⌨️ Keyboard Tips
- If output looks garbled, check if CapsLock was on at the start
- Watch for `[CTRL+C]`, `[CTRL+V]` — flag may have been pasted
- Try reading backwards if you see many Backspace keys

### 🖱️ Mouse Tips
- Open all 3 PNG images — each reveals different detail
- If image is tiny, the canvas origin may be off — try adjusting start X/Y
- Right-click-only points may also form a pattern

### 💾 Storage Tips
- Run `strings` on `storage_raw.bin` — flags are often in plaintext
- Try `binwalk storage_raw.bin` for deeper nested file detection
- ZIP files may be password protected — try `rockyou.txt` wordlist

### 🖨️ Printer Tips
- PostScript files can contain hidden commands — open in a text editor
- PCL files sometimes have text in plaintext between binary sections

---

## 9. Full Python Code

```python
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          USB PCAP CTF Solver - All-in-One Tool               ║
║  Supports: Keyboard | Mouse | Printer | Mass Storage         ║
╚══════════════════════════════════════════════════════════════╝

Requirements:
    pip install scapy pillow

Usage:
    python usb_pcap_solver.py <file.pcap>
    python usb_pcap_solver.py <file.pcap> --mode keyboard
    python usb_pcap_solver.py <file.pcap> --mode mouse
    python usb_pcap_solver.py <file.pcap> --mode printer
    python usb_pcap_solver.py <file.pcap> --mode storage
    python usb_pcap_solver.py <file.pcap> --mode auto
"""

import sys
import os
import argparse
import struct
from collections import defaultdict

# ─── Dependency Check ──────────────────────────────────────────
try:
    from scapy.all import rdpcap, Raw
    from scapy.layers.usb import USBpcap, USB
except ImportError:
    print("[!] Scapy not found. Installing...")
    os.system("pip install scapy --break-system-packages -q")
    from scapy.all import rdpcap, Raw

try:
    from PIL import Image, ImageDraw
    PIL_AVAILABLE = True
except ImportError:
    print("[!] Pillow not found. Installing...")
    os.system("pip install pillow --break-system-packages -q")
    from PIL import Image, ImageDraw
    PIL_AVAILABLE = True


# ══════════════════════════════════════════════════════════════
#  PART B — HID KEYMAPS
#  Maps raw HID hex keycodes → readable characters
# ══════════════════════════════════════════════════════════════

KEYMAP = {
    0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd',
    0x08: 'e', 0x09: 'f', 0x0A: 'g', 0x0B: 'h',
    0x0C: 'i', 0x0D: 'j', 0x0E: 'k', 0x0F: 'l',
    0x10: 'm', 0x11: 'n', 0x12: 'o', 0x13: 'p',
    0x14: 'q', 0x15: 'r', 0x16: 's', 0x17: 't',
    0x18: 'u', 0x19: 'v', 0x1A: 'w', 0x1B: 'x',
    0x1C: 'y', 0x1D: 'z',
    0x1E: '1', 0x1F: '2', 0x20: '3', 0x21: '4',
    0x22: '5', 0x23: '6', 0x24: '7', 0x25: '8',
    0x26: '9', 0x27: '0',
    0x28: '\n', 0x29: '[ESC]', 0x2A: '[BACKSPACE]',
    0x2B: '\t', 0x2C: ' ',
    0x2D: '-', 0x2E: '=',
    0x2F: '[', 0x30: ']', 0x31: '\\',
    0x33: ';', 0x34: "'",
    0x36: ',', 0x37: '.', 0x38: '/',
    0x39: '[CAPSLOCK]',
    0x4F: '[RIGHT]', 0x50: '[LEFT]',
    0x51: '[DOWN]',  0x52: '[UP]',
    0x4A: '[HOME]',  0x4B: '[PGUP]',
    0x4C: '[DEL]',   0x4D: '[END]',
    0x4E: '[PGDN]',
    0x3A: '[F1]',  0x3B: '[F2]',  0x3C: '[F3]',
    0x3D: '[F4]',  0x3E: '[F5]',  0x3F: '[F6]',
    0x40: '[F7]',  0x41: '[F8]',  0x42: '[F9]',
    0x43: '[F10]', 0x44: '[F11]', 0x45: '[F12]',
}

SHIFT_KEYMAP = {
    0x04: 'A', 0x05: 'B', 0x06: 'C', 0x07: 'D',
    0x08: 'E', 0x09: 'F', 0x0A: 'G', 0x0B: 'H',
    0x0C: 'I', 0x0D: 'J', 0x0E: 'K', 0x0F: 'L',
    0x10: 'M', 0x11: 'N', 0x12: 'O', 0x13: 'P',
    0x14: 'Q', 0x15: 'R', 0x16: 'S', 0x17: 'T',
    0x18: 'U', 0x19: 'V', 0x1A: 'W', 0x1B: 'X',
    0x1C: 'Y', 0x1D: 'Z',
    0x1E: '!', 0x1F: '@', 0x20: '#', 0x21: '$',
    0x22: '%', 0x23: '^', 0x24: '&', 0x25: '*',
    0x26: '(', 0x27: ')',
    0x2D: '_', 0x2E: '+',
    0x2F: '{', 0x30: '}', 0x31: '|',
    0x33: ':', 0x34: '"',
    0x36: '<', 0x37: '>', 0x38: '?',
}


# ══════════════════════════════════════════════════════════════
#  UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════

def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          USB PCAP CTF Solver - All-in-One Tool               ║
║  Modes: keyboard | mouse | printer | storage | auto          ║
╚══════════════════════════════════════════════════════════════╝
""")


def signed_byte(val):
    """Convert unsigned byte to signed (-128 to 127)."""
    return val - 256 if val > 127 else val


def save_text(content, filename="keyboard_output.txt"):
    with open(filename, 'w') as f:
        f.write(content)
    print(f"[+] Text saved to: {filename}")


# ══════════════════════════════════════════════════════════════
#  PART C — DATA EXTRACTION
#  Loads all USB HID data packets from the PCAP file
# ══════════════════════════════════════════════════════════════

def extract_usb_data(pcap_file):
    print(f"[*] Loading PCAP: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"[*] Total packets: {len(packets)}")

    data_list = []
    for pkt in packets:
        raw = None
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw])
        elif hasattr(pkt, 'load'):
            raw = bytes(pkt.load)
        if raw and len(raw) >= 4:
            data_list.append(raw)

    print(f"[*] Extracted {len(data_list)} data packets\n")
    return data_list


# ══════════════════════════════════════════════════════════════
#  PART D — KEYBOARD DECODER
#  Reconstructs typed text from USB keyboard HID packets
# ══════════════════════════════════════════════════════════════

def decode_keyboard(data_list):
    print("=" * 60)
    print("  ⌨️  KEYBOARD DECODER")
    print("=" * 60)

    result    = []
    caps_lock = False

    for raw in data_list:
        if len(raw) < 3:
            continue

        modifier = raw[0]
        keycode  = raw[2] if len(raw) > 2 else 0

        if keycode == 0:
            continue

        shift = (modifier & 0x02) or (modifier & 0x20)

        if keycode == 0x39:
            caps_lock = not caps_lock
            result.append('[CAPSLOCK]')
            continue

        if modifier & 0x01 or modifier & 0x10:
            char = KEYMAP.get(keycode, '')
            if char:
                result.append(f'[CTRL+{char.upper()}]')
            continue

        if shift:
            char = SHIFT_KEYMAP.get(keycode, KEYMAP.get(keycode, f'[{hex(keycode)}]'))
        elif caps_lock:
            char = SHIFT_KEYMAP.get(keycode, KEYMAP.get(keycode, f'[{hex(keycode)}]'))
        else:
            char = KEYMAP.get(keycode, f'[{hex(keycode)}]')

        if char == '[BACKSPACE]' and result:
            result.pop()
        else:
            result.append(char)

    full_text = ''.join(result)

    print("\n[+] ── RAW KEYSTROKES (with special keys) ──")
    print(full_text)

    clean = ''.join(
        c for c in result
        if not (c.startswith('[') and c.endswith(']'))
    )
    print("\n[+] ── CLEAN TEXT OUTPUT ──")
    print(clean)

    import re
    flags = re.findall(r'[A-Za-z0-9_]+\{[^\}]+\}', full_text)
    if flags:
        print("\n[🚩] ── POSSIBLE FLAGS FOUND ──")
        for flag in flags:
            print(f"  → {flag}")

    save_text(full_text, "keyboard_output.txt")
    return full_text


# ══════════════════════════════════════════════════════════════
#  PART E — MOUSE TRACKER
#  Plots USB mouse movement as PNG images
# ══════════════════════════════════════════════════════════════

def decode_mouse(data_list):
    print("=" * 60)
    print("  🖱️  MOUSE TRACKER")
    print("=" * 60)

    x, y         = 2000, 2000
    all_points   = []
    click_points = []

    for raw in data_list:
        if len(raw) < 3:
            continue

        buttons = raw[0]
        dx      = signed_byte(raw[1])
        dy      = signed_byte(raw[2])

        x = max(0, min(4000, x + dx))
        y = max(0, min(4000, y + dy))

        all_points.append((x, y))

        if buttons & 0x01:
            click_points.append((x, y))

    print(f"[+] Total movement points : {len(all_points)}")
    print(f"[+] Left-click points     : {len(click_points)}")

    # Plot 1: All movement
    img_all = Image.new('RGB', (4000, 4000), 'white')
    draw    = ImageDraw.Draw(img_all)
    if len(all_points) > 1:
        draw.line(all_points, fill='lightgray', width=1)
    img_all.save("mouse_all_movement.png")
    print("[+] Saved: mouse_all_movement.png")

    # Plot 2: Click dots
    img_click = Image.new('RGB', (4000, 4000), 'white')
    draw2     = ImageDraw.Draw(img_click)
    for pt in click_points:
        draw2.ellipse([pt[0]-3, pt[1]-3, pt[0]+3, pt[1]+3], fill='black')
    img_click.save("mouse_clicks.png")
    print("[+] Saved: mouse_clicks.png")

    # Plot 3: Click path line
    img_path = Image.new('RGB', (4000, 4000), 'white')
    draw3    = ImageDraw.Draw(img_path)
    if len(click_points) > 1:
        draw3.line(click_points, fill='black', width=2)
    img_path.save("mouse_click_path.png")
    print("[+] Saved: mouse_click_path.png")


# ══════════════════════════════════════════════════════════════
#  PART F — PRINTER DATA EXTRACTOR
#  Extracts and identifies printer job data
# ══════════════════════════════════════════════════════════════

def decode_printer(data_list):
    print("=" * 60)
    print("  🖨️  PRINTER DATA EXTRACTOR")
    print("=" * 60)

    combined = b''.join(data_list)

    if not combined:
        print("[!] No printer data found.")
        return

    print(f"[+] Total printer data: {len(combined)} bytes")

    if combined[:2] in (b'\x1b\x45', b'\x1b%'):
        print("[+] Detected: PCL")
        ext = '.pcl'
    elif combined[:2] == b'%!':
        print("[+] Detected: PostScript")
        ext = '.ps'
    elif combined[:4] == b'%PDF':
        print("[+] Detected: PDF")
        ext = '.pdf'
    else:
        print("[+] Format: Unknown — saving as .bin")
        ext = '.bin'

    outfile = f"printer_output{ext}"
    with open(outfile, 'wb') as f:
        f.write(combined)
    print(f"[+] Saved to: {outfile}")

    import re
    strings = re.findall(b'[ -~]{6,}', combined)
    if strings:
        print("\n[+] ── READABLE STRINGS ──")
        for s in strings[:40]:
            print(f"  {s.decode(errors='ignore')}")

    full_text = combined.decode(errors='ignore')
    flags = re.findall(r'[A-Za-z0-9_]+\{[^\}]+\}', full_text)
    if flags:
        print("\n[🚩] ── POSSIBLE FLAGS ──")
        for flag in flags:
            print(f"  → {flag}")


# ══════════════════════════════════════════════════════════════
#  PART G — MASS STORAGE FILE CARVER
#  Finds and extracts files hidden in USB drive transfers
# ══════════════════════════════════════════════════════════════

def decode_storage(data_list):
    print("=" * 60)
    print("  💾  MASS STORAGE EXTRACTOR")
    print("=" * 60)

    MAGIC = {
        b'\x89PNG':          ('png',  'PNG Image'),
        b'\xff\xd8\xff':     ('jpg',  'JPEG Image'),
        b'PK\x03\x04':       ('zip',  'ZIP Archive'),
        b'%PDF':             ('pdf',  'PDF Document'),
        b'GIF8':             ('gif',  'GIF Image'),
        b'\x1f\x8b':         ('gz',   'GZip Archive'),
        b'BZh':              ('bz2',  'BZip2 Archive'),
        b'\x7fELF':          ('elf',  'ELF Binary'),
        b'MZ':               ('exe',  'Windows Executable'),
        b'RIFF':             ('wav',  'WAV Audio'),
        b'ID3':              ('mp3',  'MP3 Audio'),
        b'OggS':             ('ogg',  'OGG Audio'),
    }

    combined = b''.join(data_list)
    print(f"[+] Total data: {len(combined)} bytes")

    found = []
    for magic, (ext, desc) in MAGIC.items():
        idx = 0
        while True:
            pos = combined.find(magic, idx)
            if pos == -1:
                break
            found.append((pos, ext, desc))
            idx = pos + 1

    found.sort(key=lambda x: x[0])

    if not found:
        print("[!] No known file signatures found.")
        with open('storage_raw.bin', 'wb') as f:
            f.write(combined)
        print("[*] Raw data saved to storage_raw.bin")
        return

    print(f"\n[+] Found {len(found)} potential files:")
    for i, (pos, ext, desc) in enumerate(found):
        print(f"  [{i+1}] Offset {pos:#010x} → {desc} (.{ext})")

    for i, (pos, ext, desc) in enumerate(found):
        end   = found[i+1][0] if i+1 < len(found) else len(combined)
        chunk = combined[pos:end]
        fname = f"extracted_{i+1}.{ext}"
        with open(fname, 'wb') as f:
            f.write(chunk)
        print(f"[+] Saved: {fname} ({len(chunk)} bytes)")

    import re
    text  = combined.decode(errors='ignore')
    flags = re.findall(r'[A-Za-z0-9_]+\{[^\}]+\}', text)
    if flags:
        print("\n[🚩] ── FLAGS IN RAW DATA ──")
        for flag in flags:
            print(f"  → {flag}")


# ══════════════════════════════════════════════════════════════
#  PART H — AUTO DETECTION
#  Scores packets to guess device type automatically
# ══════════════════════════════════════════════════════════════

def auto_detect(data_list, pcap_file):
    print("=" * 60)
    print("  🔍  AUTO DETECTION MODE")
    print("=" * 60)

    keyboard_score = 0
    mouse_score    = 0
    bulk_score     = 0

    for raw in data_list[:100]:
        if len(raw) == 8:
            keyboard_score += 1
        elif len(raw) == 4:
            mouse_score += 1
        elif len(raw) > 16:
            bulk_score += 1

    print(f"  Keyboard score : {keyboard_score}")
    print(f"  Mouse score    : {mouse_score}")
    print(f"  Bulk score     : {bulk_score}")

    scores   = {'keyboard': keyboard_score, 'mouse': mouse_score, 'bulk': bulk_score}
    detected = max(scores, key=scores.get)

    print(f"\n[+] Detected: {detected.upper()}\n")

    if detected == 'keyboard':
        decode_keyboard(data_list)
    elif detected == 'mouse':
        decode_mouse(data_list)
    else:
        decode_printer(data_list)
        decode_storage(data_list)


# ══════════════════════════════════════════════════════════════
#  HEX DUMP — Raw packet inspection
# ══════════════════════════════════════════════════════════════

def hex_dump(data_list, limit=30):
    print("=" * 60)
    print("  🔬  HEX DUMP")
    print("=" * 60)
    for i, raw in enumerate(data_list[:limit]):
        hex_str = ' '.join(f'{b:02x}' for b in raw)
        asc_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw)
        print(f"  [{i:03d}] len={len(raw):3d} | {hex_str:<48} | {asc_str}")


# ══════════════════════════════════════════════════════════════
#  PART I — MAIN ENTRY POINT
#  Parses arguments and routes to the correct decoder
# ══════════════════════════════════════════════════════════════

def main():
    banner()

    parser = argparse.ArgumentParser(description='USB PCAP CTF Solver')
    parser.add_argument('pcap', help='Path to .pcap file')
    parser.add_argument('--mode', default='auto',
        choices=['auto', 'keyboard', 'mouse', 'printer', 'storage', 'hex'])
    parser.add_argument('--all', action='store_true',
        help='Run ALL decoders')

    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"[!] File not found: {args.pcap}")
        sys.exit(1)

    data_list = extract_usb_data(args.pcap)

    if not data_list:
        print("[!] No USB data found.")
        sys.exit(1)

    hex_dump(data_list, limit=10)
    print()

    if args.all:
        decode_keyboard(data_list)
        decode_mouse(data_list)
        decode_printer(data_list)
        decode_storage(data_list)
    else:
        mode = args.mode
        if mode == 'auto':       auto_detect(data_list, args.pcap)
        elif mode == 'keyboard': decode_keyboard(data_list)
        elif mode == 'mouse':    decode_mouse(data_list)
        elif mode == 'printer':  decode_printer(data_list)
        elif mode == 'storage':  decode_storage(data_list)
        elif mode == 'hex':      hex_dump(data_list, limit=100)

    print("\n[✓] Done!")


if __name__ == '__main__':
    main()
```

---

*Manual version 1.0 — USB PCAP CTF Solver*

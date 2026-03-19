#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RemcosConfig Extractor v2.0
Developed by Angel Gil && Jorge Gonzalez
HACKCON_RD 2026

Extracts and decrypts configuration from unpacked Remcos RAT samples.
Supports: Remcos v1.x - v4.x
"""

import json
import struct
import sys
import os
import hashlib
import math
import argparse
import csv
from datetime import datetime

# --- Encoding fix for Windows terminals ---
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# --- Optional: pefile ---
try:
    import pefile
except ImportError:
    print("[-] pefile required: pip install pefile")
    sys.exit(1)

# --- Optional: colorama ---
try:
    from colorama import init, Fore, Style
    init()
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = ""; GREEN = ""; YELLOW = ""; CYAN = ""
        MAGENTA = ""; WHITE = ""; BLUE = ""; RESET = ""
    class Style:
        BRIGHT = ""; DIM = ""; RESET_ALL = ""


# ============================================================================
#  CONSTANTS
# ============================================================================

VERSION = "2.0"

# Remcos config field mapping (by index after pipe-split)
# Format: index -> (field_name, category, display_name, field_type)
# field_type: "string", "flag", "int", "c2", "path"
CONFIG_FIELDS = {
    0:  ("c2_hosts",            "network",       "C2 Hosts",               "c2"),
    1:  ("bot_name",            "identity",      "Bot Name / Campaign",    "string"),
    2:  ("connect_interval",    "network",       "Connect Interval (s)",   "int"),
    3:  ("install_flag",        "persistence",   "Install to System",      "flag"),
    4:  ("hkcu_run",            "persistence",   "HKCU\\Run Key",          "flag"),
    5:  ("hklm_run",            "persistence",   "HKLM\\Run Key",          "flag"),
    6:  ("startup_folder",      "persistence",   "Startup Folder",         "flag"),
    7:  ("sched_task",          "persistence",   "Scheduled Task",         "flag"),
    8:  ("task_trigger",        "persistence",   "Task Trigger",           "string"),
    9:  ("task_name",           "persistence",   "Task Name",              "string"),
    10: ("reg_key_name",        "persistence",   "Registry Key Name",      "string"),
    11: ("startup_value",       "persistence",   "Startup Value Name",     "string"),
    12: ("install_root",        "paths",         "Install Root",           "string"),
    13: ("install_subfolder",   "paths",         "Install Subfolder",      "string"),
    14: ("install_filename",    "paths",         "Install Filename",       "string"),
    15: ("keylog_flag",         "surveillance",  "Keylogger",              "flag"),
    16: ("keylog_encrypt",      "surveillance",  "Keylog Encryption",      "flag"),
    17: ("keylog_online",       "surveillance",  "Online Keylogger",       "flag"),
    18: ("screenshot_flag",     "surveillance",  "Screenshots",            "flag"),
    19: ("screenshot_interval", "surveillance",  "Screenshot Interval",    "int"),
    20: ("copy_filename",       "paths",         "Copy Filename",          "string"),
    21: ("clipboard_flag",      "surveillance",  "Clipboard Monitor",      "flag"),
    22: ("webcam_flag",         "surveillance",  "Webcam Capture",         "flag"),
    23: ("process_inject_flag", "evasion",       "Process Injection",      "flag"),
    24: ("uac_bypass_flag",     "evasion",       "UAC Bypass",             "flag"),
    25: ("watchdog_flag",       "evasion",       "Watchdog",               "flag"),
    26: ("defender_excl_flag",  "evasion",       "Defender Exclusion",     "flag"),
    27: ("hide_window_flag",    "evasion",       "Hide Window",            "flag"),
    28: ("mutex",               "identity",      "Mutex",                  "string"),
    29: ("tls_flag",            "network",       "TLS Enabled",            "flag"),
    30: ("tls_cert",            "network",       "TLS Certificate",        "string"),
    31: ("c2_password",         "network",       "C2 Password",            "string"),
    32: ("ping_interval",       "network",       "Ping Interval (s)",      "int"),
    33: ("max_packet_size",     "network",       "Max Packet Size",        "int"),
    34: ("keylog_filename",     "paths",         "Keylog Filename",        "string"),
    35: ("audio_flag",          "surveillance",  "Audio Capture",          "flag"),
    36: ("audio_record_time",   "surveillance",  "Audio Record Time",      "int"),
    37: ("browser_stealer",     "surveillance",  "Browser Stealer",        "flag"),
    38: ("file_manager",        "surveillance",  "File Manager",           "flag"),
    39: ("screen_recorder",     "surveillance",  "Screen Recorder",        "flag"),
    40: ("rdp_wrapper",         "surveillance",  "RDP Wrapper",            "flag"),
    41: ("inj_target_1",       "evasion",       "Injection Target 1",     "string"),
    42: ("inj_target_2",       "evasion",       "Injection Target 2",     "string"),
    43: ("inj_target_3",       "evasion",       "Injection Target 3",     "string"),
    44: ("inj_target_4",       "evasion",       "Injection Target 4",     "string"),
    52: ("screenshots_dir",     "paths",         "Screenshots Directory",  "string"),
    76: ("audio_dir",           "paths",         "Audio Directory",        "string"),
    98: ("keylog_dir",          "paths",         "Keylog Directory",       "string"),
}

# Category display order and colors
CATEGORIES = {
    "network":       ("NETWORK",       Fore.CYAN),
    "identity":      ("IDENTITY",      Fore.MAGENTA),
    "persistence":   ("PERSISTENCE",   Fore.YELLOW),
    "surveillance":  ("SURVEILLANCE",  Fore.RED),
    "evasion":       ("EVASION",       Fore.RED),
    "paths":         ("PATHS & FILES", Fore.BLUE),
    "unknown":       ("OTHER FIELDS",  Fore.WHITE),
}

CATEGORY_ORDER = ["network", "identity", "persistence", "surveillance", "evasion", "paths", "unknown"]


# ============================================================================
#  BOX DRAWING HELPERS
# ============================================================================

BOX_WIDTH = 72

def box_top(title="", color=""):
    """Draw top border with optional title"""
    r = Fore.RESET if HAS_COLOR else ""
    if title:
        title_str = f" {title} "
        line = f"  {color}{Style.BRIGHT}+{'=' * BOX_WIDTH}+{Style.RESET_ALL}"
        return line + f"\n  {color}{Style.BRIGHT}|{r}  {color}{Style.BRIGHT}{title_str:<{BOX_WIDTH - 2}}{color}|{Style.RESET_ALL}"
    return f"  {color}+{'-' * BOX_WIDTH}+{Style.RESET_ALL}"


def box_line(text="", color="", indent=2):
    """Draw a line inside a box"""
    r = Style.RESET_ALL if HAS_COLOR else ""
    c = color if color else ""
    content = f"{'  ' * indent}{text}"
    padding = BOX_WIDTH - 2 - len(content.replace(Fore.RED, "").replace(Fore.GREEN, "").replace(Fore.YELLOW, "").replace(Fore.CYAN, "").replace(Fore.MAGENTA, "").replace(Fore.WHITE, "").replace(Fore.BLUE, "").replace(Style.BRIGHT, "").replace(Style.DIM, "").replace(Style.RESET_ALL, "").replace(Fore.RESET, ""))
    if padding < 0:
        padding = 0
    return f"  {c}|{r}  {text}{' ' * padding}{c}|{r}"


def box_separator(color=""):
    """Draw a separator inside a box"""
    r = Style.RESET_ALL if HAS_COLOR else ""
    return f"  {color}|{'-' * BOX_WIDTH}|{r}"


def box_bottom(color=""):
    """Draw bottom border"""
    return f"  {color}+{'-' * BOX_WIDTH}+{Style.RESET_ALL}"


def box_bottom_double(color=""):
    """Draw bottom border with double line"""
    return f"  {color}{Style.BRIGHT}+{'=' * BOX_WIDTH}+{Style.RESET_ALL}"


def flag_str(value):
    """Format a boolean flag as colored ON/OFF"""
    if isinstance(value, (int, float)):
        is_on = value > 0
    elif isinstance(value, str):
        is_on = value.lower() in ("1", "true", "yes", "enabled", "on")
    elif isinstance(value, bool):
        is_on = value
    else:
        is_on = bool(value)

    if is_on:
        return f"{Fore.GREEN}{Style.BRIGHT}[ON] {Style.RESET_ALL}"
    else:
        return f"{Fore.RED}[OFF]{Style.RESET_ALL}"


# ============================================================================
#  BANNER
# ============================================================================

def print_banner():
    """Print the ASCII art banner"""
    c = Fore.CYAN if HAS_COLOR else ""
    r = Style.RESET_ALL if HAS_COLOR else ""
    y = Fore.YELLOW if HAS_COLOR else ""
    w = Fore.WHITE if HAS_COLOR else ""
    b = Style.BRIGHT if HAS_COLOR else ""
    d = Style.DIM if HAS_COLOR else ""

    banner = f"""
  {c}{b}+========================================================================+
  |                                                                        |
  |{r}  {c} ____                               ____             __ _            {c}{b}|
  |{r}  {c}|  _ \\ ___ _ __ ___   ___ ___  ___ / ___|___  _ __  / _(_) __ _     {c}{b}|
  |{r}  {c}| |_) / _ \\ '_ ` _ \\ / __/ _ \\/ __| |   / _ \\| '_ \\| |_| |/ _` |   {c}{b}|
  |{r}  {c}|  _ <  __/ | | | | | (_| (_) \\__ \\ |__| (_) | | | |  _| | (_| |   {c}{b}|
  |{r}  {c}|_| \\_\\___|_| |_| |_|\\___\\___/|___/\\____\\___/|_| |_|_| |_|\\__, |   {c}{b}|
  |{r}  {c}                                                            |___/    {c}{b}|
  |                                                                        |
  |{r}  {y}{b}               E X T R A C T O R   v{VERSION}                         {c}{b}|
  |                                                                        |
  |{r}  {w}{d}   Developed by Angel Gil && Jorge Gonzalez                        {c}{b}|
  |{r}  {w}{d}   HACKCON_RD 2026                                                 {c}{b}|
  |                                                                        |
  +========================================================================+{r}
"""
    print(banner)


# ============================================================================
#  CRYPTO
# ============================================================================

def rc4_decrypt(data: bytes, key: bytes) -> bytes:
    """RC4 (ARC4) stream cipher decryption"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]

    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


# ============================================================================
#  PE ANALYSIS
# ============================================================================

def calculate_hashes(filepath: str) -> dict:
    """Calculate file hashes (MD5, SHA-1, SHA-256)"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        data = f.read()
        md5.update(data)
        sha1.update(data)
        sha256.update(data)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size": len(data),
    }


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def detect_packer(filepath: str) -> str:
    """Basic packer detection via section entropy and known signatures"""
    try:
        pe = pefile.PE(filepath)
    except Exception:
        return "Error loading PE"

    packers = []

    # Check section entropy
    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="replace").strip("\x00")
        entropy = calculate_entropy(section.get_data())
        if entropy > 7.2:
            packers.append(f"High entropy section: {name} ({entropy:.2f})")

    # Check known packer signatures
    section_names = [s.Name.decode("utf-8", errors="replace").strip("\x00").lower() for s in pe.sections]

    if "upx0" in section_names or "upx1" in section_names:
        packers.append("UPX")
    if ".themida" in section_names:
        packers.append("Themida")
    if ".vmp" in section_names or ".vmp0" in section_names:
        packers.append("VMProtect")
    if "aspack" in section_names:
        packers.append("ASPack")
    if ".ndata" in section_names:
        packers.append("NSIS Installer")

    # Check overlay
    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset:
        overlay_size = os.path.getsize(filepath) - overlay_offset
        if overlay_size > 1024:
            packers.append(f"Overlay data ({overlay_size:,} bytes)")

    pe.close()

    if packers:
        return ", ".join(packers)
    return "None detected"


def detect_remcos_version(filepath: str) -> str:
    """Try to detect Remcos version from PE resources or strings"""
    try:
        with open(filepath, "rb") as f:
            data = f.read()

        # Search for version string patterns in binary
        patterns = [
            b"Remcos v",
            b"Remcos_v",
            b"remcos v",
        ]
        for pattern in patterns:
            idx = data.find(pattern)
            if idx != -1:
                # Extract version string (up to 20 chars after pattern)
                version_raw = data[idx:idx + 30]
                version_str = ""
                for b in version_raw:
                    if 0x20 <= b <= 0x7E:
                        version_str += chr(b)
                    else:
                        break
                if version_str:
                    return version_str

        # Check PE version info
        pe = pefile.PE(filepath)
        if hasattr(pe, "VS_FIXEDFILEINFO"):
            ffi = pe.VS_FIXEDFILEINFO[0]
            major = (ffi.FileVersionMS >> 16) & 0xFFFF
            minor = ffi.FileVersionMS & 0xFFFF
            build = (ffi.FileVersionLS >> 16) & 0xFFFF
            if major > 0:
                return f"v{major}.{minor}.{build}"
        pe.close()

    except Exception:
        pass

    return "Unknown"


# ============================================================================
#  CONFIG EXTRACTION
# ============================================================================

def extract_settings_resource(filepath: str) -> bytes:
    """Extract RCDATA/SETTINGS resource from PE file"""
    pe = pefile.PE(filepath)

    RT_RCDATA = 10

    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        raise ValueError("PE has no resource directory")

    # Strategy 1: Look for SETTINGS/SETTING named resource
    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if res_type.id == RT_RCDATA or (res_type.name and str(res_type.name).upper() == "RCDATA"):
            for res_name in res_type.directory.entries:
                name = str(res_name.name) if res_name.name else ""
                if "SETTINGS" in name.upper() or "SETTING" in name.upper():
                    for res_lang in res_name.directory.entries:
                        data_rva = res_lang.data.struct.OffsetToData
                        size = res_lang.data.struct.Size
                        data = pe.get_data(data_rva, size)
                        pe.close()
                        return data

    # Strategy 2: Look for any RCDATA resource (fallback for obfuscated names)
    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if res_type.id == RT_RCDATA or (res_type.name and str(res_type.name).upper() == "RCDATA"):
            for res_name in res_type.directory.entries:
                for res_lang in res_name.directory.entries:
                    data_rva = res_lang.data.struct.OffsetToData
                    size = res_lang.data.struct.Size
                    data = pe.get_data(data_rva, size)
                    # Heuristic: Remcos config is typically 200-5000 bytes
                    if 50 < size < 10000:
                        pe.close()
                        return data

    pe.close()
    raise ValueError("Cannot locate RCDATA/SETTINGS resource in PE")


def parse_c2_hosts(raw_value):
    """Parse C2 host string into structured list: host:port:password"""
    c2_list = []
    if isinstance(raw_value, list):
        entries = raw_value
    elif isinstance(raw_value, str):
        entries = [raw_value]
    else:
        return [{"raw": str(raw_value)}]

    for entry in entries:
        if isinstance(entry, str) and ":" in entry:
            parts = entry.split(":")
            c2 = {"host": parts[0]}
            if len(parts) > 1:
                c2["port"] = parts[1]
            if len(parts) > 2:
                c2["password"] = parts[2] if parts[2] else "(none)"
            else:
                c2["password"] = "(none)"
            c2_list.append(c2)
        else:
            c2_list.append({"raw": str(entry)})

    return c2_list


def remcos_decrypt_config(filepath: str) -> dict:
    """Extract and decrypt Remcos configuration from PE"""
    settings = extract_settings_resource(filepath)

    key_length = settings[0]
    key = settings[1: 1 + key_length]
    decrypted = rc4_decrypt(settings[1 + key_length:], key)

    res = {
        "_rc4_key_hex": key.hex(),
        "_rc4_key_ascii": key.decode("ascii", errors="replace"),
        "_rc4_key_length": key_length,
        "_raw_fields": {},
    }

    for i, val in enumerate(decrypted.split(b"|")):
        field_info = CONFIG_FIELDS.get(i)

        if val in (b"\x1e\x1e\x1f", b"\x00", b""):
            continue

        # Handle sub-values separated by \x1e
        if b"\x1e" in val:
            vals = val.split(b"\x1e")
        else:
            vals = [val]

        values = []
        for v in vals:
            if not v:
                continue
            value = None

            # Try ASCII decode
            if value is None and b"\x00" not in v[:-1]:
                try:
                    if v.endswith(b"\x00"):
                        value = v[:-1].decode("ascii")
                    else:
                        value = v.decode("ascii")
                except Exception:
                    pass

            # Try UTF-16-LE decode
            if value is None and len(v) > 4:
                try:
                    if v.endswith(b"\x00\x00"):
                        value = v[:-2].decode("utf-16-le")
                    else:
                        value = v.decode("utf-16-le")
                except Exception:
                    pass

            # Try integer decode
            if value is None and len(v) == 4:
                value, = struct.unpack("<I", v)
            if value is None and len(v) == 2:
                value, = struct.unpack("<H", v)
            if value is None and len(v) == 1:
                value, = struct.unpack("<B", v)

            if value is None:
                value = v.hex()
            if value is not None:
                values.append(value)

        if not values:
            continue

        final_value = values[0] if len(values) == 1 else values

        if field_info:
            field_name, category, display_name, field_type = field_info
            res[field_name] = final_value
            res["_raw_fields"][i] = {
                "name": field_name,
                "category": category,
                "display": display_name,
                "type": field_type,
                "value": final_value,
                "index": i,
            }
        else:
            field_name = f"FIELD_{i}"
            res[field_name] = final_value
            res["_raw_fields"][i] = {
                "name": field_name,
                "category": "unknown",
                "display": f"Unknown Field {i}",
                "type": "string",
                "value": final_value,
                "index": i,
            }

    return res


# ============================================================================
#  PRETTY PRINTING
# ============================================================================

def print_sample_info(filepath, hashes, packer_info, remcos_version):
    """Print sample information box"""
    c = Fore.CYAN
    w = Fore.WHITE
    y = Fore.YELLOW
    r = Style.RESET_ALL

    filename = os.path.basename(filepath)

    print(box_top("SAMPLE INFO", c))
    print(box_line(f"{w}File      : {Style.BRIGHT}{filename}{r}"))
    print(box_line(f"{w}SHA-256   : {y}{hashes['sha256']}{r}"))
    print(box_line(f"{w}MD5       : {y}{hashes['md5']}{r}"))
    print(box_line(f"{w}SHA-1     : {y}{hashes['sha1']}{r}"))
    print(box_line(f"{w}Size      : {w}{hashes['size']:,} bytes{r}"))
    print(box_line(f"{w}Packer    : {w}{packer_info}{r}"))
    print(box_line(f"{w}Remcos    : {Fore.GREEN}{Style.BRIGHT}{remcos_version}{r}"))
    print(box_bottom_double(c))
    print()


def print_rc4_info(config):
    """Print RC4 key information box"""
    c = Fore.MAGENTA
    y = Fore.YELLOW
    w = Fore.WHITE
    r = Style.RESET_ALL

    print(box_top("RC4 KEY", c))
    print(box_line(f"{w}Hex       : {y}{config['_rc4_key_hex']}{r}"))
    print(box_line(f"{w}ASCII     : {y}{config['_rc4_key_ascii']}{r}"))
    print(box_line(f"{w}Length    : {w}{config['_rc4_key_length']} bytes{r}"))
    print(box_bottom(c))
    print()


def print_category_box(category_key, fields, config):
    """Print a category box with its fields"""
    if not fields:
        return

    cat_display, cat_color = CATEGORIES.get(category_key, (category_key.upper(), Fore.WHITE))
    r = Style.RESET_ALL
    w = Fore.WHITE

    print(box_top(cat_display, cat_color))

    for field in fields:
        display_name = field["display"]
        value = field["value"]
        field_type = field["type"]

        # Format value based on type
        if field_type == "c2":
            c2_list = parse_c2_hosts(value)
            for idx, c2 in enumerate(c2_list, 1):
                if "raw" in c2:
                    print(box_line(f"{Fore.RED}{Style.BRIGHT}[C2 #{idx}]  {c2['raw']}{r}"))
                else:
                    host = c2.get("host", "?")
                    port = c2.get("port", "?")
                    pwd = c2.get("password", "(none)")
                    print(box_line(f"{Fore.RED}{Style.BRIGHT}[C2 #{idx}]  {host}:{port}  {Style.DIM}(password: {pwd}){r}"))

        elif field_type == "flag":
            flag = flag_str(value)
            print(box_line(f"{w}{display_name:<22} {flag}{r}"))

        elif field_type == "int":
            if isinstance(value, list):
                val_str = ", ".join(str(v) for v in value)
            else:
                val_str = str(value)
            print(box_line(f"{w}{display_name:<22} : {Fore.YELLOW}{val_str}{r}"))

        else:  # string, path
            if isinstance(value, list):
                val_str = ", ".join(str(v) for v in value)
            else:
                val_str = str(value)
            print(box_line(f"{w}{display_name:<22} : {Fore.YELLOW}{val_str}{r}"))

    print(box_bottom(cat_color))
    print()


def print_config(config):
    """Print full config organized by categories"""
    raw_fields = config.get("_raw_fields", {})

    for category_key in CATEGORY_ORDER:
        # Collect fields for this category
        fields = [f for f in raw_fields.values() if f["category"] == category_key]
        if fields:
            # Sort by index
            fields.sort(key=lambda x: x["index"])
            print_category_box(category_key, fields, config)


def print_summary(all_configs, all_hashes):
    """Print batch summary at the end"""
    c = Fore.GREEN
    y = Fore.YELLOW
    w = Fore.WHITE
    r = Style.RESET_ALL

    if len(all_configs) < 2:
        return

    # Collect unique values
    unique_c2 = set()
    unique_mutex = set()
    unique_rc4 = set()
    unique_campaigns = set()

    for config in all_configs:
        raw_fields = config.get("_raw_fields", {})

        # C2 hosts
        if "c2_hosts" in config:
            c2_list = parse_c2_hosts(config["c2_hosts"])
            for c2 in c2_list:
                if "host" in c2:
                    unique_c2.add(f"{c2['host']}:{c2.get('port', '?')}")
                elif "raw" in c2:
                    unique_c2.add(c2["raw"])

        # Mutex
        if "mutex" in config:
            unique_mutex.add(str(config["mutex"]))

        # RC4 key
        unique_rc4.add(config.get("_rc4_key_hex", ""))

        # Campaign
        if "bot_name" in config:
            unique_campaigns.add(str(config["bot_name"]))

    print()
    print(box_top("BATCH SUMMARY", c))
    print(box_line(f"{w}Samples processed   : {y}{len(all_configs)}{r}"))
    print(box_line(f"{w}Unique C2 servers   : {y}{len(unique_c2)}{r}"))
    for c2 in sorted(unique_c2):
        print(box_line(f"{Fore.RED}  >> {c2}{r}"))
    print(box_line(f"{w}Unique mutexes      : {y}{len(unique_mutex)}{r}"))
    for mx in sorted(unique_mutex):
        print(box_line(f"{Fore.MAGENTA}  >> {mx}{r}"))
    print(box_line(f"{w}Unique RC4 keys     : {y}{len(unique_rc4)}{r}"))
    for rk in sorted(unique_rc4):
        print(box_line(f"{Fore.CYAN}  >> {rk}{r}"))
    if unique_campaigns:
        print(box_line(f"{w}Campaigns detected  : {y}{len(unique_campaigns)}{r}"))
        for camp in sorted(unique_campaigns):
            print(box_line(f"{Fore.YELLOW}  >> {camp}{r}"))
    print(box_bottom_double(c))
    print()


# ============================================================================
#  EXPORT
# ============================================================================

def export_csv(all_configs, all_hashes, output_file):
    """Export configs to CSV file"""
    if not all_configs:
        return

    # Collect all field names
    all_field_names = set()
    for config in all_configs:
        for key in config:
            if not key.startswith("_"):
                all_field_names.add(key)

    field_names = ["filename", "sha256", "md5", "rc4_key"] + sorted(all_field_names)

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=field_names)
        writer.writeheader()

        for config, hashes in zip(all_configs, all_hashes):
            row = {
                "filename": hashes.get("filename", ""),
                "sha256": hashes.get("sha256", ""),
                "md5": hashes.get("md5", ""),
                "rc4_key": config.get("_rc4_key_hex", ""),
            }
            for key in all_field_names:
                val = config.get(key)
                if isinstance(val, list):
                    row[key] = " | ".join(str(v) for v in val)
                elif val is not None:
                    row[key] = str(val)
                else:
                    row[key] = ""
            writer.writerow(row)

    print(f"  {Fore.GREEN}[+] CSV exported to: {output_file}{Style.RESET_ALL}")


def export_json(all_configs, all_hashes, output_file):
    """Export configs to JSON file"""
    output = []
    for config, hashes in zip(all_configs, all_hashes):
        entry = {
            "file": hashes.get("filename", ""),
            "hashes": {
                "sha256": hashes.get("sha256", ""),
                "md5": hashes.get("md5", ""),
                "sha1": hashes.get("sha1", ""),
            },
            "rc4_key": config.get("_rc4_key_hex", ""),
            "rc4_key_ascii": config.get("_rc4_key_ascii", ""),
            "config": {k: v for k, v in config.items() if not k.startswith("_")},
        }
        output.append(entry)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    print(f"  {Fore.GREEN}[+] JSON exported to: {output_file}{Style.RESET_ALL}")


# ============================================================================
#  MAIN
# ============================================================================

def process_sample(filepath):
    """Process a single Remcos sample"""
    r = Style.RESET_ALL

    # Calculate hashes
    hashes = calculate_hashes(filepath)
    hashes["filename"] = os.path.basename(filepath)

    # Detect packer
    packer_info = detect_packer(filepath)

    # Detect version
    remcos_version = detect_remcos_version(filepath)

    # Print sample info
    print_sample_info(filepath, hashes, packer_info, remcos_version)

    # Extract and decrypt config
    config = remcos_decrypt_config(filepath)

    # Print RC4 key info
    print_rc4_info(config)

    # Print config by categories
    print_config(config)

    return config, hashes


def main():
    parser = argparse.ArgumentParser(
        description="RemcosConfig Extractor v2.0 - Extract config from Remcos RAT samples",
        epilog="Developed by Angel Gil && Jorge Gonzalez | HACKCON_RD 2026",
    )
    parser.add_argument("files", nargs="+", help="Path to unpacked Remcos PE samples")
    parser.add_argument("--json", metavar="FILE", help="Export results to JSON file")
    parser.add_argument("--csv", metavar="FILE", help="Export results to CSV file")
    parser.add_argument("--no-banner", action="store_true", help="Skip ASCII art banner")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    # Disable colors if requested
    global HAS_COLOR
    if args.no_color:
        HAS_COLOR = False
        Fore.RED = Fore.GREEN = Fore.YELLOW = Fore.CYAN = ""
        Fore.MAGENTA = Fore.WHITE = Fore.BLUE = Fore.RESET = ""
        Style.BRIGHT = Style.DIM = Style.RESET_ALL = ""

    # Print banner
    if not args.no_banner:
        print_banner()

    all_configs = []
    all_hashes = []
    total = len(args.files)

    for idx, filepath in enumerate(args.files, 1):
        # Progress indicator for batch
        if total > 1:
            pct = int((idx / total) * 100)
            bar_len = 30
            filled = int(bar_len * idx / total)
            bar = f"{'#' * filled}{'-' * (bar_len - filled)}"
            print(f"\n  {Fore.CYAN}[{bar}] {pct}% ({idx}/{total}) Processing...{Style.RESET_ALL}\n")

        try:
            config, hashes = process_sample(filepath)
            all_configs.append(config)
            all_hashes.append(hashes)

        except Exception as e:
            print(f"\n  {Fore.RED}[ERROR] {filepath}: {e}{Style.RESET_ALL}\n", file=sys.stderr)

    # Batch summary
    print_summary(all_configs, all_hashes)

    # Export
    if args.csv and all_configs:
        export_csv(all_configs, all_hashes, args.csv)

    if args.json and all_configs:
        export_json(all_configs, all_hashes, args.json)

    # Footer
    print(f"  {Style.DIM}Completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()

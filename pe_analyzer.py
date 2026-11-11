#!/usr/bin/env python3
"""
PE File Static Analyzer
------------------------
Parses Windows Portable Executable files (.exe / .dll) and prints header
info, section details with entropy (useful for spotting packed or encrypted
code), imported/exported functions, and a few heuristic notes about
commonly-abused Windows APIs.

This tool ONLY parses file structure - it never executes the file, so it's
safe to point at anything, including real malware samples, as long as you
don't run them.

Usage:
    python3 pe_analyzer.py path/to/file.exe
"""

import argparse
import math
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    import pefile
except ImportError:
    print("This tool requires the 'pefile' library. Install it with:")
    print("    pip install -r requirements.txt")
    sys.exit(1)

# Windows API functions frequently seen in process injection, keylogging,
# anti-analysis, or C2/downloader behavior. Their presence isn't proof of
# anything malicious by itself - plenty of legitimate software uses them
# too - but they're worth a second look during triage.
SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx": "Allocates memory in another process (process injection)",
    "WriteProcessMemory": "Writes to another process's memory (process injection)",
    "CreateRemoteThread": "Starts a thread in another process (process injection)",
    "SetWindowsHookExA": "Installs a system-wide hook (keylogging/monitoring)",
    "SetWindowsHookExW": "Installs a system-wide hook (keylogging/monitoring)",
    "GetAsyncKeyState": "Reads keyboard state (keylogging)",
    "IsDebuggerPresent": "Checks for a debugger (anti-analysis)",
    "CryptEncrypt": "Encrypts data (could indicate ransomware-style behavior)",
    "InternetOpenUrlA": "Makes an HTTP request (possible C2 communication)",
    "URLDownloadToFileA": "Downloads a file from a URL (downloader behavior)",
    "ShellExecuteA": "Launches another program",
}


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string: near 0 = uniform/empty, near 8 = random/encrypted."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def analyze(filepath: Path) -> None:
    pe = pefile.PE(str(filepath), fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ]
    )

    print(f"Analyzing: {filepath.name}")
    print("=" * 60)

    machine = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    compile_time = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc)
    subsystem = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "UNKNOWN")

    print(f"Type              : {'DLL' if pe.is_dll() else 'EXE' if pe.is_exe() else 'Unknown'}")
    print(f"Machine           : {machine}")
    print(f"Compile time      : {compile_time.isoformat()} UTC")
    print(f"Subsystem         : {subsystem}")
    print(f"Number of sections: {pe.FILE_HEADER.NumberOfSections}")

    print("\nSections")
    print("-" * 60)
    print(f"{'Name':<10}{'VirtSize':<12}{'RawSize':<12}{'Entropy':<10}Flag")
    for section in pe.sections:
        name = section.Name.decode(errors="replace").rstrip("\x00")
        entropy = shannon_entropy(section.get_data())
        flag = "possibly packed/encrypted" if entropy > 7.0 else ""
        print(
            f"{name:<10}{section.Misc_VirtualSize:<12}{section.SizeOfRawData:<12}"
            f"{entropy:<10.2f}{flag}"
        )

    print("\nImported DLLs and functions")
    print("-" * 60)
    found_suspicious = set()
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="replace")
            func_names = [imp.name.decode(errors="replace") for imp in entry.imports if imp.name]
            print(f"{dll_name} ({len(func_names)} functions)")
            for func in func_names:
                if func in SUSPICIOUS_IMPORTS:
                    found_suspicious.add((func, SUSPICIOUS_IMPORTS[func]))
    else:
        print("No imports found (or the file uses only ordinal-based imports).")

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        print("\nExported functions")
        print("-" * 60)
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                print(exp.name.decode(errors="replace"))

    print("\nHeuristic notes")
    print("-" * 60)
    if found_suspicious:
        for func, reason in sorted(found_suspicious):
            print(f"[!] {func}: {reason}")
    else:
        print("No commonly-flagged suspicious imports found.")
    print(
        "\nNote: none of this proves malicious intent by itself - plenty of "
        "legitimate software uses these same APIs and techniques. Treat this "
        "as a starting point for deeper analysis, not a verdict."
    )

    pe.close()


def main():
    parser = argparse.ArgumentParser(
        description="Statically analyze a Windows PE file (.exe/.dll) without executing it."
    )
    parser.add_argument("file", help="Path to the PE file to analyze")
    args = parser.parse_args()

    filepath = Path(args.file)
    if not filepath.is_file():
        print(f"Error: '{filepath}' is not a valid file.")
        sys.exit(1)

    try:
        analyze(filepath)
    except pefile.PEFormatError as e:
        print(f"Error: '{filepath}' doesn't look like a valid PE file. ({e})")
        sys.exit(1)


if __name__ == "__main__":
    main()

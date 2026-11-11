# PE File Static Analyzer

A command-line tool that statically analyzes Windows PE files (`.exe` /
`.dll`) — the second step in a malware triage workflow, after hash checking.

## Why static PE analysis matters

Once you've hashed a file and confirmed it's not already a known-bad or
known-good sample, the next step is looking at its structure *without*
running it. This tool inspects:

- **Header info** — machine type, compile timestamp, subsystem
- **Sections** — each section's size and entropy. High entropy (close to 8)
  often means the section is packed or encrypted, a common way malware hides
  its real code from static scanners
- **Imports** — which Windows DLLs and functions the file uses, since the
  APIs a program imports hint strongly at what it actually does
- **Exports** — for DLLs, what functions it makes available to other programs
- **Heuristic notes** — flags a short list of Windows APIs frequently seen
  in process injection, keylogging, anti-debugging, and downloader behavior

This tool only parses file structure — it never executes the file — so it's
safe to point at anything, including real malware samples, as long as you
don't run them.

## Setup

```bash
git clone https://github.com/Dn2z/pe-file-analyzer.git
cd pe-file-analyzer
pip install -r requirements.txt
```

## Usage

```bash
python3 pe_analyzer.py path/to/file.exe
```

## Safe testing

You don't need real malware to try this out — any legitimate Windows `.exe`
or `.dll` already on your system works fine, since the tool only reads
structure, never runs it. For example:

```bash
python3 pe_analyzer.py C:\Windows\System32\notepad.exe
```

You'll see its real header info, sections, and imports. Try a few different
programs and compare — you'll start noticing patterns (e.g. a video game and
a text editor import very different sets of DLLs).

## Example output

```
Analyzing: hello.exe
============================================================
Type              : EXE
Machine           : IMAGE_FILE_MACHINE_AMD64
Compile time      : 2026-09-12T11:29:28+00:00 UTC
Subsystem         : IMAGE_SUBSYSTEM_WINDOWS_CUI
Number of sections: 19

Sections
------------------------------------------------------------
Name      VirtSize    RawSize     Entropy   Flag
.text     27512       27648       6.34
.data     192         512         0.89
...

Imported DLLs and functions
------------------------------------------------------------
KERNEL32.dll (13 functions)
msvcrt.dll (34 functions)

Heuristic notes
------------------------------------------------------------
No commonly-flagged suspicious imports found.
```

## Extending this project

- Add a `--json` output mode so results can feed into other tools
- Flag sections whose *virtual* size is much larger than their *raw* size on
  disk (a classic unpacking-at-runtime indicator)
- Cross-reference imports against a scoring system instead of a flat list
- Combine with the [malware-hash-checker](https://github.com/Dn2z/malware-hash-checker)
  project so one command does both hash lookup and static analysis

## Disclaimer

This tool is for defensive security research and learning. Always analyze
untrusted files in an isolated, offline virtual machine with reverting
snapshots — never on your host machine.

## License

MIT — see [LICENSE](LICENSE).

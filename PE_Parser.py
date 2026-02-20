"""
PE File Parser
Analyzes Windows PE files (.exe, .dll) and prints key information.
Requires: pip install pefile
"""

import sys
import pefile


def print_separator(title=""):
    width = 60
    if title:
        print(f"\n{'=' * 5} {title} {'=' * (width - len(title) - 7)}")
    else:
        print("=" * width)


def check_mz_signature(filepath: str) -> bool:
    """Check if the file starts with the MZ magic bytes."""
    with open(filepath, "rb") as f:
        magic = f.read(2)
    return magic == b"MZ"


def get_dos_stub_message(pe: pefile.PE) -> str:
    """
    Extract the DOS stub message from the PE file.
    The stub lives between offset 0x40 and the start of the PE header (e_lfanew).
    It typically contains 'This program cannot be run in DOS mode.'
    """
    e_lfanew = pe.DOS_HEADER.e_lfanew
    # DOS header is 64 bytes (0x40); stub code starts right after
    stub_start = 0x40
    stub_end = e_lfanew

    stub_bytes = pe.__data__[stub_start:stub_end]

    # Extract printable ASCII strings from the stub
    import re
    strings = re.findall(rb'[\x20-\x7e]{4,}', stub_bytes)
    if strings:
        return b' | '.join(strings).decode(errors='replace')
    return "(no readable message found in DOS stub)"


def is_dll(pe: pefile.PE) -> bool:
    """Check the IMAGE_FILE_DLL characteristic flag (0x2000)."""
    return bool(pe.FILE_HEADER.Characteristics & 0x2000)


def print_exports(pe: pefile.PE):
    """Print exported functions if the file is a DLL."""
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print("  (no export directory found)")
        return

    exports = pe.DIRECTORY_ENTRY_EXPORT.symbols
    if not exports:
        print("  (no exported functions)")
        return

    print(f"  {'Ordinal':<10} {'RVA':<14} Name")
    print(f"  {'-'*7:<10} {'-'*10:<14} {'-'*30}")
    for exp in exports:
        name = exp.name.decode(errors='replace') if exp.name else "<unnamed>"
        rva  = hex(exp.address) if exp.address else "N/A"
        print(f"  {exp.ordinal:<10} {rva:<14} {name}")


def print_sections(pe: pefile.PE):
    """Print all PE sections with key attributes."""
    print(f"  {'Name':<12} {'VirtAddr':<14} {'VirtSize':<12} {'RawSize':<12} {'Entropy':<8} Characteristics")
    print(f"  {'-'*10:<12} {'-'*10:<14} {'-'*10:<12} {'-'*10:<12} {'-'*7:<8} {'-'*20}")
    for section in pe.sections:
        name        = section.Name.decode(errors='replace').strip('\x00')
        virt_addr   = hex(section.VirtualAddress)
        virt_size   = hex(section.Misc_VirtualSize)
        raw_size    = hex(section.SizeOfRawData)
        entropy     = f"{section.get_entropy():.2f}"
        chars       = hex(section.Characteristics)
        print(f"  {name:<12} {virt_addr:<14} {virt_size:<12} {raw_size:<12} {entropy:<8} {chars}")


def analyze_pe(filepath: str):
    print_separator()
    print(f"  PE Analysis: {filepath}")
    print_separator()

    # ── 1. MZ Signature ──────────────────────────────────────────────────────
    print_separator("MZ Signature")
    if check_mz_signature(filepath):
        print("  [✓] MZ signature detected — valid PE file")
    else:
        print("  [✗] MZ signature NOT found — this may not be a PE file")
        sys.exit(1)

    # Load with pefile
    pe = pefile.PE(filepath)

    # ── 2. DOS Stub Message ───────────────────────────────────────────────────
    print_separator("DOS Stub Message")
    print(f"  {get_dos_stub_message(pe)}")

    # ── 3. ImageBase ──────────────────────────────────────────────────────────
    print_separator("ImageBase")
    image_base = pe.OPTIONAL_HEADER.ImageBase
    print(f"  ImageBase: {hex(image_base)}  ({image_base})")

    # ── 4. DLL Check ──────────────────────────────────────────────────────────
    print_separator("DLL Detection")
    dll = is_dll(pe)
    print(f"  Is DLL: {'Yes' if dll else 'No'}")

    # Machine / architecture info (bonus context)
    machine = pe.FILE_HEADER.Machine
    arch = {0x14c: "x86 (32-bit)", 0x8664: "x86-64 (64-bit)",
            0x1c0: "ARM", 0xaa64: "ARM64"}.get(machine, hex(machine))
    print(f"  Architecture: {arch}")

    # ── 5. Exported Functions (DLL only) ──────────────────────────────────────
    if dll:
        print_separator("Exported Functions")
        print_exports(pe)

    # ── 6. Sections ───────────────────────────────────────────────────────────
    print_separator("Sections")
    print_sections(pe)

    print_separator()
    print("  Analysis complete.")
    print_separator()

    pe.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pe_parser.py <path_to_pe_file>")
        print("Example: python pe_parser.py C:\\Windows\\System32\\kernel32.dll")
        sys.exit(1)

    analyze_pe(sys.argv[1])

#!/usr/bin/env python3
"""
lg-switch — LG 45GX950A-B input switcher for Windows
"""

import argparse
import ctypes
import ctypes.wintypes
import json
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Input source values (LG-specific, sent via proprietary VCP code 0xF4)
# ---------------------------------------------------------------------------
INPUTS = {
    "dp":    (0xD0, "DisplayPort"),
    "hdmi1": (0x90, "HDMI 1"),
    "hdmi2": (0x91, "HDMI 2"),
    "usbc":  (0xD1, "USB-C / Thunderbolt"),
}

VCP_CODE        = 0xF4    # LG proprietary input-select code
DDC_DEVICE_ADDR = 0x6E    # 0x37 << 1  (DDC/CI destination address)
NVAPI_OK        = 0
NVAPI_MAX_GPUS  = 64

CONFIG_PATH = Path(__file__).parent / "config.json"

_verbose = False

# ---------------------------------------------------------------------------
# Hotkey parsing (Win32 RegisterHotKey)
# ---------------------------------------------------------------------------
MODIFIERS: dict[str, int] = {
    "ctrl":    0x0002,
    "control": 0x0002,
    "alt":     0x0001,
    "shift":   0x0004,
    "win":     0x0008,
}
MOD_NOREPEAT = 0x4000

VK_CODES: dict[str, int] = {
    **{chr(c): 0x41 + i for i, c in enumerate(range(ord("a"), ord("z") + 1))},
    **{str(d): 0x30 + d for d in range(10)},
    **{f"f{n}": 0x6F + n for n in range(1, 13)},
    "space":    0x20,
    "enter":    0x0D,
    "esc":      0x1B,
    "escape":   0x1B,
    "tab":      0x09,
    "insert":   0x2D,
    "delete":   0x2E,
    "home":     0x24,
    "end":      0x23,
    "pageup":   0x21,
    "pagedown": 0x22,
    "left":     0x25,
    "right":    0x27,
    "up":       0x26,
    "down":     0x28,
    **{f"numpad{d}": 0x60 + d for d in range(10)},
    "numpad*": 0x6A, "numpadmultiply": 0x6A,
    "numpad+": 0x6B, "numpadadd":      0x6B,
    "numpad-": 0x6D, "numpadsubtract": 0x6D,
    "numpad.": 0x6E, "numpaddecimal":  0x6E,
    "numpad/": 0x6F, "numpaddivide":   0x6F,
    # OEM symbols (US layout)
    ";":  0xBA, ":":  0xBA,
    "=":  0xBB, "+":  0xBB,
    ",":  0xBC, "<":  0xBC,
    "-":  0xBD, "_":  0xBD,
    ".":  0xBE, ">":  0xBE,
    "/":  0xBF, "?":  0xBF,
    "`":  0xC0, "~":  0xC0,
    "[":  0xDB, "{":  0xDB,
    "\\": 0xDC, "|":  0xDC,
    "]":  0xDD, "}":  0xDD,
    "'":  0xDE, "\"": 0xDE,
}


def parse_hotkey(hotkey: str) -> tuple[int, int]:
    """Parse 'ctrl+shift+d' into (modifier_flags, vk_code). Raises ValueError on bad input.

    Handles '+' as the key itself: 'ctrl++' or 'ctrl+shift++' — consecutive '+' signs
    (which produce empty tokens after split) are collapsed into a single '+' token.
    """
    raw_tokens = hotkey.split("+")
    # Collapse runs of empty strings (produced by ++ in input) into a single "+" token
    tokens = []
    i = 0
    while i < len(raw_tokens):
        if raw_tokens[i] == "":
            tokens.append("+")
            while i < len(raw_tokens) and raw_tokens[i] == "":
                i += 1
        else:
            tokens.append(raw_tokens[i].strip().lower())
            i += 1
    mods = 0
    vk   = None
    for token in tokens:
        if token in MODIFIERS:
            mods |= MODIFIERS[token]
        elif token in VK_CODES:
            if vk is not None:
                raise ValueError(f"multiple non-modifier keys in hotkey: '{hotkey}'")
            vk = VK_CODES[token]
        else:
            raise ValueError(f"unrecognised hotkey token: '{token}'")
    if vk is None:
        raise ValueError(f"hotkey has no non-modifier key: '{hotkey}'")
    return mods, vk


# ---------------------------------------------------------------------------
# Config file helpers
# ---------------------------------------------------------------------------
def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        sys.exit(
            f"error: config.json not found — run 'python lg_switch.py configure' first"
        )
    try:
        cfg = json.loads(CONFIG_PATH.read_text())
    except json.JSONDecodeError as exc:
        sys.exit(f"error: config.json is not valid JSON: {exc}")

    for key in ("hotkey", "inputs"):
        if key not in cfg:
            sys.exit(f"error: config.json is missing '{key}' — re-run configure")
    if not isinstance(cfg["inputs"], list) or len(cfg["inputs"]) != 2:
        sys.exit("error: config.json 'inputs' must be a list of exactly two input names")
    for inp in cfg["inputs"]:
        if inp not in INPUTS:
            sys.exit(f"error: config.json contains unknown input '{inp}'")
    try:
        parse_hotkey(cfg["hotkey"])
    except ValueError as exc:
        sys.exit(f"error: config.json hotkey invalid: {exc}")

    return cfg


def _save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2) + "\n")


def log(msg: str) -> None:
    if _verbose:
        print(msg)


# ---------------------------------------------------------------------------
# DDC/CI SetVCP packet
#
# LG 45GX950A-B requires source address 0x50 in the DDC/CI packet.
# The Windows DDC/CI API hardcodes 0x51, which the monitor silently ignores.
# We construct the packet manually and inject it via NVAPI raw I2C to
# bypass the Windows stack entirely.
#
# Packet layout:  [src_addr, length, opcode, vcp_code, value_hi, value_lo, checksum]
# Checksum:       XOR of DDC_DEVICE_ADDR and all preceding payload bytes.
# ---------------------------------------------------------------------------
def _build_setvcp(vcp_code: int, value: int) -> list[int]:
    vh  = (value >> 8) & 0xFF
    vl  = value & 0xFF
    pkt = [0x50, 0x84, 0x03, vcp_code, vh, vl]
    checksum = DDC_DEVICE_ADDR
    for b in pkt:
        checksum ^= b
    pkt.append(checksum)
    return pkt


# ---------------------------------------------------------------------------
# NV_I2C_INFO_V3 ctypes struct
#
# The layout must match the NVIDIA SDK header exactly. On 64-bit Windows,
# two consecutive uint8 fields at offsets 8–9 are followed by 6 bytes of
# implicit compiler padding before the first pointer at offset 16.
# We model this explicitly to avoid ctypes alignment surprises.
# ---------------------------------------------------------------------------
class _NV_I2C_INFO(ctypes.Structure):
    _fields_ = [
        ("version",          ctypes.c_uint32),
        ("displayMask",      ctypes.c_uint32),
        ("bIsDDCPort",       ctypes.c_uint8),
        ("i2cDevAddress",    ctypes.c_uint8),
        ("_pad",             ctypes.c_uint8 * 6),
        ("pbI2cRegAddress",  ctypes.c_void_p),
        ("regAddrSize",      ctypes.c_uint32),
        ("_pad2",            ctypes.c_uint32),
        ("pbData",           ctypes.c_void_p),
        ("cbSize",           ctypes.c_uint32),
        ("i2cSpeed",         ctypes.c_uint32),
        ("i2cSpeedKhz",      ctypes.c_uint32),
        ("portId",           ctypes.c_uint8),
        ("_pad3",            ctypes.c_uint8 * 3),
        ("bIsPortIdSet",     ctypes.c_uint32),
    ]

_NV_I2C_VER3 = (3 << 16) | ctypes.sizeof(_NV_I2C_INFO)


# ---------------------------------------------------------------------------
# NVAPI bootstrap helpers
# ---------------------------------------------------------------------------
def _k32() -> ctypes.WinDLL:
    k = ctypes.WinDLL("kernel32")
    k.GetProcAddress.restype  = ctypes.c_void_p
    k.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    k.GetModuleFileNameW.restype  = ctypes.c_uint32
    k.GetModuleFileNameW.argtypes = [ctypes.c_void_p,
                                      ctypes.c_wchar_p, ctypes.c_uint32]
    return k


def _load_nvapi() -> ctypes.CDLL:
    try:
        lib = ctypes.CDLL("nvapi64.dll")
    except OSError:
        sys.exit("error: nvapi64.dll not found — NVIDIA drivers required")

    if _verbose:
        k   = _k32()
        buf = ctypes.create_unicode_buffer(512)
        k.GetModuleFileNameW(ctypes.c_void_p(lib._handle), buf, 512)
        log(f"[debug] nvapi64.dll path : {buf.value}")
        log(f"[debug] NV_I2C_INFO size : {ctypes.sizeof(_NV_I2C_INFO)} bytes")
        log(f"[debug] version field    : 0x{_NV_I2C_VER3:08X}")

    return lib


def _resolve(lib: ctypes.CDLL, func_id: int):
    """Resolve an NVAPI function pointer via nvapi_QueryInterface."""
    k      = _k32()
    handle = ctypes.c_void_p(lib._handle)

    qi_addr = None
    for name in (b"nvapi_QueryInterface", b"nvapi64_QueryInterface"):
        addr = k.GetProcAddress(
            handle, ctypes.cast(ctypes.c_char_p(name), ctypes.c_void_p).value
        )
        if addr:
            qi_addr = addr
            break

    if not qi_addr:
        sys.exit("error: cannot find nvapi_QueryInterface in nvapi64.dll")

    qi  = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_uint32)(qi_addr)
    ptr = qi(func_id)
    if not ptr:
        raise RuntimeError(f"QueryInterface returned NULL for 0x{func_id:08X}")
    return ptr


# ---------------------------------------------------------------------------
# High-level NVAPI operations
# ---------------------------------------------------------------------------
def _nvapi_setup(lib: ctypes.CDLL):
    """Initialise NVAPI, return (gpu_handle, display_mask)."""
    NvAPI_Init = ctypes.CFUNCTYPE(ctypes.c_int)(_resolve(lib, 0x0150E828))
    if NvAPI_Init() != NVAPI_OK:
        sys.exit("error: NvAPI_Initialize failed")
    log("[debug] NvAPI initialised")

    NvAPI_EnumGPUs = ctypes.CFUNCTYPE(
        ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)
    )(_resolve(lib, 0xE5AC921F))

    gpu_arr   = (ctypes.c_void_p * NVAPI_MAX_GPUS)()
    gpu_count = ctypes.c_uint32(0)
    if NvAPI_EnumGPUs(gpu_arr, ctypes.byref(gpu_count)) != NVAPI_OK or gpu_count.value == 0:
        sys.exit("error: no NVIDIA GPUs found")
    log(f"[debug] {gpu_count.value} GPU(s) — using GPU 0")
    gpu = gpu_arr[0]

    NvAPI_GetOutputs = ctypes.CFUNCTYPE(
        ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)
    )(_resolve(lib, 0x1730BFC9))

    mask_val = ctypes.c_uint32(0)
    ret = NvAPI_GetOutputs(gpu, ctypes.byref(mask_val))
    if ret != NVAPI_OK or mask_val.value == 0:
        log(f"[debug] GetConnectedOutputs returned 0x{mask_val.value:08X} (ret={ret}), using fallback masks")
        masks = [1 << i for i in range(8)]
    else:
        masks = [1 << i for i in range(32) if mask_val.value & (1 << i)]
        log(f"[debug] connected output mask = 0x{mask_val.value:08X}  bits: {[hex(m) for m in masks]}")

    return gpu, masks


def _i2c_write(lib: ctypes.CDLL, gpu, masks: list[int], packet: list[int]) -> bool:
    """Send a raw DDC/CI packet via NVAPI I2C. Returns True on success."""
    NvAPI_I2CWrite = ctypes.CFUNCTYPE(
        ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(_NV_I2C_INFO)
    )(_resolve(lib, 0xE812EB07))

    data_buf = (ctypes.c_uint8 * len(packet))(*packet)

    for mask in masks:
        for port_id, port_set in [(0, 0), (1, 1), (2, 1), (3, 1),
                                   (4, 1), (5, 1), (6, 1), (7, 1)]:
            info = _NV_I2C_INFO()
            info.version         = _NV_I2C_VER3
            info.displayMask     = mask
            info.bIsDDCPort      = 1
            info.i2cDevAddress   = DDC_DEVICE_ADDR
            info.pbI2cRegAddress = None
            info.regAddrSize     = 0
            info.pbData          = ctypes.cast(data_buf, ctypes.c_void_p).value
            info.cbSize          = len(packet)
            info.i2cSpeed        = 0xFFFF
            info.i2cSpeedKhz     = 0
            info.portId          = port_id
            info.bIsPortIdSet    = port_set

            ret = NvAPI_I2CWrite(gpu, ctypes.byref(info))
            log(f"[debug]   mask=0x{mask:04X} port={port_id}(set={port_set}) -> "
                f"{'OK' if ret == NVAPI_OK else f'err {ret}'}")

            if ret == NVAPI_OK:
                return True

    return False


# ---------------------------------------------------------------------------
# configure / daemon commands
# ---------------------------------------------------------------------------
def cmd_configure() -> None:
    """Interactive setup — writes config.json."""
    print("Available inputs:", ", ".join(INPUTS))
    print()

    def prompt_input(label: str, exclude: str | None = None) -> str:
        while True:
            val = input(f"{label}: ").strip().lower()
            if val not in INPUTS:
                print(f"  Invalid input '{val}'. Choose from: {', '.join(INPUTS)}")
                continue
            if exclude is not None and val == exclude:
                print(f"  Second input must differ from the first ('{exclude}').")
                continue
            return val

    first  = prompt_input("First input")
    second = prompt_input("Second input", exclude=first)

    while True:
        raw = input("Hotkey — type it as text, e.g. ctrl+shift+d: ").strip()
        try:
            parse_hotkey(raw)
            break
        except ValueError as exc:
            print(f"  {exc}")

    cfg = {"hotkey": raw, "inputs": [first, second]}
    _save_config(cfg)
    print(f"\nSaved to {CONFIG_PATH}")
    print(f"  hotkey : {raw}")
    print(f"  inputs : {first} ↔ {second}")


def cmd_daemon() -> None:
    """Listen for the configured hotkey and toggle between two inputs."""
    cfg   = _load_config()
    mods, vk = parse_hotkey(cfg["hotkey"])
    inputs   = cfg["inputs"]

    lib        = _load_nvapi()
    gpu, masks = _nvapi_setup(lib)

    user32 = ctypes.WinDLL("user32")
    WM_HOTKEY = 0x0312
    HOTKEY_ID = 1

    if not user32.RegisterHotKey(None, HOTKEY_ID, mods | MOD_NOREPEAT, vk):
        sys.exit(
            f"error: RegisterHotKey failed for '{cfg['hotkey']}' "
            "(already in use by another application?)"
        )

    print(f"Listening for {cfg['hotkey']} — Ctrl+C to exit")
    print(f"  will toggle between: {inputs[0]} ↔ {inputs[1]}")

    PM_REMOVE = 0x0001
    msg = ctypes.wintypes.MSG()
    try:
        while True:
            # PeekMessageW + sleep instead of blocking GetMessageW so that
            # Ctrl+C (SIGINT) can be delivered between iterations.
            if not user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, PM_REMOVE):
                time.sleep(0.05)
                continue
            if msg.message == 0x0012:  # WM_QUIT
                break
            if msg.message != WM_HOTKEY:
                continue

            last = cfg.get("last_input")
            target = inputs[1] if last == inputs[0] else inputs[0]

            value, label = INPUTS[target]
            packet = _build_setvcp(VCP_CODE, value)
            log(f"[debug] packet: {[f'0x{b:02X}' for b in packet]}")

            if _i2c_write(lib, gpu, masks, packet):
                print(f"switched to {label}")
                cfg["last_input"] = target
                _save_config(cfg)
            else:
                print(f"error: failed to switch to {label} — run with --verbose for details")
    except KeyboardInterrupt:
        print("\nexiting")
    finally:
        user32.UnregisterHotKey(None, HOTKEY_ID)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lg-switch",
        description=(
            "Switch the active input on an LG 45GX950A-B monitor.\n\n"
            "Uses NVAPI raw I2C to send DDC/CI commands with source address 0x50,\n"
            "bypassing the Windows DDC/CI API which the LG silently ignores."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join([
            "inputs:",
            *[f"  {k:<12} {desc}" for k, (_, desc) in INPUTS.items()],
            "",
            "commands:",
            "  scan         verify monitor is detected on I2C bus",
            "  configure    interactive setup: choose two inputs and a hotkey",
            "  daemon       listen for configured hotkey and toggle inputs",
            "",
            "examples:",
            "  lg-switch dp",
            "  lg-switch usbc",
            "  lg-switch --verbose hdmi1",
            "  lg-switch scan",
            "  lg-switch configure",
            "  lg-switch daemon",
        ]),
    )
    parser.add_argument(
        "input",
        choices=[*INPUTS.keys(), "scan", "configure", "daemon"],
        metavar="input",
        help=f"target input or command: {{{', '.join(INPUTS)}, scan, configure, daemon}}",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="print NVAPI debug info and per-attempt results",
    )
    return parser


def main() -> None:
    global _verbose

    parser = _build_parser()
    args   = parser.parse_args()
    _verbose = args.verbose

    if args.input == "configure":
        cmd_configure()
        return

    if args.input == "daemon":
        cmd_daemon()
        return

    lib        = _load_nvapi()
    gpu, masks = _nvapi_setup(lib)

    if args.input == "scan":
        print(f"connected output mask: 0x{sum(masks):08X}")
        print(f"output bit(s):         {[hex(m) for m in masks]}")
        return

    value, label = INPUTS[args.input]
    packet = _build_setvcp(VCP_CODE, value)
    log(f"[debug] packet: {[f'0x{b:02X}' for b in packet]}")

    if _i2c_write(lib, gpu, masks, packet):
        print(f"switched to {label}")
    else:
        sys.exit(f"error: failed to switch to {label} — run with --verbose for details")


if __name__ == "__main__":
    main()

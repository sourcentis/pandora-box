"""pandora-box-theme: check a theme and draw its screens, without a kiosk."""

from __future__ import annotations

import argparse
import dataclasses
import re
import sys
from pathlib import Path

from pandora_box.device import UsbDevice
from pandora_box.engines import EngineResult, Verdict
from pandora_box.results import FileResult
from pandora_box.ui.base import Screen
from pandora_box.ui.screens import REFERENCE, Renderer, ViewState
from pandora_box.ui.theme import TEXT_SCALES, ThemeError, load_theme, theme_languages

# Made-up file names and device label, in the language of the built-in texts,
# in English for a language a theme adds
SAMPLE_NAMES = {
    "en": {
        "invoice": "Invoices/invoice-2026-10.pdf.exe",
        "budget": "Documents/budget.xlsm",
        "protected": "protected-archive.zip",
        "invoice_previous": "Invoices/invoice-2026-09.pdf",
        "photo_1": "Photos/holidays/IMG_2041.jpg",
        "photo_2": "Photos/holidays/IMG_2040.jpg",
        "notes": "Meeting notes.docx",
        "label": "USB-KEY",
    },
    "fr": {
        "invoice": "Factures/facture-2026-10.pdf.exe",
        "budget": "Documents/budget.xlsm",
        "protected": "archive-protégée.zip",
        "invoice_previous": "Factures/facture-2026-09.pdf",
        "photo_1": "Photos/vacances/IMG_2041.jpg",
        "photo_2": "Photos/vacances/IMG_2040.jpg",
        "notes": "Notes de réunion.docx",
        "label": "CLE-USB",
    },
    "de": {
        "invoice": "Rechnungen/rechnung-2026-10.pdf.exe",
        "budget": "Dokumente/budget.xlsm",
        "protected": "geschütztes-archiv.zip",
        "invoice_previous": "Rechnungen/rechnung-2026-09.pdf",
        "photo_1": "Fotos/urlaub/IMG_2041.jpg",
        "photo_2": "Fotos/urlaub/IMG_2040.jpg",
        "notes": "Besprechungsnotizen.docx",
        "label": "USB-STICK",
    },
    "nl": {
        "invoice": "Facturen/factuur-2026-10.pdf.exe",
        "budget": "Documenten/budget.xlsm",
        "protected": "beveiligd-archief.zip",
        "invoice_previous": "Facturen/factuur-2026-09.pdf",
        "photo_1": "Foto's/vakantie/IMG_2041.jpg",
        "photo_2": "Foto's/vakantie/IMG_2040.jpg",
        "notes": "Vergadernotities.docx",
        "label": "USB-STICK",
    },
}


def sample_states(language: str = "en") -> dict[str, ViewState]:
    """Every screen, with made-up files named in the language of the texts."""
    names = SAMPLE_NAMES.get(language, SAMPLE_NAMES["en"])

    def result(path: str, verdict: Verdict, detection: str = "", error: str = "") -> FileResult:
        engine = EngineResult(
            "clamav", verdict, (detection,) if detection else (), error=error or None
        )
        return FileResult(
            Path("/media/pandora-box", path), 52_000, verdict, (engine,), rel_path=path
        )

    threats = (
        result(names["invoice"], Verdict.MALICIOUS, "Win.Trojan.Agent-1234"),
        result("eicar.com", Verdict.MALICIOUS, "Eicar-Signature"),
        result(names["budget"], Verdict.SUSPICIOUS, "Heuristics.OLE2.ContainsMacros"),
    )
    unscanned = (result(names["protected"], Verdict.ERROR, error="Heuristics.Encrypted.Zip"),)
    recent = (
        threats[0],
        result(names["invoice_previous"], Verdict.CLEAN),
        result(names["photo_1"], Verdict.CLEAN),
        result(names["photo_2"], Verdict.CLEAN),
        result(names["notes"], Verdict.CLEAN),
    )
    device = UsbDevice("/dev/sda1", "vfat", names["label"], "Cruzer Blade", "4C53", "SanDisk")
    info = (
        "PandoraBox 20261014120000 of 2026-10-14 12:00 UTC",
        "Signatures: set 42 of 2026-10-14 06:00 UTC",
        "Engines: malwarebazaar, hashlookup, clamav (1.4.3), yara (1.21.0), heuristics",
    )
    scanning = ViewState(
        Screen.SCANNING,
        device=device,
        usage=(16_008_609_792, 2_254_857_830),
        percent=37,
        done=152,
        total=411,
        threats=1,
        recent=recent,
    )
    return {
        "ready": ViewState(Screen.READY, info=info),
        "unavailable": ViewState(
            Screen.UNAVAILABLE,
            messages=(
                "NO VALID SIGNATURES: no signature set installed",
                "This kiosk cannot scan: insert a signature update device.",
            ),
        ),
        "preparing": ViewState(Screen.SCANNING, device=device),
        "scanning": scanning,
        "threats": ViewState(Screen.THREATS, files=threats),
        "cleaning": ViewState(
            Screen.CLEANING, messages=tuple(f"{f.rel_path} removed" for f in threats[:2])
        ),
        "clean": ViewState(Screen.CLEAN),
        "warning": ViewState(Screen.WARNING, files=threats[2:] + unscanned),
        "cleaned": ViewState(Screen.CLEANED, files=threats),
        "not_cleaned": ViewState(Screen.NOT_CLEANED, files=threats[:1]),
        "not_verified": ViewState(Screen.NOT_VERIFIED, files=unscanned),
        "key_changed": ViewState(Screen.KEY_CHANGED),
        "refused": ViewState(
            Screen.REFUSED, device=UsbDevice("", model="USB Keyboard", vendor="046d:c31c")
        ),
        "refused_composite": ViewState(
            Screen.REFUSED_COMPOSITE,
            device=UsbDevice("", model="USB Flash Disk", vendor="1234:5678"),
        ),
        "error": ViewState(Screen.ERROR, messages=("Cannot mount device: filesystem not allowed",)),
        "service": ViewState(
            Screen.SERVICE,
            messages=(
                "Signature update device: verifying the signature set...",
                "Signatures updated: set 43",
                "A signature update device is not scanned. Remove the device.",
            ),
        ),
        "transferring": ViewState(
            Screen.TRANSFERRING,
            messages=("Copying the clean files to the server...", "Copied: 45% of 2.1GB"),
        ),
        "transferred": ViewState(Screen.TRANSFERRED, files=threats[:2]),
        "transfer_failed": ViewState(
            Screen.TRANSFER_FAILED,
            messages=("Copy to the server FAILED: sftp: [Errno 113] No route to host",),
        ),
    }


def _size(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"(\d+)x(\d+)", value)
    if match is None or not (320 <= int(match[1]) <= 7680 and 240 <= int(match[2]) <= 4320):
        raise argparse.ArgumentTypeError("expected WIDTHxHEIGHT, e.g. 1024x600")
    return int(match[1]), int(match[2])


def _text_scale(value: str) -> float:
    low, high = TEXT_SCALES
    try:
        scale = float(value)
    except ValueError:
        scale = 0.0
    if not low <= scale <= high:
        raise argparse.ArgumentTypeError(f"expected a number from {low:g} to {high:g}")
    return scale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pandora-box-theme", description="Check a kiosk theme and draw its screens"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="check a theme folder")
    preview = sub.add_parser("preview", help="draw every screen into PNG files")
    for command in (check, preview):
        command.add_argument("theme", type=Path, nargs="?", help="theme folder (default: built-in)")
        command.add_argument("--language", default="", help="language of the texts (default: all)")
    preview.add_argument("output", type=Path, help="folder of the PNG files")
    preview.add_argument(
        "--size", type=_size, default=REFERENCE, help="screen size (default: 1024x600)"
    )
    preview.add_argument(
        "--text-scale",
        type=_text_scale,
        help="size of the texts, in place of text_scale of the theme (1 to 1.5)",
    )
    args = parser.parse_args(argv)

    try:
        # Every language of the theme, unless one is given
        languages = [args.language] if args.language else theme_languages(args.theme)
        themes = [load_theme(args.theme, language) for language in languages]
    except ThemeError as ex:
        print(f"pandora-box-theme: {ex}", file=sys.stderr)
        return 2
    if args.command == "check":
        print(f"{args.theme or 'built-in theme'}: OK ({', '.join(languages)})")
        return 0

    args.output.mkdir(parents=True, exist_ok=True)
    for theme in themes:
        if args.text_scale is not None:
            theme = dataclasses.replace(theme, text_scale=args.text_scale)
        renderer = Renderer(theme, args.size)
        for name, state in sample_states(theme.language).items():
            frame = renderer.render(state)
            path = args.output / f"{theme.language}-{name}.png"
            frame.image(0.0).save(path)
            print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

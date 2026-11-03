"""Theme of the graphical interface: logo, colors, images and texts.

The built-in theme (the theme folder of this package) holds every key. An
administrator theme is a folder with a theme.toml and its files: each key it
sets replaces the built-in one. The theme is part of the image: it is checked
when the image is built, and at startup.
"""

from __future__ import annotations

import re
import string
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from PIL import Image, ImageFont

BUILTIN = Path(__file__).with_name("theme")
THEME_FILE = "theme.toml"
# Fonts of the Debian package fonts-dejavu-core
DEJAVU = Path("/usr/share/fonts/truetype/dejavu")

COLORS = (
    "header",
    "header_text",
    "background",
    "text",
    "muted",
    "clean",
    "threat",
    "warning",
    "progress",
    "progress_background",
)
# Contrast ratios required between a color and the color it is drawn on
# (WCAG 2.1 level AA): 4.5 for text, 3 for large bold text (titles, banner,
# percentage) and for the progress bar
CONTRASTS = (
    ("text", "background", 4.5),
    ("muted", "background", 4.5),
    ("clean", "background", 4.5),
    ("threat", "background", 4.5),
    ("warning", "background", 4.5),
    ("header_text", "header", 3.0),
    ("header_text", "threat", 3.0),
    ("header_text", "progress", 3.0),
    ("progress", "progress_background", 3.0),
)
# Size of the texts, relative to the built-in layout
TEXT_SCALES = (1.0, 1.5)
ANIMATIONS = ("insert", "busy")
ICONS = ("clean", "threat", "error")
# Texts and their placeholders
TEXTS: dict[str, frozenset[str]] = {
    name: frozenset(fields)
    for name, fields in {
        "title": (),
        "footer": (),
        "insert": (),
        "insert_help": (),
        "unavailable": (),
        "unavailable_help": (),
        "preparing": (),
        "scanning": (),
        "scanning_help": (),
        "scan_progress": ("done", "total"),
        "scan_threats": ("count",),
        "device_usage": ("size", "used"),
        "threats": (),
        "threats_help": (),
        "threats_warning": (),
        "touch_to_clean": (),
        "cleaning": (),
        "clean": (),
        "clean_help": (),
        "warning": (),
        "warning_help": (),
        "cleaned": (),
        "cleaned_help": ("count",),
        "not_cleaned": (),
        "not_cleaned_help": (),
        "not_verified": (),
        "not_verified_help": (),
        "key_changed": (),
        "key_changed_help": (),
        "refused": (),
        "refused_help": (),
        "refused_composite_help": (),
        "error": (),
        "error_help": (),
        "service": (),
        "transferring": (),
        "transferred": (),
        "transferred_help": (),
        "transferred_left": (),
        "transfer_failed": (),
        "transfer_failed_help": (),
        "more_files": ("count",),
        "verdict_clean": (),
        "verdict_malicious": (),
        "verdict_suspicious": (),
        "verdict_error": (),
        "verdict_skipped": (),
    }.items()
}

_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
# Images of a theme are small: a bigger one is a mistake (or a decompression bomb)
MAX_IMAGE_SIDE = 4096
_FORMATS = ("PNG", "JPEG")

Color = tuple[int, int, int]


class ThemeError(Exception):
    """Raised when a theme is invalid."""


@dataclass(frozen=True)
class Theme:
    language: str
    texts: dict[str, str]
    colors: dict[str, Color]
    logo: Image.Image | None
    insert: tuple[Image.Image, ...]
    busy: tuple[Image.Image, ...]
    icons: dict[str, Image.Image]
    font_path: Path | None = None
    bold_path: Path | None = None
    text_scale: float = 1.0
    _fonts: dict[tuple[int, bool], ImageFont.FreeTypeFont | ImageFont.ImageFont] = field(
        default_factory=dict, compare=False, repr=False
    )

    def text(self, name: str, **values: object) -> str:
        return self.texts[name].format(**values) if values else self.texts[name]

    def font(self, size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
        key = (size, bold)
        if key not in self._fonts:
            path = self.bold_path if bold else self.font_path
            if path is None:
                self._fonts[key] = ImageFont.load_default(size)
            else:
                self._fonts[key] = ImageFont.truetype(str(path), size)
        return self._fonts[key]


def load_theme(folder: Path | None, language: str) -> Theme:
    """The built-in theme, with the keys of the theme of that folder."""
    data = _read(BUILTIN)
    merged = _resolve(data, BUILTIN)
    if folder is not None:
        if not folder.is_dir():
            raise ThemeError(f"theme folder not found: {folder}")
        custom = _read(folder) if (folder / THEME_FILE).exists() else {}
        _merge(merged, _resolve(custom, folder))

    texts = merged["texts"]
    if language not in texts:
        raise ThemeError(
            f"no texts for the language {language!r} (available: {', '.join(sorted(texts))})"
        )
    # A language added by a theme gets the English texts it does not translate
    language_texts = {**texts["en"], **texts[language]}
    for lang, table in texts.items():
        _check_texts(lang, table)

    try:
        font_path = merged["font"] or _dejavu("DejaVuSans.ttf")
        bold_path = merged["font_bold"] or _dejavu("DejaVuSans-Bold.ttf") or font_path
        for path in (font_path, bold_path):
            if path is not None:
                ImageFont.truetype(str(path), 12)
    except OSError as ex:
        raise ThemeError(f"cannot load the font: {ex}") from ex

    colors = {name: _color(name, merged["colors"][name]) for name in COLORS}
    _check_contrasts(colors)
    images = merged["images"]
    return Theme(
        language=language,
        texts=language_texts,
        colors=colors,
        logo=None if merged["logo"] is None else _image(merged["logo"]),
        insert=tuple(_image(path) for path in images["insert"]),
        busy=tuple(_image(path) for path in images["busy"]),
        icons={name: _image(images[name]) for name in ICONS},
        font_path=font_path,
        bold_path=bold_path,
        text_scale=merged["text_scale"],
    )


def theme_languages(folder: Path | None) -> list[str]:
    """The languages of the built-in theme and of the theme of that folder."""
    languages = set(_table(_read(BUILTIN), "texts", BUILTIN))
    if folder is not None and (folder / THEME_FILE).exists():
        languages |= set(_table(_read(folder), "texts", folder))
    return sorted(languages)


def _read(folder: Path) -> dict[str, Any]:
    path = folder / THEME_FILE
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except tomllib.TOMLDecodeError as ex:
        raise ThemeError(f"{path}: invalid TOML: {ex}") from ex
    except OSError as ex:
        raise ThemeError(f"{path}: {ex.strerror}") from ex


def _resolve(data: dict[str, Any], folder: Path) -> dict[str, Any]:
    """Check the keys of a theme.toml; file names become paths in its folder."""
    where = folder / THEME_FILE
    keys = {"logo", "font", "font_bold", "text_scale", "colors", "images", "texts"}
    _reject_unknown(data, keys, where, "")
    out: dict[str, Any] = {"colors": {}, "images": {}, "texts": {}}
    if "text_scale" in data:
        scale = data["text_scale"]
        low, high = TEXT_SCALES
        if (
            isinstance(scale, bool)
            or not isinstance(scale, int | float)
            or not (low <= scale <= high)
        ):
            raise ThemeError(f"{where}: text_scale must be a number from {low:g} to {high:g}")
        out["text_scale"] = float(scale)
    for key in ("logo", "font", "font_bold"):
        if key in data:
            value = data[key]
            if not isinstance(value, str):
                raise ThemeError(f"{where}: {key} must be a file name")
            out[key] = _file(folder, value) if value else None

    colors = _table(data, "colors", where)
    _reject_unknown(colors, COLORS, where, "colors")
    out["colors"] = dict(colors)

    images = _table(data, "images", where)
    _reject_unknown(images, ANIMATIONS + ICONS, where, "images")
    for key, value in images.items():
        if key in ANIMATIONS:
            names = value if isinstance(value, list) else []
            if not names or not all(isinstance(v, str) for v in names):
                raise ThemeError(f"{where}: images.{key} must be a list of file names")
            out["images"][key] = [_file(folder, v) for v in value]
        elif isinstance(value, str) and value:
            out["images"][key] = _file(folder, value)
        else:
            raise ThemeError(f"{where}: images.{key} must be a file name")

    texts = _table(data, "texts", where)
    for language, table in texts.items():
        if not re.match(r"^[a-z]{2}$", language) or not isinstance(table, dict):
            raise ThemeError(f"{where}: [texts.{language}] must be a table of a language code")
        _reject_unknown(table, TEXTS, where, f"texts.{language}")
        if not all(isinstance(v, str) for v in table.values()):
            raise ThemeError(f"{where}: the texts of [texts.{language}] must be strings")
        out["texts"][language] = dict(table)
    return out


def _merge(base: dict[str, Any], custom: dict[str, Any]) -> None:
    for key in ("logo", "font", "font_bold", "text_scale"):
        if key in custom:
            base[key] = custom[key]
    base["colors"].update(custom["colors"])
    base["images"].update(custom["images"])
    for language, table in custom["texts"].items():
        base["texts"].setdefault(language, {}).update(table)


def _table(data: dict[str, Any], key: str, where: Path) -> dict[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ThemeError(f"{where}: [{key}] must be a table")
    return value


def _reject_unknown(table: dict[str, Any], allowed: Any, where: Path, section: str) -> None:
    unknown = sorted(set(table) - set(allowed))
    if unknown:
        name = f"[{section}]" if section else "top level"
        raise ThemeError(f"{where}: unknown key(s) in {name}: {', '.join(unknown)}")


def _file(folder: Path, name: str) -> Path:
    """A file of the theme folder: never a path out of it."""
    path = folder / name
    if Path(name).is_absolute() or ".." in Path(name).parts:
        raise ThemeError(f"{folder / THEME_FILE}: {name} must be a file of the theme folder")
    if not path.is_file():
        raise ThemeError(f"theme file not found: {path}")
    return path


def _check_texts(language: str, table: dict[str, str]) -> None:
    for name, text in table.items():
        try:
            fields = {f for _, f, _, _ in string.Formatter().parse(text) if f is not None}
        except ValueError as ex:
            raise ThemeError(f"texts.{language}.{name}: {ex}") from ex
        unknown = fields - TEXTS[name]
        if unknown:
            allowed = ", ".join(f"{{{f}}}" for f in sorted(TEXTS[name])) or "none"
            raise ThemeError(
                f"texts.{language}.{name}: unknown placeholder(s) "
                f"{', '.join(f'{{{f}}}' for f in sorted(unknown))} (allowed: {allowed})"
            )


def _color(name: str, value: object) -> Color:
    if not isinstance(value, str) or not _COLOR.match(value):
        raise ThemeError(f'colors.{name} must be a color like "#8b0019"')
    return int(value[1:3], 16), int(value[3:5], 16), int(value[5:7], 16)


def contrast(first: Color, second: Color) -> float:
    """Contrast ratio of two colors (WCAG 2.1), from 1 to 21."""

    def luminance(color: Color) -> float:
        channels = [c / 255 for c in color]
        linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    light, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def _check_contrasts(colors: dict[str, Color]) -> None:
    """Every text must be readable on its background (WCAG 2.1 level AA)."""
    low = []
    for front, back, minimum in CONTRASTS:
        ratio = contrast(colors[front], colors[back])
        if ratio < minimum:
            low.append(f"colors.{front} on colors.{back}: {ratio:.2f}:1, at least {minimum:g}:1")
    if low:
        raise ThemeError("contrast too low (WCAG 2.1 AA): " + "; ".join(low))


def _image(path: Path) -> Image.Image:
    try:
        with Image.open(path) as image:
            if image.format not in _FORMATS:
                raise ThemeError(f"{path}: not a PNG or JPEG image")
            if max(image.size) > MAX_IMAGE_SIDE:
                raise ThemeError(f"{path}: image bigger than {MAX_IMAGE_SIDE} pixels")
            return image.convert("RGBA")
    except (OSError, Image.DecompressionBombError) as ex:
        raise ThemeError(f"{path}: cannot read the image: {ex}") from ex


def _dejavu(name: str) -> Path | None:
    path = DEJAVU / name
    return path if path.is_file() else None

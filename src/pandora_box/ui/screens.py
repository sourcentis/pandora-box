"""Screens of the graphical interface, drawn with Pillow.

Drawing is separate from the framebuffer: the screens can be tested and
previewed anywhere (pandora-box-theme preview). File names and device labels
come from the device: they are untrusted, made printable and fitted to their
place, never interpreted.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from PIL import Image, ImageDraw, ImageFont

from pandora_box.device import UsbDevice
from pandora_box.engines import Verdict
from pandora_box.results import FileResult
from pandora_box.text import human_size, printable
from pandora_box.ui.base import Screen
from pandora_box.ui.theme import Color, Theme

Font = ImageFont.FreeTypeFont | ImageFont.ImageFont

# Reference size of the layout: the 7-inch screen of the kiosk
REFERENCE = (1024, 600)
# Files listed on the screen while scanning
RECENT_FILES = 6
# Seconds between two images of the animations
INSERT_INTERVAL = 1.0
BUSY_INTERVAL = 0.12

_ELLIPSIS = "…"


@dataclass(frozen=True)
class ViewState:
    """What the screen shows; the display builds it from the kiosk calls."""

    screen: Screen = Screen.READY
    files: tuple[FileResult, ...] = ()
    info: tuple[str, ...] = ()
    device: UsbDevice | None = None
    usage: tuple[int, int] | None = None
    percent: int = 0
    done: int = 0
    total: int = 0
    threats: int = 0
    current: str = ""
    # The latest scanned files, the latest first
    recent: tuple[FileResult, ...] = ()
    messages: tuple[str, ...] = ()


@dataclass(frozen=True)
class Animation:
    position: tuple[int, int]
    frames: tuple[Image.Image, ...]
    interval: float


@dataclass
class Frame:
    """A drawn screen: its fixed part, its animation and the texts drawn."""

    base: Image.Image
    animation: Animation | None = None
    lines: list[str] = field(default_factory=list)
    # Box of each text drawn, for the layout checks
    boxes: list[tuple[int, int, int, int]] = field(default_factory=list)

    def image(self, now: float = 0.0) -> Image.Image:
        """The screen at that time (seconds), with the animation image of the time."""
        if self.animation is None:
            return self.base
        anim = self.animation
        index = int(now / anim.interval) % len(anim.frames)
        image = self.base.copy()
        frame = anim.frames[index]
        image.paste(frame, anim.position, frame)
        return image


def detection(result: FileResult) -> str:
    """Why a file is listed: the detection names, or the reason it was not scanned."""
    names = sorted(
        {
            r.detail
            for r in result.results
            if r.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS) and r.detail
        }
    )
    if not names and result.unscanned:
        errors = (r for r in result.results if r.verdict is Verdict.ERROR)
        names = sorted({r.detail for r in errors if r.detail})
    return ", ".join(names) or result.detail


class Renderer:
    def __init__(self, theme: Theme, size: tuple[int, int]) -> None:
        self.theme = theme
        self.width, self.height = size
        self.scale = min(self.width / REFERENCE[0], self.height / REFERENCE[1])
        self.text_scale = theme.text_scale
        self._resized: dict[tuple[int, tuple[int, int]], Image.Image] = {}

    # -- helpers -------------------------------------------------------------

    def px(self, value: float) -> int:
        return max(1, round(value * self.scale))

    def tx(self, value: float) -> int:
        """A size that follows the texts: font sizes, lines, rows (theme text_scale)."""
        return self.px(value * self.text_scale)

    def font(self, size: float, bold: bool = False) -> Font:
        return self.theme.font(self.tx(size), bold)

    def color(self, name: str) -> Color:
        return self.theme.colors[name]

    def resized(self, image: Image.Image, box: tuple[int, int]) -> Image.Image:
        """The image fitted into the box, aspect ratio kept (cached)."""
        ratio = min(box[0] / image.width, box[1] / image.height)
        size = (max(1, round(image.width * ratio)), max(1, round(image.height * ratio)))
        key = (id(image), size)
        if key not in self._resized:
            self._resized[key] = image.resize(size, Image.Resampling.LANCZOS)
        return self._resized[key]

    # -- screens -------------------------------------------------------------

    def render(self, state: ViewState) -> Frame:
        frame = Frame(Image.new("RGB", (self.width, self.height), self.color("background")))
        canvas = _Canvas(self, frame)
        top = self._header(canvas)
        bottom = self._footer(canvas, state)
        body = (self.px(32), top + self.px(20), self.width - self.px(32), bottom - self.px(12))
        draw = getattr(self, f"_{state.screen.value}")
        draw(canvas, state, body)
        return frame

    def _header(self, canvas: _Canvas) -> int:
        height = max(self.px(80), self.tx(64))
        canvas.draw.rectangle((0, 0, self.width, height), fill=self.color("header"))
        left = self.px(16)
        logo = self.theme.logo
        if logo is not None:
            image = self.resized(logo, (self.px(240), height - self.px(16)))
            canvas.frame.base.paste(image, (left, (height - image.height) // 2), image)
            left += image.width + self.px(16)
        # Centered on the screen, unless the logo is in the way
        title = self.theme.text("title")
        font = self.font(30, bold=True)
        width = self.width - left - self.px(16)
        text = canvas.fit(title, font, width)
        x = max(left, (self.width - canvas.text_width(text, font)) // 2)
        canvas.text((x, height // 2), text, font, self.color("header_text"), anchor="lm")
        return height

    def _footer(self, canvas: _Canvas, state: ViewState) -> int:
        footer = self.theme.text("footer")
        if not footer:
            return self.height
        height = self.tx(30)
        top = self.height - height
        canvas.draw.line((0, top, self.width, top), fill=self.color("progress_background"))
        font = self.font(16)
        text = canvas.fit(footer, font, self.width - self.px(32))
        canvas.text((self.px(16), top + height // 2), text, font, self.color("muted"), anchor="lm")
        return top

    def _ready(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        left, top, right, bottom = body
        info = state.info[:4]
        info_font = self.font(16)
        info_row = self.tx(21)
        info_top = bottom - len(info) * info_row
        title_font, help_font = self.font(34, True), self.font(18)
        title, help_text = self.theme.text("insert"), self.theme.text("insert_help")
        # The texts above the versions; the animation gets the room left
        # (less with larger texts, or longer ones in another language)
        texts = (
            len(canvas.wrap(title, title_font, right - left)) * canvas.line_height(title_font)
            + self.px(10)
            + len(canvas.wrap(help_text, help_font, right - left)) * canvas.line_height(help_font)
        )
        room = info_top - top - texts - self.px(24 + 12)
        height = min(self.px(240 / self.text_scale), room)
        y = top
        if height >= self.px(40):
            frames = tuple(
                self.resized(image, (self.px(430), height)) for image in self.theme.insert
            )
            x = (self.width - frames[0].width) // 2
            canvas.frame.animation = Animation((x, top), frames, INSERT_INTERVAL)
            y += frames[0].height + self.px(24)
        y = canvas.paragraph(title, title_font, "text", y, body, True)
        y += self.px(10)
        canvas.paragraph(help_text, help_font, "muted", y, body, True)
        for i, line in enumerate(info):
            text = canvas.fit(line, info_font, right - left)
            canvas.text((left, info_top + i * info_row), text, info_font, self.color("muted"))

    def _unavailable(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        y = self._result(canvas, body, "error", "threat", "unavailable", "unavailable_help")
        self._messages(canvas, state.messages[-6:], (body[0], y, body[2], body[3]))

    def _scanning(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        left, _, right, bottom = body
        y = self._busy_title(canvas, self.theme.text("scanning"), body)
        y = canvas.paragraph(self.theme.text("scanning_help"), self.font(18), "muted", y, body)
        y += self.px(6)
        device = self._device_line(state)
        if device:
            y = canvas.paragraph(device, self.font(18), "text", y, body)
        y += self.px(12)
        # Progress bar, the percentage inside
        bar_height = self.tx(34)
        radius = bar_height // 2
        canvas.draw.rounded_rectangle(
            (left, y, right, y + bar_height), radius, fill=self.color("progress_background")
        )
        filled = left + (right - left) * max(0, min(100, state.percent)) // 100
        if filled - left >= bar_height:
            canvas.draw.rounded_rectangle(
                (left, y, filled, y + bar_height), radius, fill=self.color("progress")
            )
        percent = f"{state.percent}%"
        font = self.font(20, bold=True)
        inside = filled - left > canvas.text_width(percent, font) + self.px(24)
        canvas.text(
            (filled - self.px(12) if inside else filled + self.px(12), y + bar_height // 2),
            percent,
            font,
            self.color("header_text") if inside else self.color("text"),
            anchor="rm" if inside else "lm",
        )
        y += bar_height + self.px(12)
        font = self.font(20, bold=True)
        if state.total:
            counts = self.theme.text("scan_progress", done=state.done, total=state.total)
        else:
            counts = self.theme.text("preparing")
        canvas.text((left, y), counts, font, self.color("text"))
        threats = self.theme.text("scan_threats", count=state.threats)
        color = self.color("threat") if state.threats else self.color("muted")
        # Side by side when they fit, else one below the other
        if canvas.text_width(counts, font) + canvas.text_width(threats, font) + self.px(24) > (
            right - left
        ):
            y += self.tx(30)
            canvas.text((left, y), threats, font, color)
        else:
            canvas.text((right, y), threats, font, color, anchor="ra")
        y += self.tx(36)
        self._file_list(canvas, state.recent, (left, y, right, bottom), recent=True)

    def _threats(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        left, top, right, bottom = body
        # The whole screen is the button: a banner tells to touch it, never
        # cut (a long text, large texts: on two lines)
        font = self.font(28, True)
        lines = canvas.wrap(self.theme.text("touch_to_clean"), font, right - left - self.px(24))
        height = canvas.line_height(font)
        banner = max(self.tx(64), len(lines) * height + self.px(16))
        canvas.draw.rounded_rectangle(
            (left, bottom - banner, right, bottom), self.px(12), fill=self.color("threat")
        )
        first = bottom - banner // 2 - (len(lines) - 1) * height // 2
        for i, line in enumerate(lines):
            canvas.text(
                ((left + right) // 2, first + i * height),
                line,
                font,
                self.color("header_text"),
                anchor="mm",
            )
        banner_top = bottom - banner
        y = self._result(
            canvas, (left, top, right, banner_top), "threat", "threat", "threats", "threats_help"
        )
        # The warning above the banner, unless the files then have no room
        # (long texts, large texts): the banner tells what to do
        warning_y = banner_top - self.tx(32)
        listed = self.tx(48) * (2 if len(state.files) > 1 else 1)
        list_bottom = banner_top - self.px(8)
        if y + listed <= warning_y - self.px(8):
            font = self.font(18, bold=True)
            warning = canvas.fit(self.theme.text("threats_warning"), font, right - left)
            canvas.text(
                ((left + right) // 2, warning_y), warning, font, self.color("threat"), anchor="ma"
            )
            list_bottom = warning_y - self.px(8)
        self._file_list(canvas, state.files, (left, y, right, list_bottom))

    def _cleaning(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        y = self._busy_title(canvas, self.theme.text("cleaning"), body)
        self._messages(canvas, state.messages[-8:], (body[0], y, body[2], body[3]))

    def _clean(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        self._result(canvas, body, "clean", "clean", "clean", "clean_help")

    def _warning(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        y = self._result(canvas, body, "threat", "warning", "warning", "warning_help")
        self._file_list(canvas, state.files, (body[0], y, body[2], body[3]))

    def _cleaned(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        help_text = self.theme.text("cleaned_help", count=len(state.files))
        y = self._result(canvas, body, "clean", "clean", "cleaned", help_text=help_text)
        self._file_list(canvas, state.files, (body[0], y, body[2], body[3]))

    def _not_cleaned(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        y = self._result(canvas, body, "threat", "threat", "not_cleaned", "not_cleaned_help")
        self._file_list(canvas, state.files, (body[0], y, body[2], body[3]))

    def _not_verified(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        y = self._result(canvas, body, "error", "threat", "not_verified", "not_verified_help")
        self._file_list(canvas, state.files, (body[0], y, body[2], body[3]))

    def _key_changed(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        self._result(canvas, body, "threat", "threat", "key_changed", "key_changed_help")

    def _refused(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        y = self._result(canvas, body, "error", "threat", "refused", "refused_help")
        self._refused_device(canvas, state, (body[0], y, body[2], body[3]))

    def _refused_composite(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        y = self._result(canvas, body, "threat", "threat", "refused", "refused_composite_help")
        self._refused_device(canvas, state, (body[0], y, body[2], body[3]))

    def _refused_device(self, canvas: _Canvas, state: ViewState, box: Box) -> None:
        """The name the device gives and its identifiers, as USBGuard saw them."""
        line = self._device_line(state)
        if not line:
            return
        font = self.font(18)
        canvas.text((box[0], box[1]), canvas.fit(line, font, box[2] - box[0]), font,
                    self.color("muted"))  # fmt: skip

    def _error(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        y = self._result(canvas, body, "error", "threat", "error", "error_help")
        self._messages(canvas, state.messages[-3:], (body[0], y, body[2], body[3]))

    def _transferring(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        y = self._busy_title(canvas, self.theme.text("transferring"), body)
        self._messages(canvas, state.messages[-8:], (body[0], y, body[2], body[3]))

    def _transferred(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        # The files listed are those not copied
        y = self._result(canvas, body, "clean", "clean", "transferred", "transferred_help")
        if state.files:
            font = self.font(18, bold=True)
            canvas.text((body[0], y), self.theme.text("transferred_left"), font, self.color("text"))
            y += self.tx(30)
        self._file_list(canvas, state.files, (body[0], y, body[2], body[3]))

    def _transfer_failed(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        y = self._result(canvas, body, "error", "threat", "transfer_failed", "transfer_failed_help")
        self._messages(canvas, state.messages[-3:], (body[0], y, body[2], body[3]))

    def _service(self, canvas: _Canvas, state: ViewState, body: Box) -> None:
        font = self.font(30, bold=True)
        canvas.text((body[0], body[1]), self.theme.text("service"), font, self.color("text"))
        top = body[1] + self.tx(52)
        self._messages(canvas, state.messages, (body[0], top, body[2], body[3]))

    # -- parts ---------------------------------------------------------------

    def _result(
        self,
        canvas: _Canvas,
        body: Box,
        icon: str,
        color: str,
        title: str,
        help_name: str = "",
        help_text: str = "",
    ) -> int:
        """Icon on the left, title and help on its right; return the top of the rest."""
        left, top, right, _ = body
        # Larger texts leave less room to the icon
        size = self.px(150 / self.text_scale)
        image = self.resized(self.theme.icons[icon], (size, size))
        canvas.frame.base.paste(image, (left, top), image)
        text_box = (left + size + self.px(28), top, right, body[3])
        y = top + self.px(8)
        y = canvas.paragraph(self.theme.text(title), self.font(34, True), color, y, text_box)
        y += self.px(8)
        help_text = help_text or self.theme.text(help_name)
        y = canvas.paragraph(help_text, self.font(20), "text", y, text_box)
        return max(y, top + size) + self.px(16)

    def _busy_title(self, canvas: _Canvas, title: str, body: Box) -> int:
        left, top, right, _ = body
        size = self.px(56)
        frames = tuple(self.resized(image, (size, size)) for image in self.theme.busy)
        canvas.frame.animation = Animation((left, top), frames, BUSY_INTERVAL)
        font = self.font(30, bold=True)
        x = left + size + self.px(16)
        lines = canvas.wrap(title, font, right - x)
        height = canvas.line_height(font)
        # Centered on the spinner, wrapped below it when too long
        y = top + max(0, (size - height * len(lines)) // 2)
        for line in lines:
            canvas.text((x, y), line, font, self.color("text"))
            y += height
        return max(y, top + size) + self.px(8)

    def _device_line(self, state: ViewState) -> str:
        d = state.device
        parts = []
        if d is not None:
            name = " ".join(p for p in (printable(d.vendor), printable(d.model)) if p)
            parts += [p for p in (name, printable(d.label)) if p]
        if state.usage is not None:
            size, used = state.usage
            usage = self.theme.text("device_usage", size=human_size(size), used=human_size(used))
            parts.append(usage)
        return " · ".join(parts)

    def _file_list(
        self, canvas: _Canvas, files: Sequence[FileResult], box: Box, recent: bool = False
    ) -> None:
        """Files with their verdict, as many as fit; the path on its line, the reason below."""
        left, top, right, bottom = box
        name_font, detail_font = self.font(18), self.font(16)
        row = self.tx(26) if recent else self.tx(48)
        # At least one file and the count of the others, even when the room
        # is short (large texts): the files matter more than the space below
        rows = max(2 if len(files) > 1 else 1, (bottom - top) // row)
        if not files:
            return
        shown = list(files) if len(files) <= rows else list(files)[: rows - 1]
        y = top
        for result in shown:
            label = self.theme.text(f"verdict_{result.verdict.value}")
            label_width = canvas.text_width(label, detail_font) + self.px(16)
            color = self.color(_VERDICT_COLORS[result.verdict])
            canvas.text((right, y + self.tx(2)), label, detail_font, color, anchor="ra")
            name = result.display_path or result.path.name
            path = canvas.fit_path(printable(name), name_font, right - left - label_width)
            canvas.text((left, y), path, name_font, self.color("text"))
            if not recent:
                reason = canvas.fit(printable(detection(result)), detail_font, right - left)
                canvas.text((left, y + self.tx(23)), reason, detail_font, self.color("muted"))
            y += row
        if len(shown) < len(files):
            more = self.theme.text("more_files", count=len(files) - len(shown))
            canvas.text((left, y), more, name_font, self.color("muted"))

    def _messages(self, canvas: _Canvas, messages: Sequence[str], box: Box) -> None:
        """The latest kiosk messages that fit, the oldest first."""
        left, top, right, bottom = box
        font = self.font(17)
        row = self.tx(24)
        lines: list[str] = []
        for message in messages:
            lines += canvas.wrap(printable(message), font, right - left)
        lines = lines[-max(0, (bottom - top) // row) :] if bottom > top else []
        for i, line in enumerate(lines):
            canvas.text((left, top + i * row), line, font, self.color("muted"))


Box = tuple[int, int, int, int]

_VERDICT_COLORS = {
    Verdict.CLEAN: "clean",
    Verdict.MALICIOUS: "threat",
    Verdict.SUSPICIOUS: "warning",
    Verdict.ERROR: "warning",
    Verdict.SKIPPED: "warning",
}


class _Canvas:
    """Text drawing that fits the texts to their place and records them."""

    def __init__(self, renderer: Renderer, frame: Frame) -> None:
        self.renderer = renderer
        self.frame = frame
        self.draw = ImageDraw.Draw(frame.base)

    def text(
        self,
        xy: tuple[int, int],
        text: str,
        font: Font,
        color: Color,
        anchor: str = "la",
    ) -> None:
        if text:
            self.draw.text(xy, text, font=font, fill=color, anchor=anchor)
            self.frame.lines.append(text)
            box = self.draw.textbbox(xy, text, font=font, anchor=anchor)
            self.frame.boxes.append(tuple(round(v) for v in box))  # type: ignore[arg-type]

    def text_width(self, text: str, font: Font) -> int:
        return round(self.draw.textlength(text, font=font))

    def paragraph(
        self, text: str, font: Font, color: str, y: int, box: Box, center: bool = False
    ) -> int:
        """Draw the wrapped text from y; return the y below it."""
        left, _, right, _ = box
        height = self.line_height(font)
        for line in self.wrap(text, font, right - left):
            if center:
                self.text(((left + right) // 2, y), line, font, self.renderer.color(color), "ma")
            else:
                self.text((left, y), line, font, self.renderer.color(color))
            y += height
        return y

    def line_height(self, font: Font) -> int:
        top, bottom = self.draw.textbbox((0, 0), "Ag", font=font)[1::2]
        return round((bottom - top) * 1.35)

    def wrap(self, text: str, font: Font, width: int) -> list[str]:
        """Lines of at most width pixels; a word too long is cut."""
        lines: list[str] = []
        for paragraph in text.split("\n"):
            line = ""
            for word in paragraph.split(" "):
                candidate = f"{line} {word}" if line else word
                if self.text_width(candidate, font) <= width:
                    line = candidate
                    continue
                if line:
                    lines.append(line)
                while self.text_width(word, font) > width and len(word) > 1:
                    cut = self._fitting(word, font, width)
                    lines.append(word[:cut])
                    word = word[cut:]
                line = word
            lines.append(line)
        return lines

    def fit(self, text: str, font: Font, width: int) -> str:
        """The text, cut with an ellipsis at its end when it is too wide."""
        if self.text_width(text, font) <= width:
            return text
        cut = self._fitting(text, font, width - self.text_width(_ELLIPSIS, font))
        return text[:cut] + _ELLIPSIS

    def fit_path(self, path: str, font: Font, width: int) -> str:
        """A path cut in its middle: the start and the file name stay visible."""
        if self.text_width(path, font) <= width:
            return path
        head, tail = 0, len(path)
        # Keep twice as much of the end (the file name) as of the start
        for keep in range(len(path) - 1, 0, -1):
            tail = len(path) - (2 * keep) // 3
            head = keep - (2 * keep) // 3
            if self.text_width(path[:head] + _ELLIPSIS + path[tail:], font) <= width:
                break
        return path[:head] + _ELLIPSIS + path[tail:]

    def _fitting(self, text: str, font: Font, width: int) -> int:
        """Number of characters of the start of text that fit in width (at least 1)."""
        low, high = 1, len(text)
        while low < high:
            middle = (low + high + 1) // 2
            if self.text_width(text[:middle], font) <= width:
                low = middle
            else:
                high = middle - 1
        return low

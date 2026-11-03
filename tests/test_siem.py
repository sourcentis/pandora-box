from __future__ import annotations

import json
import shutil
import socket
import ssl
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from pandora_box import siem
from pandora_box.config import ConfigError, SiemConfig, parse_config
from pandora_box.follow import LogFollower, Position, load_position, save_position
from pandora_box.logs import get_logger, log_event, setup_logging
from pandora_box.siem import Sender, frame, syslog_message

ENTRY = (
    b'{"timestamp": "2026-10-14T10:25:32.123456+00:00", "level": "WARNING", '
    b'"kiosk": "Hall A", "event": "infected_files", "count": 2}'
)


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(siem, "POLL_SECONDS", 0.01)
    monkeypatch.setattr(siem, "MIN_BACKOFF", 0.01)


def test_syslog_message() -> None:
    message = syslog_message(ENTRY, "local0", "fallback")
    # local0 (16) * 8 + warning (4); the kiosk name without its space
    assert message == (
        b"<132>1 2026-10-14T10:25:32.123456+00:00 Hall_A pandora-box - infected_files - " + ENTRY
    )
    assert syslog_message(ENTRY, "user", "x").startswith(b"<12>1 ")


def test_syslog_message_of_another_line() -> None:
    # Header fields that cannot be read are NILVALUE, the line is sent as is
    assert syslog_message(b"not json", "local7", "kiosk-01") == (
        b"<189>1 - kiosk-01 pandora-box - - - not json"
    )
    line = b'{"timestamp": "2026-10-14T10:25:32", "level": "INFO", "event": "' + b"e" * 40 + b'"}'
    header = syslog_message(line, "local0", "k").split(b" {")[0]
    # No time zone: no timestamp; MSGID at most 32 characters
    assert header == b"<134>1 - k pandora-box - " + b"e" * 32 + b" -"


def test_frame() -> None:
    assert frame(b"abc", SiemConfig(format="syslog")) == b"3 abc"
    assert frame(b"{}", SiemConfig(format="json")) == b"{}\n"


def test_server_port() -> None:
    assert SiemConfig(transport="tls").server_port == 6514
    assert SiemConfig(transport="tcp").server_port == 514
    assert SiemConfig(transport="udp", port=5514).server_port == 5514


# -- Log file ------------------------------------------------------------------


def test_follower_waits_for_complete_lines(tmp_path: Path) -> None:
    log = tmp_path / "pandora-box.log"
    follower = LogFollower(log, None)
    assert follower.read(10) == []  # not created yet
    log.write_bytes(b"one\ntw")
    assert follower.read(10) == [b"one"]
    with log.open("ab") as f:
        f.write(b"o\nthree\n")
    assert follower.read(1) == [b"two"]
    assert follower.read(10) == [b"three"]
    assert follower.position() == Position(log.stat().st_ino, 14)


def test_follower_across_rotation(tmp_path: Path) -> None:
    log = tmp_path / "pandora-box.log"
    log.write_bytes(b"a\nb\n")
    follower = LogFollower(log, None)
    assert follower.read(1) == [b"a"]
    # logrotate moves the file, the kiosk logs on and opens a new one
    with log.open("ab") as f:
        f.write(b"c\n")
    log.rename(tmp_path / "pandora-box.log.1")
    assert follower.read(10) == [b"b", b"c"]
    assert follower.read(10) == []
    log.write_bytes(b"d\n")
    assert follower.read(10) == [b"d"]


def test_follower_resumes_at_position(tmp_path: Path) -> None:
    log = tmp_path / "pandora-box.log"
    log.write_bytes(b"a\nb\n")
    position = Position(log.stat().st_ino, 2)
    assert LogFollower(log, position).read(10) == [b"b"]
    # Moved by logrotate while the service was stopped
    log.rename(tmp_path / "pandora-box.log.1")
    log.write_bytes(b"c\n")
    follower = LogFollower(log, position)
    assert follower.read(10) == [b"b"]
    assert follower.read(10) == [b"c"]


def test_follower_lost_position(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = tmp_path / "pandora-box.log"
    log.write_bytes(b"a\n")
    follower = LogFollower(log, Position(log.stat().st_ino + 1, 100))
    assert follower.read(10) == [b"a"]
    assert "is read from its start" in capsys.readouterr().err


def test_follower_truncated_file(tmp_path: Path) -> None:
    log = tmp_path / "pandora-box.log"
    log.write_bytes(b"a\nb\n")
    follower = LogFollower(log, Position(log.stat().st_ino, 4))
    assert follower.read(10) == []
    log.write_bytes(b"c\n")
    assert follower.read(10) == []  # truncation seen: from the start again
    assert follower.read(10) == [b"c"]


def test_position_file(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    assert load_position(state) is None
    save_position(state, Position(12, 34))
    assert load_position(state) == Position(12, 34)
    state.write_text("{}")
    assert load_position(state) is None


# -- Servers ---------------------------------------------------------------------


class StreamServer:
    """A SIEM receiving octet-counted syslog messages, or JSON lines."""

    def __init__(self, context: ssl.SSLContext | None = None, port: int = 0) -> None:
        self.listener = socket.create_server(("127.0.0.1", port))
        self.port = self.listener.getsockname()[1]
        self.context = context
        self.data = b""
        self.connections = 0
        self.lock = threading.Lock()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with self.lock:
                self.connections += 1
            threading.Thread(target=self._receive, args=(conn,), daemon=True).start()

    def _receive(self, conn: socket.socket) -> None:
        try:
            if self.context is not None:
                conn = self.context.wrap_socket(conn, server_side=True)
            while chunk := conn.recv(65536):
                with self.lock:
                    self.data += chunk
        except OSError:
            pass
        finally:
            conn.close()

    def messages(self) -> list[bytes]:
        with self.lock:
            data = self.data
        messages = []
        while data:
            length, _, rest = data.partition(b" ")
            messages.append(rest[: int(length)])
            data = rest[int(length) :]
        return messages

    def close(self) -> None:
        self.listener.close()


def wait_until(condition: Callable[[], bool], timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("timeout")
        time.sleep(0.01)


class Service:
    """run() in a thread."""

    def __init__(self, config: SiemConfig, log: Path, state: Path) -> None:
        self.stop = threading.Event()
        self.thread = threading.Thread(
            target=siem.run, args=(config, log, "kiosk-01", state, self.stop), daemon=True
        )
        self.thread.start()

    def close(self) -> None:
        self.stop.set()
        self.thread.join(10)
        assert not self.thread.is_alive()


@pytest.fixture
def log(tmp_path: Path) -> Iterator[Path]:
    file = tmp_path / "log" / "pandora-box.log"
    setup_logging("kiosk-01", "INFO", file)
    yield file
    setup_logging("kiosk-01", "INFO", None)


def events(messages: list[bytes]) -> list[str]:
    return [json.loads(m.split(b" - ", 2)[2])["event"] for m in messages]


def test_run_over_tcp(tmp_path: Path, log: Path) -> None:
    server = StreamServer()
    config = SiemConfig(enabled=True, host="127.0.0.1", port=server.port, transport="tcp")
    state = tmp_path / "state.json"
    logger = get_logger("test")
    log_event(logger, "scan_started", device="/dev/sdb1")
    service = Service(config, log, state)
    try:
        wait_until(lambda: len(server.messages()) == 1)
        log_event(logger, "device_verdict", verdict="malicious")
        wait_until(lambda: len(server.messages()) == 2)
    finally:
        service.close()
    assert events(server.messages()) == ["scan_started", "device_verdict"]
    assert server.messages()[0].startswith(b"<134>1 ")
    assert load_position(state) == Position(log.stat().st_ino, log.stat().st_size)

    # Logged while the service is stopped: sent at its next start, once
    log_event(logger, "device_removed")
    service = Service(config, log, state)
    try:
        wait_until(lambda: len(server.messages()) == 3)
        time.sleep(0.1)
    finally:
        service.close()
        server.close()
    assert events(server.messages()) == ["scan_started", "device_verdict", "device_removed"]


def test_run_while_siem_is_down(tmp_path: Path, log: Path) -> None:
    # A port nobody listens on, then a SIEM on it
    probe = socket.create_server(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    config = SiemConfig(enabled=True, host="127.0.0.1", port=port, transport="tcp")
    log_event(get_logger("test"), "scan_started")
    service = Service(config, log, tmp_path / "state.json")
    try:
        time.sleep(0.2)
        server = StreamServer(port=port)
        log_event(get_logger("test"), "device_removed")
        wait_until(lambda: len(server.messages()) == 2)
    finally:
        service.close()
    assert events(server.messages()) == ["scan_started", "device_removed"]
    server.close()


def test_reconnects_after_close(tmp_path: Path, log: Path) -> None:
    server = StreamServer()
    config = SiemConfig(enabled=True, host="127.0.0.1", port=server.port, transport="tcp")
    sender = Sender(config)
    sender.send([b"one"])
    assert sender.sock is not None
    # The connection ends (the SIEM closes it at the end of the stream): the
    # next send opens a new one
    sender.sock.shutdown(socket.SHUT_WR)
    wait_until(lambda: server.messages() == [b"one"])
    time.sleep(0.1)
    sender.send([b"two"])
    wait_until(lambda: server.messages() == [b"one", b"two"])
    assert server.connections == 2
    sender.close()
    server.close()


def test_json_over_udp(tmp_path: Path, log: Path) -> None:
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(10)
    config = SiemConfig(
        enabled=True,
        host="127.0.0.1",
        port=receiver.getsockname()[1],
        transport="udp",
        format="json",
    )
    log_event(get_logger("test"), "scan_started")
    service = Service(config, log, tmp_path / "state.json")
    try:
        datagram = receiver.recv(65536)
    finally:
        service.close()
        receiver.close()
    entry = json.loads(datagram)
    assert entry["event"] == "scan_started"
    assert entry["kiosk"] == "kiosk-01"


# -- TLS -------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A certificate authority and the certificate of a SIEM for localhost."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl not found")
    folder = tmp_path_factory.mktemp("pki")

    def openssl(*args: str) -> None:
        subprocess.run(["openssl", *args], cwd=folder, check=True, capture_output=True)

    for name in ("ca", "other-ca"):
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.pem", "-days", "1",
                "-subj", f"/CN={name}", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign")  # fmt: skip
    openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", "siem.key", "-out", "siem.csr", "-subj", "/CN=localhost")  # fmt: skip
    (folder / "ext").write_text("subjectAltName=DNS:localhost\n")
    openssl("x509", "-req", "-in", "siem.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-out", "siem.pem", "-days", "1", "-extfile", "ext")  # fmt: skip
    return folder


def tls_server(pki: Path) -> StreamServer:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pki / "siem.pem", pki / "siem.key")
    return StreamServer(context)


def test_tls(pki: Path) -> None:
    server = tls_server(pki)
    config = SiemConfig(
        enabled=True, host="localhost", port=server.port, transport="tls", ca=pki / "ca.pem"
    )
    sender = Sender(config)
    sender.send([b"one", b"two"])
    wait_until(lambda: server.messages() == [b"one", b"two"])
    # The session tickets of TLS 1.3, received meanwhile, do not close it
    time.sleep(0.1)
    sender.send([b"three"])
    wait_until(lambda: server.messages() == [b"one", b"two", b"three"])
    assert server.connections == 1
    sender.close()
    server.close()


def test_tls_refuses_unknown_certificate(pki: Path) -> None:
    server = tls_server(pki)
    config = SiemConfig(
        enabled=True, host="localhost", port=server.port, transport="tls", ca=pki / "other-ca.pem"
    )
    with pytest.raises(ssl.SSLCertVerificationError):
        Sender(config).send([b"secret"])
    server.close()
    assert server.messages() == []


# -- Command -----------------------------------------------------------------------


def write_config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "pandora-box.toml"
    path.write_text(text)
    return path


def test_main_disabled(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert siem.main(["--config", str(write_config(tmp_path, ""))]) == 0
    assert "disabled" in capsys.readouterr().err


def test_main_invalid_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = write_config(tmp_path, '[siem]\nenabled = true\nhost = ""\n')
    assert siem.main(["--config", str(config)]) == 2
    assert "siem.host is required" in capsys.readouterr().err


def test_main_missing_ca(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = write_config(
        tmp_path, f'[siem]\nenabled = true\nhost = "siem"\nca = "{tmp_path}/none.pem"\n'
    )
    assert siem.main(["--config", str(config)]) == 2
    assert "siem.ca" in capsys.readouterr().err


def test_config() -> None:
    config = parse_config(
        {
            "siem": {
                "enabled": True,
                "host": "siem.example.org",
                "port": 6514,
                "ca": "/usr/share/pandora-box/siem-ca.pem",
                "format": "json",
                "facility": "local3",
                "timeout": 5,
            }
        }
    ).siem
    assert config == SiemConfig(
        enabled=True,
        host="siem.example.org",
        port=6514,
        transport="tls",
        ca=Path("/usr/share/pandora-box/siem-ca.pem"),
        format="json",
        facility="local3",
        timeout=5.0,
    )
    assert siem.facility_code(config.facility) == 19


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"siem": {"enabled": True}}, "siem.host is required"),
        ({"siem": {"host": "siem example"}}, "siem.host must be a host name"),
        ({"siem": {"port": 70000}}, "siem.port must be between"),
        ({"siem": {"transport": "relp"}}, "siem.transport must be one of: tls, tcp, udp"),
        ({"siem": {"format": "cef"}}, "siem.format must be one of: syslog, json"),
        ({"siem": {"facility": "kern"}}, "siem.facility must be one of"),
        ({"siem": {"transport": "tcp", "ca": "/ca.pem"}}, 'only used with transport = "tls"'),
        ({"siem": {"ca": "ca.pem"}}, "siem.ca must be an absolute path"),
        ({"siem": {"tls": True}}, "unknown key(s) in [siem]: tls"),
        (
            {"siem": {"enabled": True, "host": "siem"}, "logging": {"file": ""}},
            "logging.file is required",
        ),
    ],
)
def test_invalid_config(data: dict[str, object], message: str) -> None:
    with pytest.raises(ConfigError) as info:
        parse_config(data)
    assert message in str(info.value)

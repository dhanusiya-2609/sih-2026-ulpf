"""
These tests exercise the real listener protocol/handler code (the same
functions asyncio.start_server / create_datagram_endpoint wire up in
main.py) directly, rather than opening real OS sockets -- this keeps the
test suite fast and port-conflict-free while still running the actual
production code path end-to-end (parse -> normalize -> store).

Real socket-level delivery (an actual UDP datagram / TCP stream over
127.0.0.1) was manually verified during development -- see
docs/evaluation_checklist.md for that session's transcript summary.
"""
import asyncio
import io

from app.database import SessionLocal, Base, engine
from app.models import NormalizedEvent, RawEvent
from app.ingestion.listeners import SyslogUDPProtocol, _handle_tcp_client, stats

# These tests don't use the `client` fixture (no TestClient/app startup), so
# ensure the schema exists regardless of test collection/execution order.
Base.metadata.create_all(bind=engine)


def test_udp_protocol_processes_datagram_end_to_end():
    proto = SyslogUDPProtocol()
    before = stats.udp_received
    msg = b"<38>Oct 12 01:00:00 udptest1 sshd[1]: Failed password for root from 192.0.2.50 port 4000 ssh2"
    proto.datagram_received(msg, ("192.0.2.1", 55000))
    assert stats.udp_received == before + 1

    db = SessionLocal()
    try:
        raw = db.query(RawEvent).filter(RawEvent.collection_method == "udp",
                                         RawEvent.peer_address == "192.0.2.1").order_by(
            RawEvent.ingest_timestamp.desc()).first()
        assert raw is not None
        assert raw.raw_message == msg.decode()
        ne = db.query(NormalizedEvent).filter(NormalizedEvent.raw_event_id == raw.id).first()
        assert ne is not None
        assert ne.source_ip == "192.0.2.50"
    finally:
        db.close()


def test_udp_protocol_never_raises_on_garbage_bytes():
    proto = SyslogUDPProtocol()
    # Invalid UTF-8 continuation byte -- must not raise, must degrade gracefully.
    proto.datagram_received(b"\xff\xfe not valid utf-8 \x00", ("192.0.2.2", 55001))
    # No exception means the guard worked; decode(errors="replace") handles it.


class _FakeStreamReader:
    def __init__(self, lines: list[bytes]):
        self._lines = lines[:]

    async def readline(self):
        if not self._lines:
            return b""
        return self._lines.pop(0)


class _FakeStreamWriter:
    def __init__(self, peer):
        self._peer = peer
        self.closed = False

    def get_extra_info(self, key):
        return self._peer if key == "peername" else None

    def close(self):
        self.closed = True


def test_tcp_handler_processes_lines_end_to_end():
    before = stats.tcp_received
    lines = [
        b"<38>Oct 12 01:05:00 tcptest1 sshd[2]: Failed password for admin from 192.0.2.60 port 4100 ssh2\n",
        b"",  # EOF
    ]
    reader = _FakeStreamReader(lines)
    writer = _FakeStreamWriter(("192.0.2.3", 44000))

    asyncio.run(_handle_tcp_client(reader, writer))

    assert stats.tcp_received == before + 1
    assert writer.closed is True

    db = SessionLocal()
    try:
        raw = db.query(RawEvent).filter(RawEvent.collection_method == "tcp",
                                         RawEvent.peer_address == "192.0.2.3").order_by(
            RawEvent.ingest_timestamp.desc()).first()
        assert raw is not None
        ne = db.query(NormalizedEvent).filter(NormalizedEvent.raw_event_id == raw.id).first()
        assert ne.source_ip == "192.0.2.60"
    finally:
        db.close()


def test_tcp_handler_skips_blank_lines_without_crashing():
    lines = [b"\n", b"   \n", b""]
    reader = _FakeStreamReader(lines)
    writer = _FakeStreamWriter(("192.0.2.4", 44001))
    asyncio.run(_handle_tcp_client(reader, writer))  # must not raise
    assert writer.closed is True

"""
Live Syslog collection over UDP and TCP.

UDP note (per problem statement requirement): UDP provides no delivery
guarantee. This implementation does NOT claim reliable delivery. It exposes
best-effort operational counters (received / malformed / dropped-on-error)
so operators can observe loss, rather than pretending it cannot occur.
"""
import asyncio
import logging

from sqlalchemy.orm import Session

from ..database import SessionLocal
from .pipeline import process_single_event

logger = logging.getLogger("ulpf.listeners")


class ListenerStats:
    def __init__(self):
        self.udp_received = 0
        self.udp_malformed = 0
        self.udp_dropped = 0
        self.tcp_received = 0
        self.tcp_malformed = 0


stats = ListenerStats()


def _resolve_source_id_by_ip(db: Session, ip: str) -> str | None:
    from ..models import Source
    src = db.query(Source).filter(Source.ip_address == ip, Source.enabled == True).first()  # noqa: E712
    return src.source_id if src else None


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        stats.udp_received += 1
        peer_ip = addr[0]
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            stats.udp_malformed += 1
            return
        db = SessionLocal()
        try:
            source_id = _resolve_source_id_by_ip(db, peer_ip)
            process_single_event(db, text, source_id=source_id, collection_method="udp",
                                  peer_address=peer_ip)
            db.commit()
        except Exception:
            logger.exception("Failed to process UDP syslog datagram from %s", peer_ip)
            stats.udp_malformed += 1
            db.rollback()
        finally:
            db.close()

    def error_received(self, exc):
        logger.warning("UDP listener error: %s", exc)
        stats.udp_dropped += 1


async def start_udp_listener(host: str, port: int):
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: SyslogUDPProtocol(), local_addr=(host, port)
    )
    logger.info("UDP syslog listener started on %s:%s", host, port)
    return transport


async def _handle_tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else None
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            stats.tcp_received += 1
            text = line.decode("utf-8", errors="replace").rstrip("\n\r")
            if not text.strip():
                continue
            db = SessionLocal()
            try:
                source_id = _resolve_source_id_by_ip(db, peer_ip) if peer_ip else None
                process_single_event(db, text, source_id=source_id, collection_method="tcp",
                                      peer_address=peer_ip)
                db.commit()
            except Exception:
                logger.exception("Failed to process TCP syslog line from %s", peer_ip)
                stats.tcp_malformed += 1
                db.rollback()
            finally:
                db.close()
    except (ConnectionResetError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def start_tcp_listener(host: str, port: int):
    server = await asyncio.start_server(_handle_tcp_client, host, port)
    logger.info("TCP syslog listener started on %s:%s", host, port)
    return server

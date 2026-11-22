"""
Lightweight HTTP Layer-7 Protocol Dissector & Safe Basic Assembler.
Features TTL-based session eviction to strictly prevent memory leaks.
"""
import time
import urllib.parse
import threading
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
from config.settings import HTTP_SESSION_TTL, HTTP_MAX_BUFFER_SIZE, MAX_SESSIONS_TRACKED


HTTP_VERBS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")


@dataclass
class HTTPRequestData:
    method: str
    uri: str
    raw_uri: str
    path: str
    query_string: str
    headers: Dict[str, str]
    body: str
    full_text: str  # Full raw decoded request for regex scanning


@dataclass
class _SessionBuffer:
    buffer: bytearray = field(default_factory=bytearray)
    last_seen: float = field(default_factory=time.time)
    expected_seq: Optional[int] = None


class HTTPParser:
    def __init__(self):
        self._sessions: Dict[Tuple[str, str, int, int], _SessionBuffer] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def parse_payload(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      payload: bytes, seq: Optional[int] = None) -> Optional[HTTPRequestData]:
        """
        Inspect payload for HTTP Request. Performs safe single-packet extraction
        or basic contiguous assembly, protected by TTL timeout.
        """
        if not payload:
            return None

        # Periodically purge expired sessions to prevent memory leaks
        self._periodic_cleanup()

        # Quick check: Is this a standalone or starting HTTP request packet?
        is_start_of_http = any(payload.startswith(verb) for verb in HTTP_VERBS)

        session_key = (src_ip, dst_ip, src_port, dst_port)

        with self._lock:
            if is_start_of_http:
                # If a new request arrives on this session, reset the buffer
                buf = _SessionBuffer(buffer=bytearray(payload[:HTTP_MAX_BUFFER_SIZE]), last_seen=time.time())
                if len(self._sessions) < MAX_SESSIONS_TRACKED:
                    self._sessions[session_key] = buf
                data_to_parse = bytes(buf.buffer)
            elif session_key in self._sessions:
                # Append contiguous payload to existing session up to max limit
                buf = self._sessions[session_key]
                buf.last_seen = time.time()
                remaining_cap = HTTP_MAX_BUFFER_SIZE - len(buf.buffer)
                if remaining_cap > 0:
                    buf.buffer.extend(payload[:remaining_cap])
                data_to_parse = bytes(buf.buffer)
            else:
                # Not starting with HTTP verb and no prior session
                return None

        return self._dissect_http(data_to_parse)

    def _dissect_http(self, raw_bytes: bytes) -> Optional[HTTPRequestData]:
        """
        Parse raw bytes into structured HTTPRequestData.
        """
        try:
            # Decode with error replacement for resilient parsing
            text = raw_bytes.decode("utf-8", errors="replace")

            # Split header section and body section
            parts = text.split("\r\n\r\n", 1)
            header_section = parts[0]
            body_section = parts[1] if len(parts) > 1 else ""

            lines = header_section.split("\r\n")
            if not lines:
                return None

            request_line = lines[0].strip()
            tokens = request_line.split(" ")
            if len(tokens) < 2:
                return None

            method = tokens[0].upper()
            if method not in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
                return None

            raw_uri = tokens[1]

            # URL unquote to reveal hidden payload (e.g. %2e%2e%2f -> ../)
            try:
                uri = urllib.parse.unquote(raw_uri)
            except Exception:
                uri = raw_uri

            parsed_url = urllib.parse.urlsplit(uri)
            path = parsed_url.path
            query_string = parsed_url.query

            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            return HTTPRequestData(
                method=method,
                uri=uri,
                raw_uri=raw_uri,
                path=path,
                query_string=query_string,
                headers=headers,
                body=body_section,
                full_text=text
            )

        except Exception:
            return None

    def _periodic_cleanup(self):
        """Active Garbage Collector removing stale sessions older than HTTP_SESSION_TTL."""
        now = time.time()
        if now - self._last_cleanup < 3.0:
            return

        with self._lock:
            self._last_cleanup = now
            expired = [k for k, v in self._sessions.items() if now - v.last_seen > HTTP_SESSION_TTL]
            for k in expired:
                del self._sessions[k]

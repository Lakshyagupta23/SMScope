"""Bounded TCP evidence reconstruction and conservative email upgrade parsing."""
from array import array
import re


class Direction:
    """First-captured-byte wins. Sequence offsets unwrap relative to first segment.

    The bounded segment list avoids allocating attacker-selected sequence spans.
    Gaps remain separate ranges and are never silently concatenated for parsing.
    """
    def __init__(self, limit=524288, segment_limit=8192):
        self.limit, self.segment_limit = limit, segment_limit
        self.origin = None
        self.segments = []
        self.retained = 0
        self.truncated = False
        self.syn = self.fin = self.rst = False
        self.syn_offset = None
        self.fin_offset = None

    def add(self, seq, payload, frame, syn=False, fin=False, rst=False):
        self.syn |= syn
        self.fin |= fin
        self.rst |= rst
        start = (seq + int(syn)) & 0xffffffff
        if self.origin is None:
            self.origin = start
        offset = ((start - self.origin + 2**31) % 2**32) - 2**31
        if syn:
            self.syn_offset = offset
        if fin:
            self.fin_offset = offset + len(payload)
        if not payload:
            return
        remaining = self.limit - self.retained
        if len(self.segments) >= self.segment_limit:
            self.truncated = True
            return
        if len(payload) > remaining:
            self.truncated = True
        payload = payload[:max(0, remaining)]
        if payload:
            self.segments.append((offset, payload, frame))
            self.retained += len(payload)

    def finish(self):
        if not self.segments:
            gaps = [[self.syn_offset, self.fin_offset]] if self.syn_offset is not None and self.fin_offset is not None and self.fin_offset > self.syn_offset else []
            return {"ranges": [], "gaps": gaps, "retransmitted_bytes": 0, "overlap_bytes": 0,
                    "conflicting_overlap_bytes": 0, "truncated": self.truncated, "syn_seen": self.syn,
                    "fin_seen": self.fin, "rst_seen": self.rst, "status": "INCOMPLETE" if gaps else "NO_PAYLOAD"}, []
        low = min(s[0] for s in self.segments)
        high = max(s[0] + len(s[1]) for s in self.segments)
        # Cap sequence span as well as captured bytes. Large gaps cannot allocate RAM.
        high_bound = min(high, low + self.limit)
        size = high_bound - low
        data, seen, frames = bytearray(size), bytearray(size), array("I", [0]) * size
        overlap = conflict = 0
        for offset, payload, frame in self.segments:
            for j, byte in enumerate(payload):
                i = offset + j - low
                if not 0 <= i < size:
                    self.truncated = True
                    continue
                if seen[i]:
                    overlap += 1
                    conflict += data[i] != byte
                else:
                    data[i], seen[i], frames[i] = byte, 1, frame
        gaps, ranges, internal = [], [], []
        if self.syn_offset is not None and low > self.syn_offset:
            gaps.append([self.syn_offset, low])
        if self.fin_offset is not None and self.fin_offset > high:
            gaps.append([high, self.fin_offset])
        i = 0
        while i < size:
            start, present = i, seen[i]
            while i < size and seen[i] == present:
                i += 1
            if not present:
                gaps.append([low + start, low + i])
            else:
                raw = bytes(data[start:i])
                refs = frames[start:i]
                ranges.append({"sequence_start": (self.origin + low + start) & 0xffffffff,
                               "offset": low + start, "length": len(raw), "payload_hex": raw.hex(),
                               "packet_refs": sorted(set(refs))[:8192]})
                internal.append((low + start, raw, refs))
        status = "INCOMPLETE" if gaps or self.truncated or conflict else "OBSERVED_CONTIGUOUS"
        return {"ranges": ranges, "gaps": gaps, "retransmitted_bytes": overlap - conflict,
                "overlap_bytes": overlap, "conflicting_overlap_bytes": conflict,
                "overlap_policy": "first-captured-byte-wins", "truncated": self.truncated,
                "syn_seen": self.syn, "fin_seen": self.fin, "rst_seen": self.rst,
                "status": status, "sequence_origin": self.origin}, internal


def plaintext_events(internal, direction):
    """Only complete ASCII control lines before the first binary/TLS boundary."""
    events, plaintext = [], []
    # Do not resume protocol parsing after a gap: the missing bytes could have
    # entered DATA, an IMAP literal or TLS. Preserve all ranges in TCP evidence.
    for offset, raw, refs in internal[:1]:
        cursor = 0
        while cursor < len(raw):
            if raw[cursor] in (20, 21, 22, 23) and raw[cursor + 1:cursor + 2] == b"\x03":
                break
            end = raw.find(b"\r\n", cursor)
            if end < 0:
                break
            line = raw[cursor:end]
            if any(b < 9 or 13 < b < 32 or b > 126 for b in line):
                break
            chunk = raw[cursor:end + 2]
            plaintext.append(chunk)
            events.append((max(refs[cursor:end + 2]), direction, offset + cursor, line.decode("ascii")))
            cursor = end + 2
    return events, b"".join(plaintext)


def starttls_state(events, protocol, tls_frames=()):
    state = {"status": "NOT_OBSERVED", "advertised": False, "requested": False,
             "accepted": False, "tls_started": False, "completed": None,
             "failed": False, "events": [], "reason": "Missing messages do not establish stripping or MITM"}
    pending = None
    smtp_data, data_pending, pop_body, pop_pending, pop_capa = False, False, False, False, False
    imap_literal = {"client_to_server": 0, "server_to_client": 0}
    bdat_remaining = 0
    for frame, direction, offset, line in sorted(events):
        server = direction == "server_to_client"
        upper = line.upper()
        event = None
        if protocol == "SMTP":
            if not server and smtp_data:
                if line == ".":
                    smtp_data = False
                continue
            if not server and bdat_remaining:
                bdat_remaining = max(0, bdat_remaining - len(line) - 2)
                continue
            if not server and re.fullmatch(r"BDAT \d+( LAST)?", upper):
                bdat_remaining = int(upper.split()[1])
                continue
            if not server and upper == "DATA":
                data_pending = True
            if server and data_pending and re.match(r"354[ -]", upper):
                smtp_data, data_pending = True, False
            if server and re.match(r"250[ -]STARTTLS(?:\s|$)", upper):
                event = "advertised"
            elif not server and upper == "STARTTLS":
                pending, event = (None, frame), "requested"
            elif server and pending and frame >= pending[1] and re.match(r"\d{3} ", upper):
                event = "accepted" if upper.startswith("220 ") else "failed"
                pending = None
        elif protocol == "IMAP":
            if imap_literal[direction]:
                imap_literal[direction] = max(0, imap_literal[direction] - len(line) - 2)
                continue
            literal = re.search(r"\{(\d+)\+?\}$", line)
            if literal:
                imap_literal[direction] = int(literal.group(1))
            if server and upper.startswith("* CAPABILITY ") and "STARTTLS" in upper.split():
                event = "advertised"
            request = re.fullmatch(r"([^\s]+) STARTTLS", line, re.I)
            if not server and request:
                pending, event = (request.group(1), frame), "requested"
            if server and pending and frame >= pending[1]:
                reply = re.match(r"([^\s]+) (OK|NO|BAD)(?:\s|$)", line, re.I)
                if reply and reply.group(1) == pending[0]:
                    event, pending = ("accepted" if reply.group(2).upper() == "OK" else "failed"), None
        elif protocol == "POP3":
            if not server and upper.startswith(("RETR ", "TOP ")):
                pop_pending = True
            if not server and upper == "CAPA":
                pop_capa = True
            if server and pop_body:
                if line == ".":
                    pop_body = False
                continue
            if server and pop_pending:
                pop_pending = False
                pop_body = upper.startswith("+OK")
                continue
            if server and pop_capa:
                if upper == "STLS":
                    event = "advertised"
                if line == "." or upper.startswith("-ERR"):
                    pop_capa = False
            if not server and upper == "STLS":
                pending, event = (None, frame), "requested"
            elif server and pending and frame >= pending[1] and upper.startswith(("+OK", "-ERR")):
                event, pending = ("accepted" if upper.startswith("+OK") else "failed"), None
        if event:
            state[event] = True
            state["events"].append({"event": event, "packet": frame, "direction": direction, "offset": offset})
            state["status"] = event.upper()
        if state["accepted"]:
            break  # Following bytes belong to TLS, not additional plaintext commands.
    accepted = next((e["packet"] for e in state["events"] if e["event"] == "accepted"), None)
    if accepted is not None and any(f >= accepted for f in tls_frames):
        state.update(tls_started=True, status="TLS_STARTED")
    if pending:
        state.update(status="UNKNOWN", reason="Upgrade requested; matching response not captured")
    return state

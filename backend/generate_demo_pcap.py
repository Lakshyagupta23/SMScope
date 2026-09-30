"""Offline synthetic protocol fixtures, NOT full authenticated TLS connections.

Generates well-framed ClientHello/ServerHello negotiation prefixes with correct
TCP sequencing. No certificates/Finished/ciphertext are fabricated as successful
authentication. All addresses are documentation ranges; no packets are sent.
"""
import argparse
import datetime
import ipaddress
import os
import struct
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
SYN, ACK, PSH, FIN, RST = 2, 16, 8, 1, 4
PSHACK, SYNACK, FINACK = PSH | ACK, SYN | ACK, FIN | ACK
TLS_HANDSHAKE, TLS_CHANGE_SPEC, TLS_ALERT, TLS_APP_DATA = 22, 20, 21, 23
SSL_3_0, TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3 = (bytes([3, n]) for n in range(5))
CS_RC4_MD5, CS_RC4_SHA, CS_DES_CBC_SHA = b"\x00\x04", b"\x00\x05", b"\x00\x09"
CS_RSA_CBC_SHA, CS_RSA_CBC_SHA256 = b"\x00\x2f", b"\x00\x3c"
CS_ECDHE_RSA_CBC, CS_ECDHE_RSA_GCM, CS_TLS13_AES_GCM = b"\xc0\x13", b"\xc0\x2f", b"\x13\x01"


def _ip_checksum(data):
    data += b"\0" * (len(data) % 2)
    n = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while n >> 16:
        n = (n & 65535) + (n >> 16)
    return ~n & 65535


def _build_tcp(src_port, dst_port, seq, ack, flags, payload, src_ip, dst_ip):
    src, dst = ipaddress.ip_address(src_ip), ipaddress.ip_address(dst_ip)
    header = struct.pack("!HHIIHHHH", src_port, dst_port, seq & 0xffffffff, ack & 0xffffffff, 0x5000 | flags, 65535, 0, 0)
    length = len(header) + len(payload)
    pseudo = src.packed + dst.packed + (struct.pack("!I3xB", length, 6) if src.version == 6 else struct.pack("!BBH", 0, 6, length))
    checksum = _ip_checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", checksum) + header[18:] + payload


def _build_ip(src_ip, dst_ip, proto, payload):
    src, dst = ipaddress.ip_address(src_ip), ipaddress.ip_address(dst_ip)
    if src.version == 6:
        return struct.pack("!IHBB16s16s", 6 << 28, len(payload), proto, 64, src.packed, dst.packed) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x1234, 0x4000, 64, proto, 0, src.packed, dst.packed)
    return header[:10] + struct.pack("!H", _ip_checksum(header)) + header[12:] + payload


def _build_ethernet(src_mac, dst_mac):
    return bytes.fromhex(dst_mac.replace(":", "")) + bytes.fromhex(src_mac.replace(":", "")) + b"\x08\x00"


def _pcap_packet(raw, ts_sec, ts_usec):
    return struct.pack("<IIII", ts_sec, ts_usec, len(raw), len(raw)) + raw


def _ethernet_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload, ts_sec, ts_usec,
                     src_mac="02:00:00:00:00:01", dst_mac="02:00:00:00:00:02"):
    tcp = _build_tcp(src_port, dst_port, seq, ack, flags, payload, src_ip, dst_ip)
    eth = _build_ethernet(src_mac, dst_mac)
    if ipaddress.ip_address(src_ip).version == 6:
        eth = eth[:12] + b"\x86\xdd"
    return _pcap_packet(eth + _build_ip(src_ip, dst_ip, 6, tcp), ts_sec, ts_usec)


def _tls_record(content_type, version, body):
    return bytes([content_type]) + (TLS_1_2 if version == TLS_1_3 else version) + struct.pack("!H", len(body)) + body


def _ext(kind, data):
    return struct.pack("!HH", kind, len(data)) + data


def _key_share():
    public = x25519.X25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b"\x00\x1d\x00\x20" + public


def _tls_client_hello(version, ciphers):
    legacy = TLS_1_2 if version == TLS_1_3 else version
    name = b"mail.example.test"
    sni = struct.pack("!H", len(name) + 3) + b"\0" + struct.pack("!H", len(name)) + name
    extensions = b"" if version == SSL_3_0 else _ext(0, sni)
    if version in (TLS_1_2, TLS_1_3):
        extensions += _ext(10, b"\x00\x02\x00\x1d") + _ext(13, b"\x00\x04\x08\x04\x04\x03")
    if version == TLS_1_3:
        share = _key_share()
        extensions += _ext(43, b"\x04\x03\x04\x03\x03") + _ext(51, struct.pack("!H", len(share)) + share)
    cipher_bytes = b"".join(ciphers)
    body = legacy + os.urandom(32) + b"\0" + struct.pack("!H", len(cipher_bytes)) + cipher_bytes + b"\x01\0"
    if extensions:
        body += struct.pack("!H", len(extensions)) + extensions
    return _tls_record(TLS_HANDSHAKE, TLS_1_0 if version == TLS_1_3 else version, b"\x01" + len(body).to_bytes(3, "big") + body)


def _tls_server_hello(version, cipher, *, psk_only=False):
    legacy = TLS_1_2 if version == TLS_1_3 else version
    body = legacy + os.urandom(32) + b"\0" + cipher + b"\0"
    if version == TLS_1_3:
        extensions = _ext(43, TLS_1_3) + (_ext(41, b"\x00\x00") if psk_only else _ext(51, _key_share()))
        body += struct.pack("!H", len(extensions)) + extensions
    return _tls_record(TLS_HANDSHAKE, version, b"\x02" + len(body).to_bytes(3, "big") + body)


def _tls_change_cipher_spec(version):
    return _tls_record(TLS_CHANGE_SPEC, version, b"\x01")


class PcapBuilder:
    def __init__(self):
        self.packets = []
        self._base_ts = int(datetime.datetime(2026, 9, 26, 10, tzinfo=datetime.timezone.utc).timestamp())
        self._ts_offset = 0
        self._seq = {}

    def _ts(self):
        self._ts_offset += 120000
        return self._base_ts + self._ts_offset // 1000000, self._ts_offset % 1000000

    def add_packet(self, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload):
        self.packets.append(_ethernet_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload, *self._ts()))

    def _handshake(self, ci, si, sp, dp):
        self.add_packet(ci, si, sp, dp, 1000, 0, SYN, b"")
        self.add_packet(si, ci, dp, sp, 2000, 1001, SYNACK, b"")
        self.add_packet(ci, si, sp, dp, 1001, 2001, ACK, b"")
        self._seq[(ci, sp, si, dp)] = 1001
        self._seq[(si, dp, ci, sp)] = 2001

    def send(self, ci, si, sp, dp, payload, server=False):
        key = (si, dp, ci, sp) if server else (ci, sp, si, dp)
        reverse = (key[2], key[3], key[0], key[1])
        self.add_packet(key[0], key[2], key[1], key[3], self._seq[key], self._seq[reverse], PSHACK, payload)
        self._seq[key] += len(payload)

    def _smtp_upgrade(self, flow, accept=True):
        self.send(*flow, b"220 mail.example.test ESMTP synthetic fixture\r\n", server=True)
        self.send(*flow, b"EHLO client.example.test\r\n")
        self.send(*flow, b"250-mail.example.test\r\n250 STARTTLS\r\n", server=True)
        self.send(*flow, b"STARTTLS\r\n")
        if accept:
            self.send(*flow, b"220 Ready to start TLS\r\n", server=True)

    def _negotiation(self, host, sport, port, version, ciphers, selected, upgrade=False):
        flow = (f"192.0.2.{host}", "198.51.100.25", sport, port)
        self._handshake(*flow)
        if upgrade:
            self._smtp_upgrade(flow)
        self.send(*flow, _tls_client_hello(version, ciphers))
        self.send(*flow, _tls_server_hello(version, selected), server=True)

    def add_starttls_stripped_session(self):
        """Legacy method name: incomplete upgrade, not evidence of stripping."""
        flow = ("192.0.2.10", "198.51.100.25", 54321, 25)
        self._handshake(*flow)
        self._smtp_upgrade(flow, accept=False)

    def add_sslv3_rc4_session(self):
        self._negotiation(11, 44444, 465, SSL_3_0, [CS_RC4_MD5, CS_RC4_SHA], CS_RC4_SHA)

    def add_tlsv10_session(self):
        self._negotiation(12, 33333, 25, TLS_1_0, [CS_RSA_CBC_SHA, CS_DES_CBC_SHA], CS_RSA_CBC_SHA, True)

    def add_tlsv12_cbc_session(self):
        self._negotiation(13, 22222, 587, TLS_1_2, [CS_ECDHE_RSA_CBC, CS_RSA_CBC_SHA256], CS_RSA_CBC_SHA256, True)

    def add_secure_imaps_session(self):
        """Modern-parameter negotiation prefix; security is not authenticated."""
        self._negotiation(14, 11111, 993, TLS_1_3, [CS_TLS13_AES_GCM, CS_ECDHE_RSA_GCM], CS_TLS13_AES_GCM)

    def add_secure_pop3s_session(self):
        self._negotiation(15, 55555, 995, TLS_1_2, [CS_ECDHE_RSA_GCM, CS_ECDHE_RSA_CBC], CS_ECDHE_RSA_GCM)

    def add_plaintext_smtp_session(self):
        flow = ("192.0.2.16", "198.51.100.25", 60001, 25)
        self._handshake(*flow)
        self.send(*flow, b"220 mail.example.test ESMTP synthetic fixture\r\n", server=True)
        self.send(*flow, b"EHLO client.example.test\r\n")
        self.send(*flow, b"250 mail.example.test\r\n", server=True)
        self.send(*flow, b"MAIL FROM:<sender@example.test>\r\n")
        self.send(*flow, b"250 OK\r\n", server=True)

    def add_cobaltstrike_session(self):
        """Legacy method name: inert plaintext rule-test string, not attribution."""
        flow = ("192.0.2.17", "198.51.100.25", 61000, 25)
        self._handshake(*flow)
        for payload, server in ((b"220 mail.example.test ESMTP fixture\r\n", True),
                                (b"EHLO client.example.test\r\n", False), (b"250 OK\r\n", True),
                                (b"MAIL FROM:<sender@example.test>\r\n", False), (b"250 OK\r\n", True),
                                (b"RCPT TO:<receiver@example.test>\r\n", False), (b"250 OK\r\n", True),
                                (b"DATA\r\n", False), (b"354 Send message\r\n", True),
                                (b"Subject: Inert synthetic rule fixture\r\n\r\nIEX(New-Object Net.WebClient)\r\n.\r\n", False),
                                (b"250 Queued\r\n", True)):
            self.send(*flow, payload, server=server)

    def write(self, output_path):
        with open(output_path, "wb") as output:
            output.write(PCAP_GLOBAL_HEADER)
            for packet in self.packets:
                output.write(packet)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="demo_capture.pcap")
    args = parser.parse_args()
    builder = PcapBuilder()
    for method in (builder.add_starttls_stripped_session, builder.add_sslv3_rc4_session,
                   builder.add_tlsv10_session, builder.add_tlsv12_cbc_session, builder.add_secure_imaps_session,
                   builder.add_secure_pop3s_session, builder.add_plaintext_smtp_session, builder.add_cobaltstrike_session):
        method()
    builder.write(args.output)
    print(f"Wrote {len(builder.packets)} synthetic packets to {args.output}. No network traffic sent.")
    print("Negotiation prefixes only: no authenticated TLS connections or secure baselines are claimed.")


if __name__ == "__main__":
    main()

"""
TCP/IP Layer 3 & Layer 4 Protocol Dissector.
Fast, resilient extraction of IP and TCP headers from Scapy packets.
"""
import ipaddress
from dataclasses import dataclass
from typing import Optional, Dict, Any
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw


def classify_direction(src_ip: str, dst_ip: str) -> str:
    """
    Classify traffic scope based on RFC 1918 private IP ranges:
    - INBOUND: Public (Internet) -> Private (Local Server)
    - OUTBOUND: Private (Local Host) -> Public (Internet/C2)
    - INTERNAL: Private <-> Private (Lateral Movement / East-West)
    - EXTERNAL: Public <-> Public
    """
    try:
        src_obj = ipaddress.ip_address(src_ip)
        dst_obj = ipaddress.ip_address(dst_ip)
        src_priv = src_obj.is_private or src_obj.is_loopback
        dst_priv = dst_obj.is_private or dst_obj.is_loopback

        if not src_priv and dst_priv:
            return "INBOUND"
        elif src_priv and not dst_priv:
            return "OUTBOUND"
        elif src_priv and dst_priv:
            return "INTERNAL"
        return "EXTERNAL"
    except ValueError:
        return "UNKNOWN"


@dataclass
class ParsedPacket:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str  # TCP, UDP, ICMP, OTHER
    direction: str = "UNKNOWN"  # INBOUND, OUTBOUND, INTERNAL, EXTERNAL
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: str = ""
    is_syn: bool = False
    is_ack: bool = False
    is_rst: bool = False
    is_fin: bool = False
    is_psh: bool = False
    seq: Optional[int] = None
    ack: Optional[int] = None
    payload: bytes = b""
    raw_len: int = 0


class TCPIPParser:
    @staticmethod
    def parse(packet) -> Optional[ParsedPacket]:
        """
        Parse raw network packet into a structured ParsedPacket object.
        Returns None if packet is not an IP packet.
        """
        if not packet.haslayer(IP):
            return None

        try:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            direction = classify_direction(src_ip, dst_ip)
            raw_len = len(packet)
            pkt_time = float(getattr(packet, "time", 0.0))

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                flags_str = str(tcp_layer.flags)

                # Flag checks
                is_syn = "S" in flags_str
                is_ack = "A" in flags_str
                is_rst = "R" in flags_str
                is_fin = "F" in flags_str
                is_psh = "P" in flags_str

                payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""

                return ParsedPacket(
                    timestamp=pkt_time,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="TCP",
                    direction=direction,
                    src_port=src_port,
                    dst_port=dst_port,
                    tcp_flags=flags_str,
                    is_syn=is_syn,
                    is_ack=is_ack,
                    is_rst=is_rst,
                    is_fin=is_fin,
                    is_psh=is_psh,
                    seq=int(tcp_layer.seq),
                    ack=int(tcp_layer.ack),
                    payload=payload,
                    raw_len=raw_len
                )

            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
                return ParsedPacket(
                    timestamp=pkt_time,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="UDP",
                    direction=direction,
                    src_port=int(udp_layer.sport),
                    dst_port=int(udp_layer.dport),
                    payload=payload,
                    raw_len=raw_len
                )

            elif packet.haslayer(ICMP):
                return ParsedPacket(
                    timestamp=pkt_time,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol="ICMP",
                    direction=direction,
                    raw_len=raw_len
                )

            return ParsedPacket(
                timestamp=pkt_time,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="IP_OTHER",
                direction=direction,
                raw_len=raw_len
            )

        except Exception as e:
            # Defensive guard against malformed packet headers
            return None

"""
dns_parser.py — DNS 查询/应答解析

从 UDP/TCP payload 中解析 DNS 报文:
  - 查询: 域名、查询类型 (A/AAAA/MX/TXT/CNAME/NS)
  - 应答: 解析结果、TTL、权威标志
  - 安全检测: DNS 隧道特征（超长域名、高熵标签、异常查询类型）

纯字节解析，遵循 RFC 1035。
"""
import logging
import struct
from typing import Optional

logger = logging.getLogger(__name__)

# DNS 查询类型
_QTYPE_MAP = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
              15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
              65: "HTTPS"}

# DNS 响应码
_RCODE_MAP = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
              4: "NOTIMP", 5: "REFUSED"}

# DNS 隧道检测阈值
_TUNNEL_LABEL_LEN = 30       # 单标签超过此长度可疑
_TUNNEL_DOMAIN_LEN = 100     # 总域名超过此长度可疑
_TUNNEL_HIGH_ENTROPY = 3.5   # 标签熵阈值


def _calc_entropy(s: str) -> float:
    """计算字符串的 Shannon 熵"""
    if not s:
        return 0.0
    import math
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in freq.values())


def _parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """解析 DNS 域名（支持压缩指针）"""
    labels = []
    jumped = False
    original_offset = offset
    max_jumps = 10

    for _ in range(max_jumps):
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # 压缩指针 (0xC0xx)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    name = ".".join(labels)
    return name, (original_offset if jumped else offset)


class DnsParser:
    """DNS 协议解析器"""

    def parse(self, pkt) -> Optional["ProtocolMessage"]:
        from protocol_parser.dissector import ProtocolMessage

        payload = pkt.payload
        if not payload or len(payload) < 12:
            return None

        try:
            # DNS 头: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
            tx_id, flags, qd_count, an_count, ns_count, ar_count = \
                struct.unpack("!HHHHHH", payload[:12])

            is_response = bool(flags & 0x8000)
            opcode = (flags >> 11) & 0xF
            rcode = flags & 0xF
            rd = bool(flags & 0x0100)  # Recursion Desired
            ra = bool(flags & 0x0080)  # Recursion Available

            offset = 12
            queries = []

            # 解析查询段
            for _ in range(qd_count):
                if offset >= len(payload):
                    break
                qname, offset = _parse_dns_name(payload, offset)
                if offset + 4 > len(payload):
                    break
                qtype, qclass = struct.unpack("!HH", payload[offset:offset + 4])
                offset += 4
                queries.append({
                    "name": qname,
                    "type": _QTYPE_MAP.get(qtype, str(qtype)),
                    "class": "IN" if qclass == 1 else str(qclass),
                })

            # 解析应答段（仅响应）
            answers = []
            if is_response:
                for _ in range(an_count):
                    if offset >= len(payload):
                        break
                    aname, offset = _parse_dns_name(payload, offset)
                    if offset + 10 > len(payload):
                        break
                    atype, aclass, ttl, rdlength = \
                        struct.unpack("!HHIH", payload[offset:offset + 10])
                    offset += 10
                    rdata_raw = payload[offset:offset + rdlength]
                    offset += rdlength

                    rdata = ""
                    if atype == 1 and rdlength == 4:  # A
                        rdata = ".".join(str(b) for b in rdata_raw)
                    elif atype == 28 and rdlength == 16:  # AAAA
                        import ipaddress
                        rdata = str(ipaddress.IPv6Address(rdata_raw))
                    elif atype in (5, 12, 2):  # CNAME / PTR / NS
                        rdata, _ = _parse_dns_name(payload, offset - rdlength)
                    elif atype == 16:  # TXT
                        rdata = rdata_raw[1:].decode("utf-8", errors="replace") \
                            if rdlength > 1 else ""

                    answers.append({
                        "name": aname,
                        "type": _QTYPE_MAP.get(atype, str(atype)),
                        "ttl": ttl,
                        "data": rdata,
                    })

            # 主查询名
            primary_name = queries[0]["name"] if queries else ""
            primary_type = queries[0]["type"] if queries else ""

            # DNS 隧道检测
            tunnel_flags = []
            if primary_name:
                labels = primary_name.split(".")
                for label in labels:
                    if len(label) > _TUNNEL_LABEL_LEN:
                        tunnel_flags.append("long_label")
                        break
                if len(primary_name) > _TUNNEL_DOMAIN_LEN:
                    tunnel_flags.append("long_domain")
                # 高熵检测（取最长标签）
                longest = max(labels, key=len) if labels else ""
                if len(longest) > 10 and _calc_entropy(longest) > _TUNNEL_HIGH_ENTROPY:
                    tunnel_flags.append("high_entropy")
                # TXT / NULL 查询类型常用于隧道
                if primary_type in ("TXT", "NULL", "ANY"):
                    tunnel_flags.append("suspicious_qtype")

            msg = ProtocolMessage(
                protocol="DNS",
                direction="response" if is_response else "request",
                method=primary_type,
                host=primary_name,
                raw_meta={
                    "tx_id": tx_id,
                    "opcode": opcode,
                    "rcode": _RCODE_MAP.get(rcode, str(rcode)),
                    "queries": queries,
                    "answers": answers[:10],  # 限制数量
                    "query_count": qd_count,
                    "answer_count": an_count,
                    "recursion_desired": rd,
                    "recursion_available": ra,
                    "tunnel_flags": tunnel_flags,
                },
            )
            return msg
        except Exception as e:
            logger.debug("DNS 解析失败: %s", e)
            return None


# ── 全局单例 ──
dns_parser = DnsParser()

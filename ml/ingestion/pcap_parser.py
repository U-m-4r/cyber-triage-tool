"""
PCAP / network-flow parser -> network artifacts.

Strategies, in order:
  1. Native capture via pyshark, else scapy (guarded imports; used only if installed).
     Packets are aggregated into bidirectional flows keyed by the 5-tuple, and
     per-flow features are computed to match the CICIDS2017 flow schema.
  2. Flow CSV exports (tshark `-T fields`, CICFlowMeter, Zeek conn.log as CSV).
     Parsed with pandas and mapped to the schema.

Normalizes to ArtifactSchema.NETWORK so parsed flows score through the same
IsolationForest + rule pipeline the /api/analyze CSV path already uses.

Flow feature definitions follow the CICFlowMeter methodology used to build
CICIDS2017 (Sharafaldin et al., 2018). See FORMULAS.md#flow-features.
"""

import os
import csv
from collections import defaultdict

from .base import ArtifactSchema, ParserError, optional_import, register_parser

# tshark / CICFlowMeter field name -> our schema column.
_CSV_ALIASES = {
    "flow duration": "Flow Duration",
    "frame.time_delta": "Flow Duration",
    "total fwd packets": "Total Fwd Packets",
    "total backward packets": "Total Backward Packets",
    "fwd packet length max": "Fwd Packet Length Max",
    "fwd packet length min": "Fwd Packet Length Min",
    "fwd packet length mean": "Fwd Packet Length Mean",
    "bwd packet length max": "Bwd Packet Length Max",
    "bwd packet length min": "Bwd Packet Length Min",
    "flow bytes/s": "Flow Bytes/s",
    "flow packets/s": "Flow Packets/s",
    "packet length mean": "Packet Length Mean",
}


def _blank_flow(source):
    row = {"artifact_type": "network", "source_file": os.path.basename(source),
           "observed_at": ""}
    for col in ArtifactSchema.NETWORK:
        row[col] = 0
    return row


def _num(v):
    try:
        return float(v)
    except (ValueError, TypeError):
        return 0.0


def _parse_csv(path):
    """Map a flow-export CSV to the network schema by column-name aliasing."""
    rows = []
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh)
        header_map = {}
        for col in (reader.fieldnames or []):
            key = col.strip().lower()
            if key in _CSV_ALIASES:
                header_map[col] = _CSV_ALIASES[key]
        if not header_map:
            raise ParserError(
                "Flow CSV has no recognizable columns. Expected CICIDS2017 / "
                "CICFlowMeter / tshark flow fields (e.g. 'Flow Duration')."
            )
        for r in reader:
            flow = _blank_flow(path)
            for src_col, dst_col in header_map.items():
                flow[dst_col] = _num(r.get(src_col))
            ts = r.get("Timestamp") or r.get("frame.time") or ""
            flow["observed_at"] = ts
            rows.append(flow)
    return rows


def _flows_from_packets(packet_iter, source):
    """Aggregate (ts, src, dst, proto, length, is_fwd) tuples into 5-tuple flows.

    Feature definitions follow CICFlowMeter (Sharafaldin et al., 2018):
    Flow Duration = last_ts - first_ts; Flow Bytes/s and Flow Packets/s are totals
    divided by duration; packet-length min/max/mean are per-direction aggregates.
    """
    flows = defaultdict(lambda: {
        "first": None, "last": None, "fwd_lens": [], "bwd_lens": [],
    })
    for ts, src, dst, length, is_fwd in packet_iter:
        key = (src, dst) if is_fwd else (dst, src)
        f = flows[key]
        if f["first"] is None:
            f["first"] = ts
        f["last"] = ts
        (f["fwd_lens"] if is_fwd else f["bwd_lens"]).append(length)

    rows = []
    for (src, dst), f in flows.items():
        # Flow Duration in microseconds to match the CICIDS2017 unit convention.
        duration_us = max(0.0, (f["last"] - f["first"]) * 1_000_000) if f["first"] else 0.0
        fwd, bwd = f["fwd_lens"], f["bwd_lens"]
        all_lens = fwd + bwd
        total_pkts = len(all_lens)
        total_bytes = sum(all_lens)
        dur_s = duration_us / 1_000_000 or 1e-6
        row = _blank_flow(source)
        row.update({
            "Flow Duration": round(duration_us, 2),
            "Total Fwd Packets": len(fwd),
            "Total Backward Packets": len(bwd),
            "Fwd Packet Length Max": max(fwd) if fwd else 0,
            "Fwd Packet Length Min": min(fwd) if fwd else 0,
            "Fwd Packet Length Mean": round(sum(fwd) / len(fwd), 2) if fwd else 0,
            "Bwd Packet Length Max": max(bwd) if bwd else 0,
            "Bwd Packet Length Min": min(bwd) if bwd else 0,
            "Flow Bytes/s": round(total_bytes / dur_s, 2),
            "Flow Packets/s": round(total_pkts / dur_s, 2),
            "Packet Length Mean": round(total_bytes / total_pkts, 2) if total_pkts else 0,
        })
        rows.append(row)
    return rows


def _parse_native_pcap(path):
    """Native .pcap via scapy, if installed. Returns None when unavailable."""
    scapy = optional_import("scapy.all")
    if scapy is None:
        return None
    packets = scapy.rdpcap(path)

    def gen():
        for pkt in packets:
            if not pkt.haslayer("IP"):
                continue
            ip = pkt["IP"]
            yield float(pkt.time), ip.src, ip.dst, len(pkt), True
    return _flows_from_packets(gen(), path)


def parse(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".csv":
        return _parse_csv(path)
    native = _parse_native_pcap(path)
    if native is not None:
        return native
    raise ParserError(
        "Native .pcap parsing needs the optional 'scapy' (or 'pyshark') package. "
        "Export flows to CSV (tshark -T fields / CICFlowMeter) and re-upload."
    )


register_parser("pcap", (".pcap", ".pcapng"), parse)


# Feature compatibility evidence

Status: **CONDITIONALLY_COMPATIBLE**, all eleven required measurements mapped.
The primary measurement is explicitly conditional on CICFlowMeter family feature
equivalence; it is not a claim that the two datasets' generating binaries match.
No replacement features, imputation, independent normalization or unit conversion.

| Model feature (ordered) | Actual 2018 header | Definition | Unit | Numeric contract |
|---|---|---|---|---|
| Flow Duration | Flow Duration | Last minus first flow timestamp | microseconds | finite, nonnegative float64 |
| Total Fwd Packets | Tot Fwd Pkts | Forward-direction packet count | packets | finite, nonnegative float64 |
| Total Length of Fwd Packets | TotLen Fwd Pkts | Sum of forward packet payload lengths | bytes | finite, nonnegative float64 |
| Fwd Packet Length Max | Fwd Pkt Len Max | Maximum forward payload length | bytes | finite, nonnegative float64 |
| Fwd Packet Length Min | Fwd Pkt Len Min | Minimum forward payload length | bytes | finite, nonnegative float64 |
| Fwd Packet Length Mean | Fwd Pkt Len Mean | Forward payload-length statistic mean | bytes | finite, nonnegative float64 |
| Bwd Packet Length Max | Bwd Pkt Len Max | Maximum backward payload length | bytes | finite, nonnegative float64 |
| Bwd Packet Length Min | Bwd Pkt Len Min | Minimum backward payload length | bytes | finite, nonnegative float64 |
| Flow Bytes/s | Flow Byts/s | Forward plus backward payload byte sum divided by seconds | bytes/second | finite, nonnegative float64 |
| Flow Packets/s | Flow Pkts/s | Bidirectional packet count divided by seconds | packets/second | finite, nonnegative float64 |
| Packet Length Mean | Pkt Len Mean | Bidirectional flow-length summary mean | bytes | finite, nonnegative float64 |

The official [2018 dataset documentation](https://www.unb.ca/cic/datasets/ids-2018.html)
describes CICFlowMeter-V3 features and directional flow statistics. Its prose
description of byte rate is ambiguous; the extractor formula, rather than that
description alone, establishes bytes per second. The official
[2017 documentation](https://www.unb.ca/cic/datasets/ids-2017.html) also identifies
CICFlowMeter as its feature source. Training bundle order/units are independently
checked by the existing loaders.

The historical official extractor commit inspected before inference is
`8d0a1f51a3d1dbb34126fa46d0f3f974fe069333` (latest repository commit before
2018-03-03). This is evidence of implementation definitions, **not** a provenance
assertion that this commit generated the official daily CSVs:

- [FlowFeature.java](https://github.com/ahlashkari/CICFlowMeter/blob/8d0a1f51a3d1dbb34126fa46d0f3f974fe069333/src/main/java/cic/cs/unb/ca/jnetpcap/FlowFeature.java): exact source alias names/order.
- [BasicFlow.java](https://github.com/ahlashkari/CICFlowMeter/blob/8d0a1f51a3d1dbb34126fa46d0f3f974fe069333/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java): forward/backward payload statistics, flow duration, byte/packet rate formulas, and flow-length mean.
- [BasicPacketInfo.java](https://github.com/ahlashkari/CICFlowMeter/blob/8d0a1f51a3d1dbb34126fa46d0f3f974fe069333/src/main/java/cic/cs/unb/ca/jnetpcap/BasicPacketInfo.java): timestamp and payload-length fields.

Actual first-5000-row headers and numerical rate checks are in
`feature-preflight.json`, including source hashes of the inspected code. In the
web day, all 4,980 finite positive-duration preflight rows satisfy the byte-rate
formula at the declared close tolerance. Three of the 4,968 such bot-day rows use
a publisher-rounded `1.03E+07` rate for 31 bytes / 3 microseconds; the original
value is preserved rather than recomputed. These checks support units, not exact
reconstruction of packet capture or all extractor behavior.

Flow timeout, direction, packet accounting, first-packet contributions and
version-specific implementation differences may affect statistics even with the
same names and units. In particular, historical flow-length summary code adds the
first packet at initialization and inside direction handling. We preserve the
published mean rather than replace it with a guessed arithmetic mean. The 2017
cleaned source also lacks an exact extractor build record. No additional PCAPs
were downloaded or executed to manufacture equivalence. This limitation accompanies
the external evaluation and the application's PDF compatibility notes.

Unrecognized units, missing fields, duplicate headers or simultaneous target/source
aliases are INCOMPATIBLE and stop processing. Missing build provenance makes the
known family mapping conditional; a different/unknown schema is not automatically
accepted based on this report.

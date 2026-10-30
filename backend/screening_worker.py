"""Killable export/capture parser worker; no recovered content is executed."""
import contextlib
import csv
import io
import json
from pathlib import Path
import sys
import time

from ml.ingestion import parse_file


def parse(path, kind, limit):
    started = time.monotonic()
    if kind in ('native_evtx', 'native_registry'):
        from forensics import evtx_parser, registry_parser
        parser = evtx_parser.parse_evtx if kind == 'native_evtx' else registry_parser.parse_registry_hive
        frame = parser(path, limit=limit, max_seconds=55)
        return {'records':json.loads(frame.to_json(orient='records')), 'parsing':frame.attrs['parsing']}
    with open(path, 'rb') as source:
        head = source.read(65536)
    if kind == 'pcap' and head[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a'):
        from ml.ingestion.pcap_parser import _parse_native_pcap
        rows = _parse_native_pcap(path, max_packets=limit)
        if rows is None:
            raise ValueError('Native capture parser unavailable: install scapy')
        for index, row in enumerate(rows):
            row['record_id'] = index
        return {'records':list(rows), 'parsing':rows.parsing}
    text = head.decode('utf-16' if head.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')
    stripped = text.lstrip()
    representation = 'reg' if stripped.startswith(('Windows Registry Editor','REGEDIT4','[HKEY')) else (
        'json' if stripped.startswith(('{','[')) else 'xml' if stripped.startswith('<') else 'csv')
    from ml.ingestion import PARSER_REGISTRY
    import importlib
    parser_module = importlib.import_module(PARSER_REGISTRY[kind]['func'].__module__)
    parser = getattr(parser_module, '_parse_'+representation, None)
    if parser is None:
        raise ValueError('Unsupported export representation for selected evidence type')
    with contextlib.redirect_stdout(io.StringIO()):
        records = parser(path)
    total = len(records)
    source_count = None
    if representation == 'csv':
        with open(path, newline='', encoding='utf-8-sig') as source:
            source_count = sum(1 for _ in csv.DictReader(source))
    elif representation == 'json':
        with open(path, encoding='utf-8') as source:
            original = json.load(source)
        if isinstance(original, dict):
            original = next((original[key] for key in ('events','Events','keys','entries','files')
                             if isinstance(original.get(key), list)), [original])
        source_count = len(original)
    invalid = max(0, (source_count or total)-total)
    good = []
    for index, record in enumerate(records):
        if kind == 'evtx' and not record.get('EventID'):
            invalid += 1
            continue
        record.setdefault('record_id', index)
        record.setdefault('source_row', index)
        good.append(record)
    excluded = max(0, len(good)-limit)
    return {'records':good[:limit], 'parsing':{
        'status':'PARTIAL' if invalid or excluded else 'COMPLETED',
        'skipped':invalid+excluded, 'source_records':source_count,
        'records_parsed':total, 'enumeration_complete':True,
        'reason':f'{invalid} malformed or unparsed records; {excluded} excluded by record limit' if invalid or excluded else None,
        'processing_seconds':round(time.monotonic()-started, 6)}}


if __name__ == '__main__':
    try:
        print(json.dumps(parse(sys.argv[1], sys.argv[2], int(sys.argv[3])), allow_nan=False))
    except Exception as exc:
        print(json.dumps({'error':str(exc)}))
        raise SystemExit(1)

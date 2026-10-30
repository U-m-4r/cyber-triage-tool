"""Structural PE gating and the unmodified, pinned EMBER2024 v3 extractor."""
import hashlib
import importlib.metadata
from pathlib import Path
import struct

FEATURE_VERSION = 'EMBER2024-v3-0ef753e81d98bf209f71b03cd331dfc190b5b54d'
DIMENSIONS = 2568
SOURCE_HASHES = {'features.py': '58a085e9ad307aa2c52e165985ff80db8fd5b763891c0cba2d1758a4825f7273',
                 'pefile_warnings.txt': 'a23a9d0a7a938b19390a75fe0eb024dbc9bad7a134bb1511a2913f365a52e5fb'}


def identify_pe(data):
    """Validate headers and section bounds without trusting file extensions.

    Only native I386 PE32 and AMD64 PE32+ are currently enabled. Managed CLR,
    ARM, drivers and other variants are outside the verified application scope.
    """
    if not data.startswith(b'MZ'):
        return {'status': 'NOT_APPLICABLE', 'reason': 'Not a DOS/PE image', 'file_type': 'non-PE'}
    pe_signature = False
    try:
        if len(data) < 64:
            raise ValueError('Truncated DOS header')
        offset = struct.unpack_from('<I', data, 60)[0]
        if offset < 64 or offset + 24 > len(data) or data[offset:offset+4] != b'PE\0\0':
            raise ValueError('Invalid PE signature or header offset')
        pe_signature = True
        machine, sections = struct.unpack_from('<HH', data, offset + 4)
        optional_size = struct.unpack_from('<H', data, offset + 20)[0]
        optional = offset + 24
        if optional_size < 96 or optional + optional_size > len(data):
            raise ValueError('Truncated optional header')
        magic = struct.unpack_from('<H', data, optional)[0]
        if (machine, magic) not in {(0x14c, 0x10b), (0x8664, 0x20b)}:
            return {'status': 'NOT_APPLICABLE', 'reason': 'Unsupported machine/optional-header variant', 'file_type': 'unsupported-PE', 'is_pe': True}
        file_type = 'PE32-I386' if magic == 0x10b else 'PE32+-AMD64'
        dd = optional + (96 if magic == 0x10b else 112)
        if dd + 15*8 <= optional + optional_size and any(struct.unpack_from('<II', data, dd + 14*8)):
            return {'status': 'NOT_APPLICABLE', 'reason': 'Managed CLR PE not yet verified', 'file_type': 'managed-PE', 'is_pe': True}
        if struct.unpack_from('<H', data, optional + 68)[0] not in (2, 3):
            return {'status': 'NOT_APPLICABLE', 'reason': 'Only Windows GUI/console subsystems verified', 'file_type': file_type, 'is_pe': True}
        table = optional + optional_size
        if not 1 <= sections <= 96 or table + sections*40 > len(data):
            raise ValueError('Invalid section table')
        for section in range(sections):
            size, pointer = struct.unpack_from('<II', data, table + section*40 + 16)
            if size and (pointer < table + sections*40 or pointer + size > len(data)):
                raise ValueError('Truncated or overlapping section data')
        return {'status': 'SUPPORTED', 'file_type': file_type, 'is_pe': True}
    except (ValueError, struct.error) as exc:
        return {'status': 'EXTRACTION_FAILED', 'reason': str(exc), 'file_type': 'malformed-PE', 'is_pe': pe_signature}


def get_extractor():
    root = Path(__file__).resolve().parents[1] / 'third_party' / 'ember2024'
    for name, expected in SOURCE_HASHES.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
            raise ValueError('Feature extractor checksum mismatch: ' + name)
    for package, version in [('pefile', '2024.8.26'), ('signify', '0.7.1')]:
        if importlib.metadata.version(package) != version:
            raise ValueError(f'Extractor requires {package}=={version}')
    from third_party.ember2024.features import PEFeatureExtractor
    extractor = PEFeatureExtractor()
    if extractor.dim != DIMENSIONS:
        raise ValueError('Unexpected feature schema dimension')
    return extractor


def extract_features(data):
    import numpy as np
    identified = identify_pe(data)
    if identified['status'] != 'SUPPORTED':
        raise ValueError(identified.get('reason', identified['status']))
    extractor = get_extractor()
    raw = extractor.raw_features(data)
    # Upstream also supports non-PE vectors by swallowing PE parse errors.
    # Our PE-only API must surface that failure instead of classifying a zeroed PE.
    if raw.get('general', {}).get('is_pe') != 1:
        raise ValueError('Upstream parser rejected PE structure')
    vector = extractor.process_raw_features(raw)
    if vector.shape != (DIMENSIONS,) or not np.isfinite(vector).all():
        raise ValueError('Invalid feature vector dimension or non-finite values')
    return vector

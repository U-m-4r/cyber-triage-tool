"""Acquire pinned parser-maintainer regression fixtures, never executables.

Binary evidence stays ignored. Sources: python-evtx (Apache-2.0) and
python-registry (Apache-2.0). Upstream sample logs/hives may contain historical
host identifiers; do not publish raw records or screenshots of those identifiers.
"""
import hashlib
import json
from pathlib import Path
import requests

FIXTURES = {
    'system.evtx': ('williballenthin/python-evtx', 'c0007441657899c39180de10a2be1a0e43dbeaf9',
                    'tests/data/system.evtx', 1118208, 'ccb83cfefc9038017224cd97b800b66e248fe14529649ddf47907e5a2021449e'),
    'SYSTEM.hive': ('williballenthin/python-registry', 'e649a288b8c62e341eee4a6b95a1337a41c1c163',
                    'testing/reg_samples/new_log_1/SYSTEM', 7602176, '6b5ef3ad32ddd095b2d40671f5d1815d6563a40d3eb9d9ba3d8e93b0c444ad6b'),
}


def main():
    directory = Path('.test-artifacts/issue5/fixtures'); directory.mkdir(parents=True, exist_ok=True)
    manifest = {}
    session = requests.Session(); session.trust_env = False
    for name, (repo, commit, relative, size, checksum) in FIXTURES.items():
        url = f'https://raw.githubusercontent.com/{repo}/{commit}/{relative}'
        path = directory/name
        if not path.exists():
            response = session.get(url, timeout=60); response.raise_for_status()
            if len(response.content) != size:
                raise ValueError('Unexpected upstream fixture size')
            path.write_bytes(response.content)
        assert path.stat().st_size == size
        assert hashlib.sha256(path.read_bytes()).hexdigest() == checksum, 'Pinned fixture checksum mismatch; original preserved'
        manifest[name] = {'source':url, 'revision':commit, 'size_bytes':size,
                          'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                          'license':'Apache-2.0 upstream repository; fixtures retained locally only'}
    output = Path('test-results/issue-5'); output.mkdir(parents=True, exist_ok=True)
    (output/'fixture-provenance.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()

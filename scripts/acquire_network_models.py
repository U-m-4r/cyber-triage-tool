"""Retrieve reviewed frozen artifacts from this project's versioned GitHub release.

Joblib is executable serialization. Only these operator-approved, checksum-pinned
assets are allowed; uploaded evidence is never accepted as a model.
"""
import argparse
import hashlib
import json
from pathlib import Path
import requests

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,default=ROOT/'models')
    parser.add_argument('--source-dir',type=Path,help='Verify/copy an operator-owned offline artifact directory')
    args=parser.parse_args()
    manifest=json.loads((ROOT/'models/network-artifacts.json').read_text())
    args.output_dir.mkdir(parents=True,exist_ok=True)
    for name,metadata in manifest['artifacts'].items():
        target=args.output_dir/name
        if target.exists():
            if target.stat().st_size != metadata['size_bytes']:
                raise ValueError('Existing artifact size mismatch; refusing to overwrite '+name)
            data=target.read_bytes()
        elif args.source_dir:
            if (args.source_dir/name).stat().st_size != metadata['size_bytes']:
                raise ValueError('Offline artifact size mismatch: '+name)
            data=(args.source_dir/name).read_bytes()
        else:
            url=f"https://github.com/{manifest['repository']}/releases/download/{manifest['release']}/{name}"
            with requests.get(url,stream=True,timeout=60) as response:
                response.raise_for_status()
                chunks=[]; total=0
                for chunk in response.iter_content(65536):
                    total+=len(chunk)
                    if total>metadata['size_bytes']:
                        raise ValueError('Unexpected artifact size: '+name)
                    chunks.append(chunk)
                data=b''.join(chunks)
        if len(data)!=metadata['size_bytes'] or hashlib.sha256(data).hexdigest()!=metadata['sha256']:
            raise ValueError('Artifact checksum mismatch; refusing to overwrite or load '+name)
        if not target.exists():
            with target.open('xb') as stream:
                stream.write(data)
        print('Verified',name,metadata['sha256'])


if __name__=='__main__':
    main()

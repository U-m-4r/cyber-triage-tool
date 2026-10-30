"""Explicit opt-in download of checksum-pinned rejected research text models.

Never imported by application boot or network uploads. No pickle deserialization.
"""
import hashlib
import json
from pathlib import Path
import zipfile
import requests
from ml.network_experiment import sha


def main():
    manifest=json.loads(Path('test-results/issue-6/research-artifacts.json').read_text())
    assert manifest['deployment_allowed'] is False
    destination=Path('.test-artifacts/issue6/released-research')
    if destination.exists():raise RuntimeError('Refusing to overwrite downloaded research artifacts')
    destination.mkdir(parents=True)
    archive_path=destination/'verified.zip'
    session=requests.Session();session.trust_env=False
    with session.get(manifest['url'],stream=True,timeout=(30,90)) as response:
        response.raise_for_status();total=0;digest=hashlib.sha256()
        with archive_path.open('xb') as output:
            for block in response.iter_content(1048576):
                total+=len(block)
                if total>manifest['size_bytes']:raise ValueError('Research artifact exceeds pinned size')
                output.write(block);digest.update(block)
    if total!=manifest['size_bytes'] or digest.hexdigest()!=manifest['sha256']:
        raise ValueError('Research archive integrity failed; no model extracted')
    with zipfile.ZipFile(archive_path) as archive:
        for item in manifest['contents']:
            member=item['member'];target=(destination/member).resolve()
            if not target.is_relative_to(destination.resolve()):raise ValueError('Unsafe archive member')
            data=archive.read(member)
            if hashlib.sha256(data).hexdigest()!=item['sha256']:raise ValueError('Research member integrity mismatch')
            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    summary={'archive_sha256':sha(archive_path),'members_verified':len(manifest['contents']),
             'deployment_allowed':False,'destination':str(destination)}
    (destination/'verification.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))


if __name__=='__main__':main()

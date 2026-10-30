"""Real ignored controlled fixtures plus adapter format gates."""
from pathlib import Path
import pytest
from forensics.disk_image import analyze_disk_image,ScanLimits
from forensics.image_reader import open_image


def test_logical_ewf_is_explicitly_rejected(tmp_path):
    p=tmp_path/'logical.E01';p.write_bytes(b'LVF\x09\x0d\x0a\xff\x00')
    with pytest.raises(ValueError,match='Logical EWF'):
        open_image(p,None)


def test_actual_ntfs_default_stream_and_allocation_scope():
    p=Path('.test-artifacts/issue8/controlled/controlled.img')
    if not p.exists():pytest.skip('Generate controlled NTFS fixture first')
    scan=analyze_disk_image(p,limits=ScanLimits(max_files=1,max_file_bytes=100000))
    assert scan['filesystems'][0]['type']==1
    assert scan['scan_status']=='PARTIAL'
    assert scan['image_container']['format']=='raw'
    assert all('allocated default' in r['content_scope'] for r in scan['findings'])


def test_actual_segmented_ewf_matches_raw_bytes():
    pytest.importorskip('pyewf');tsk=pytest.importorskip('pytsk3')
    p=Path('.test-artifacts/issue8/controlled/controlled-ewf.E01')
    if not p.exists():pytest.skip('Generate segmented EWF fixture first')
    image=open_image(p,tsk)
    try:
        assert len(image.segments)==5
        with p.with_name('controlled.img').open('rb') as source:
            for offset in (0,31232,65536,67108864-512):
                source.seek(offset)
                assert image.read(offset,512)==source.read(512)
    finally:image.close()

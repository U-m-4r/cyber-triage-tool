"""Prepare a NEW harmless NTFS fixture directory; never edits acquired evidence.

Run generated build.sh with reviewed Alpine ntfs-3g/build-base packages and ewf.sh
with Debian ewf-tools. Bind only this directory, never host devices or evidence.
"""
from pathlib import Path
import argparse
import pip


def main():
    parser=argparse.ArgumentParser();parser.add_argument('output',type=Path);args=parser.parse_args()
    root=args.output;root.mkdir(parents=True,exist_ok=False)
    (root/'positive.txt').write_bytes(b'CYBER_TRIAGE_HARMLESS_TEST_MARKER_2026')
    (root/'negative.txt').write_bytes(b'Ordinary harmless negative fixture\n')
    (root/'empty.txt').write_bytes(b'');(root/'large.txt').write_bytes(b'A'*3000000)
    (root/'launcher.exe').write_bytes((Path(pip.__file__).parent/'_vendor/distlib/t64.exe').read_bytes())
    (root/'mkdir.c').write_bytes(Path('scripts/issue8_mkdir.c').read_bytes())
    script='''set -eu
apk add --no-cache ntfs-3g-progs ntfs-3g-dev build-base
cd /work
test ! -e controlled.img
truncate -s 64M controlled.img
mkntfs -F -Q -L ISSUE8 controlled.img
cc mkdir.c -o fixture-mkdir -lntfs-3g
./fixture-mkdir controlled.img
ntfscp -f controlled.img positive.txt /nested/positive.txt
ntfscp -f controlled.img negative.txt /nested/negative.txt
ntfscp -f controlled.img empty.txt /empty.txt
ntfscp -f controlled.img large.txt /large.txt
ntfscp -f controlled.img launcher.exe /nested/launcher.bin
ntfscp -f controlled.img negative.txt /nested/naïve.txt
ntfsls -R controlled.img
'''
    (root/'build.sh').write_bytes(script.encode('utf8'))
    (root/'ewf.sh').write_bytes(b'set -eu\napt-get update -qq\napt-get install -y -qq ewf-tools\ntest ! -e /work/controlled-ewf.E01\newfacquire -u -t /work/controlled-ewf -S 16MiB /work/controlled.img\newfverify /work/controlled-ewf.E01\n')


if __name__=='__main__':main()

"""Read-only raw/EWF media adapter. Container and logical hashes stay separate."""
from pathlib import Path


def open_image(path, tsk):
    with open(path,'rb') as stream:
        signature=stream.read(8)
    if signature[:8] not in (b'EVF\x09\x0d\x0a\xff\x00',b'LVF\x09\x0d\x0a\xff\x00'):
        return tsk.Img_Info(str(path))
    if signature.startswith(b'LVF'):
        raise ValueError('Logical EWF containers are unsupported; physical E01 required')
    try:
        import pyewf
    except ImportError as exc:
        raise RuntimeError('E01 unavailable: install reviewed libewf-python native dependency') from exc
    segments=pyewf.glob(str(path))
    if not segments:raise ValueError('No EWF segments found')
    handle=pyewf.handle()
    try:handle.open(segments,'r')
    except Exception:
        handle.close();raise
    class EwfImage(tsk.Img_Info):
        def __init__(self):
            self.handle=handle
            self.segments=[str(Path(p)) for p in segments]
            super().__init__(url='',type=tsk.TSK_IMG_TYPE_EXTERNAL)
        def read(self,offset,size):
            self.handle.seek(offset)
            return self.handle.read(size)
        def get_size(self):return self.handle.get_media_size()
        def close(self):
            if self.handle is not None:
                self.handle.close();self.handle=None
    return EwfImage()

"""Explicit, checksum-verified retrieval of one official LightGBM text model."""
import hashlib
from pathlib import Path
import requests
from ml.pe_malware_detector import MODEL_REVISION, MODEL_SHA256, DEFAULT_MODEL


def main():
    if DEFAULT_MODEL.exists():
        assert hashlib.sha256(DEFAULT_MODEL.read_bytes()).hexdigest() == MODEL_SHA256
        print('Official model already present and checksum verified')
        return
    url = f'https://huggingface.co/joyce8/EMBER2024-benchmark-models/resolve/{MODEL_REVISION}/EMBER2024_PE.model'
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    assert len(response.content) == 3756042
    assert hashlib.sha256(response.content).hexdigest() == MODEL_SHA256
    DEFAULT_MODEL.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_MODEL.write_bytes(response.content)
    print('Verified official model:', MODEL_SHA256)


if __name__ == '__main__':
    main()

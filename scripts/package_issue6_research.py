"""Package rejected research candidates outside Git; never for production use."""
import json
from pathlib import Path
import zipfile
from ml.network_experiment import sha,write_once


def main():
    root=Path('test-results/issue-6');work=Path('.test-artifacts/issue6')
    final=json.loads((root/'final-results.json').read_text())
    assert not final['deployment_eligible']
    target=work/'issue-6-rejected-research-models.zip'
    paths=[]
    for name in ('xgboost','lightgbm'):
        directory=work/'candidates'/name;metadata=json.loads((directory/'metadata.json').read_text())
        assert sha(directory/metadata['filename'])==metadata['sha256']
        paths += [(directory/'metadata.json',name+'/metadata.json'),(directory/metadata['filename'],name+'/'+metadata['filename'])]
    paths += [(root/name,'protocol/'+name) for name in ('PROTOCOL.md','selection.json','locked-test.json','prepared.json','final-results.json')]
    with zipfile.ZipFile(target,'x',compression=zipfile.ZIP_DEFLATED) as archive:
        for path,member in paths:archive.write(path,member)
        archive.writestr('RESEARCH_ONLY.txt',
            'REJECTED FOR DEPLOYMENT. This challenger failed prespecified false-positive and attack-family gates.\n'
            'Never use as the production default. No calibrated confidence or independent bot generalization.\n'
            'Two trained binary candidates; only LightGBM received the one-shot final test.\n')
    write_once(root/'research-artifacts.json',{'tag':'issue-6-research-v1','prerelease':True,'deployment_allowed':False,
        'name':target.name,'size_bytes':target.stat().st_size,'sha256':sha(target),
        'url':'https://github.com/U-m-4r/cyber-triage-tool/releases/download/issue-6-research-v1/'+target.name,
        'contents':[{ 'member':member,'sha256':sha(path)} for path,member in paths],
        'scope':'Research reproducibility only; final false-positive and family gates failed'})
    print(target,sha(target))


if __name__=='__main__':main()

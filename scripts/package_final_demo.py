"""Read genuine saved cases/results, build local evidence backup and charts."""
import json
from pathlib import Path
import shutil
from ml.network_experiment import write_once,sha


def main():
    root=Path('test-results/final-demo');latest=json.loads((root/'latest.json').read_text())
    out=Path(latest['output']);work=Path(latest['work']);summary=json.loads((out/'summary.json').read_text())
    backup=root/'backup';backup.mkdir(exist_ok=False)
    (backup/'README.txt').write_text('PREVIOUSLY CAPTURED GENUINE EXECUTION EVIDENCE. Offline backup, not a live demonstration. Native fixture reports may contain historical host records. Keep ignored and local.')
    cases=[]
    for name,result in summary['results'].items():
        response=json.loads((work/(name+'-api.json')).read_text())
        pdf=work/(name+'.pdf');shutil.copyfile(pdf,backup/(name+'.pdf'))
        cases.append({'name':name,**result,'screening':response['screening'],'coverage':response['coverage'],
            'summary':response.get('summary'),'model':response.get('inference_metadata'),
            'findings':len(response['findings']),'rulesets':response['screening']['yara'].get('identifier'),
            'pdf_path':str(backup/(name+'.pdf')),'api_output':str(work/(name+'-api.json'))})
    for name,record in [('ntfs-final',json.loads((root/'ntfs-final.json').read_text())),('local-ewf',json.loads((out/'local-ewf-summary.json').read_text()))]:
        pdf=Path(record['pdf']);shutil.copyfile(pdf,backup/(name+'.pdf'));cases.append({'name':name,**record,'pdf_path':str(backup/(name+'.pdf'))})
    write_once(root/'case-manifest.json',{'database':summary['database'],'run':summary['run'],'cases':cases,'unsupported':summary['unsupported'],
        'backup_label':'Previously captured genuine execution evidence, not live','browser':'Real verification available; see browser-acceptance.md'})
    import pymupdf
    checks={}
    for path in backup.glob('*.pdf'):
        doc=pymupdf.open(path);outside=[]
        for i,page in enumerate(doc):
            outside.extend({'page':i+1,'bbox':b[:4]} for b in page.get_text('blocks') if not page.rect.contains(pymupdf.Rect(b[:4])))
            page.get_pixmap(matrix=pymupdf.Matrix(.15,.15)) # Render every page; keep only selected sample.
        doc[-1].get_pixmap(matrix=pymupdf.Matrix(.8,.8)).save(backup/(path.stem+'-last-page.png'))
        checks[path.name]={'pages':len(doc),'all_pages_rendered':True,'out_of_page_text':outside,'sha256':sha(path)}
    write_once(root/'pdf-verification.json',checks)
    from backend.evaluation_results import catalog
    catalog_data=catalog();write_once(root/'evaluation-catalog.json',catalog_data)
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    groups=catalog_data['evaluations']
    fig,axes=plt.subplots(1,2,figsize=(13,5))
    labels=[];recall=[];fpr=[]
    for group in groups[:2]:
        for entry in group['entries']:
            labels.append(group['id']+' '+entry['name']+'\nN='+format(entry['metrics']['samples'],','));recall.append(entry['metrics']['recall']);fpr.append(entry['metrics']['false_positive_rate'])
    axes[0].bar(labels,recall);axes[1].bar(labels,fpr)
    for a,title in zip(axes,('Attack recall TP/(TP+FN)','False positives FP/(FP+TN)')):
        a.set_title(title);a.set_ylim(0,1);a.tick_params(axis='x',labelrotation=22,labelsize=8)
    fig.suptitle('Frozen network models: CICIDS2017 internal vs CSE-CIC-IDS2018 external\nDifferent populations; not a controlled cross-dataset comparison. Saved thresholds unchanged.')
    fig.tight_layout();fig.savefig(root/'internal-external-comparison.png',dpi=200);plt.close(fig)
    for group in groups:
        if group['id']=='challenge':continue
        fig,axes=plt.subplots(1,len(group['entries']),figsize=(6*len(group['entries']),5),squeeze=False)
        for a,entry in zip(axes[0],group['entries']):
            m=entry['metrics'];c=m['confusion_matrix'];matrix=[[c['tn'],c['fp']],[c['fn'],c['tp']]]
            a.imshow(matrix,cmap='Blues');a.set_title(entry['name']+'\nN='+format(m['samples'],','),fontsize=10)
            for i in range(2):
                for j in range(2):a.text(j,i,f'{matrix[i][j]:,}',ha='center',va='center',color='red')
            a.set(xticks=[0,1],yticks=[0,1],xticklabels=['Benign','Attack'],yticklabels=['Benign','Attack'],xlabel='Predicted',ylabel='Actual')
        fig.suptitle(group['title']+' — saved labeled evaluation, frozen threshold');fig.tight_layout();fig.savefig(root/(group['id']+'-confusion.png'),dpi=200);plt.close(fig)
    for p in Path('test-results/issue-7/evaluation-v3').glob('*.png'):shutil.copyfile(p,backup/p.name)
    shutil.copyfile(root/'evaluation-catalog.json',backup/'evaluation-catalog.json')
    print('Packaged',len(cases),'saved cases and',sum(x['pages'] for x in checks.values()),'PDF pages; out-of-page text',sum(len(x['out_of_page_text']) for x in checks.values()))


if __name__=='__main__':main()

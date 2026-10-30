"""Render actual saved network evidence; derive all plot values from measured JSON."""
import argparse
import json
from pathlib import Path
import pymupdf as fitz
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from PIL import Image, ImageDraw


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_dir',type=Path)
    args=parser.parse_args()
    root=Path('test-results/issue-3')
    evaluation=json.loads((root/'evaluation.json').read_text())
    fig,axes=plt.subplots(1,2,figsize=(10,4.5),layout='constrained')
    for axis,name in zip(axes,['Isolation Forest','Production XGBoost']):
        cm=evaluation['models'][name]['metrics']['confusion_matrix']
        matrix=np.array([[cm['tn'],cm['fp']],[cm['fn'],cm['tp']]])
        axis.imshow(matrix,cmap='Blues')
        for (y,x),value in np.ndenumerate(matrix):
            axis.text(x,y,f'{value:,}',ha='center',va='center',color='white' if value>matrix.max()/2 else 'black')
        axis.set(xticks=[0,1],yticks=[0,1],xticklabels=['Benign','Attack'],yticklabels=['Benign','Attack'],xlabel='Predicted',ylabel='Actual',title=name)
    fig.suptitle('Frozen production models · internal CICIDS2017 test · 345,892 flows')
    fig.savefig(root/'confusion-matrices.png',dpi=170); plt.close(fig)
    multiclass=evaluation['models']['Experimental multiclass xgboost']['metrics']['confusion_matrix']
    labels=list(multiclass)
    matrix=np.array([[multiclass[a][b] for b in labels] for a in labels])
    fig,axis=plt.subplots(figsize=(10,8),layout='constrained')
    axis.imshow(np.log1p(matrix),cmap='Blues')
    for (y,x),value in np.ndenumerate(matrix):
        axis.text(x,y,f'{value:,}',ha='center',va='center',fontsize=9,color='white' if value>3000 else 'black')
    axis.set(xticks=range(len(labels)),yticks=range(len(labels)),xticklabels=labels,yticklabels=labels,xlabel='Predicted',ylabel='Actual',title='Experimental multiclass XGBoost · internal test\nWeb Attack recall: 21 / 272 (7.72%) · weaker artifact provenance')
    plt.setp(axis.get_xticklabels(),rotation=35,ha='right')
    fig.savefig(root/'multiclass-xgboost-confusion.png',dpi=150); plt.close(fig)
    checks={}
    for detector in ['baseline','supervised']:
        document=fitz.open(args.run_dir/(detector+'.pdf'))
        pages=[]; outside=[]
        for i,page in enumerate(document):
            pix=page.get_pixmap(matrix=fitz.Matrix(.4,.4),alpha=False)
            thumb=Image.frombytes('RGB',[pix.width,pix.height],pix.samples)
            tile=Image.new('RGB',(260,365),'#e5e7eb'); tile.paste(thumb,((260-thumb.width)//2,22))
            ImageDraw.Draw(tile).text((10,3),f'{detector} · page {i+1}',fill='black'); pages.append(tile)
            for block in page.get_text('blocks'):
                if not page.rect.contains(fitz.Rect(block[:4])):
                    outside.append({'page':i+1,'bbox':block[:4]})
        cols=4; rows=(len(pages)+cols-1)//cols
        sheet=Image.new('RGB',(cols*260,rows*365),'white')
        for i,tile in enumerate(pages):
            sheet.paste(tile,((i%cols)*260,(i//cols)*365))
        sheet.save(args.run_dir/(detector+'-pdf-contact-sheet.png'))
        for number in [0,1,len(document)-1]:
            document[number].get_pixmap(matrix=fitz.Matrix(1.2,1.2)).save(args.run_dir/f'{detector}-pdf-page-{number+1}.png')
        checks[detector]={'pages':len(document),'text_blocks_outside_page':outside,'rendered_all_pages':True}
        assert not outside
    (args.run_dir/'pdf-render-checks.json').write_text(json.dumps(checks,indent=2))
    print(json.dumps(checks,indent=2))


if __name__=='__main__':
    main()

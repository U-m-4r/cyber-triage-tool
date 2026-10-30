"""Render and inspect actual saved-case PDFs without committing source records."""
import json
from pathlib import Path
import pymupdf
from PIL import Image,ImageDraw


def main():
    root=Path('test-results/issue-4');run=json.loads((root/'demo-latest.json').read_text())['run']
    output=root/run;work=Path('.test-artifacts/issue4')/run
    summary=json.loads((output/'summary.json').read_text());checks={}
    for detector in ['supervised','baseline']:
        document=pymupdf.open(work/(detector+'.pdf'));tiles=[];outside=[];source_pages=[]
        text=' '.join(p.get_text() for p in document)
        assert summary['results'][detector]['model_id'] in text and 'CSE-CIC-IDS2018' in text
        for i,page in enumerate(document):
            if 'External source:' in page.get_text():source_pages.append(i+1)
            for block in page.get_text('blocks'):
                if not page.rect.contains(pymupdf.Rect(block[:4])):outside.append({'page':i+1,'bbox':block[:4]})
            pix=page.get_pixmap(matrix=pymupdf.Matrix(.4,.4),alpha=False)
            image=Image.frombytes('RGB',[pix.width,pix.height],pix.samples)
            tile=Image.new('RGB',(260,365),'#e5e7eb');tile.paste(image,((260-image.width)//2,22))
            ImageDraw.Draw(tile).text((8,3),f'{detector} page {i+1}',fill='black');tiles.append(tile)
        sheet=Image.new('RGB',(1040,365*((len(tiles)+3)//4)),'white')
        for i,tile in enumerate(tiles):sheet.paste(tile,((i%4)*260,(i//4)*365))
        sheet.save(output/(detector+'-pdf-contact-sheet.png'))
        for page in sorted(set([1,*source_pages])):
            document[page-1].get_pixmap(matrix=pymupdf.Matrix(1.2,1.2)).save(output/f'{detector}-pdf-page-{page}.png')
        assert not outside and source_pages
        checks[detector]={'pages':len(document),'all_pages_rendered':True,'text_blocks_outside_page':outside,
                           'dataset_compatibility_pages':source_pages,'model_id_present':True,
                           'conditional_compatibility_present':'CONDITIONALLY_COMPATIBLE' in text,
                           'source_row_counts_present':f"Source rows: {summary['records']}" in text}
    (output/'pdf-verification.json').write_text(json.dumps(checks,indent=2));print(json.dumps(checks,indent=2))


if __name__=='__main__':main()

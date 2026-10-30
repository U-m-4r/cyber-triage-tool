"""Render actual retained-detector reports; no browser screenshots are created."""
import json
from pathlib import Path
import pymupdf
from PIL import Image,ImageDraw
from ml.network_experiment import repo_path


def main():
    root=Path('test-results/issue-6');latest=json.loads((root/'demo-latest.json').read_text())
    work=repo_path(latest['work']);out=repo_path(latest['output']);checks={}
    for name in ('supervised','baseline'):
        document=pymupdf.open(work/(name+'.pdf'));tiles=[];outside=[];coverage=[]
        for i,page in enumerate(document):
            if 'Unified screening:' in page.get_text():coverage.append(i+1)
            outside.extend({'page':i+1,'bbox':block[:4]} for block in page.get_text('blocks')
                           if not page.rect.contains(pymupdf.Rect(block[:4])))
            pix=page.get_pixmap(matrix=pymupdf.Matrix(.4,.4),alpha=False)
            image=Image.frombytes('RGB',(pix.width,pix.height),pix.samples)
            tile=Image.new('RGB',(260,365),'#e5e7eb');tile.paste(image,((260-image.width)//2,22))
            ImageDraw.Draw(tile).text((8,3),f'{name} page {i+1}',fill='black');tiles.append(tile)
        sheet=Image.new('RGB',(1040,365*((len(tiles)+3)//4)),'white')
        for i,tile in enumerate(tiles):sheet.paste(tile,((i%4)*260,(i//4)*365))
        sheet.save(work/(name+'-contact.png'))
        for page in coverage:document[page-1].get_pixmap(matrix=pymupdf.Matrix(1.2,1.2)).save(out/f'{name}-coverage-page-{page}.png')
        assert not outside and coverage
        checks[name]={'pages':len(document),'all_pages_rendered':True,'out_of_page_text':outside,
                      'coverage_pages':coverage,'visual_review':'Pending sample/contact inspection'}
    (out/'pdf-verification.json').write_text(json.dumps(checks,indent=2));print(json.dumps(checks,indent=2))


if __name__=='__main__':main()

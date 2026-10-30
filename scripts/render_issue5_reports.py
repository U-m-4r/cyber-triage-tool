"""Render all saved-case PDFs and record page geometry; never mock a report."""
import json
from pathlib import Path
import pymupdf
from PIL import Image, ImageDraw


def main():
    root = Path('test-results/issue-5')
    latest = json.loads((root/'latest.json').read_text())
    output, work = Path(latest['output']), Path(latest['work'])
    scratch = work/'rendered'; scratch.mkdir(exist_ok=True)
    checks = {}
    for pdf in work.glob('*.pdf'):
        document = pymupdf.open(pdf)
        tiles, outside, coverage_pages = [], [], []
        for index, page in enumerate(document):
            if 'Unified screening:' in page.get_text():
                coverage_pages.append(index+1)
            outside.extend({'page':index+1, 'bbox':block[:4]} for block in page.get_text('blocks')
                           if not page.rect.contains(pymupdf.Rect(block[:4])))
            pix = page.get_pixmap(matrix=pymupdf.Matrix(.4,.4), alpha=False)
            image = Image.frombytes('RGB', (pix.width,pix.height), pix.samples)
            tile = Image.new('RGB', (260,365), '#e5e7eb')
            tile.paste(image, ((260-image.width)//2,22))
            ImageDraw.Draw(tile).text((8,3), f'{pdf.stem} page {index+1}', fill='black')
            tiles.append(tile)
        sheet = Image.new('RGB', (1040,365*((len(tiles)+3)//4)), 'white')
        for index, tile in enumerate(tiles):
            sheet.paste(tile, ((index%4)*260,(index//4)*365))
        sheet.save(scratch/(pdf.stem+'-contact.png'))
        if pdf.stem in ('disk','standalone-pe','event-export','registry-export','pcap'):
            # Only our harmless generated records are included in public visual QA.
            for page in coverage_pages:
                document[page-1].get_pixmap(matrix=pymupdf.Matrix(1.2,1.2)).save(output/f'{pdf.stem}-coverage-page-{page}.png')
        assert coverage_pages and not outside, (pdf.name,outside)
        checks[pdf.name] = {'pages':len(document), 'all_pages_rendered':True,
            'outside_page_text_blocks':outside, 'coverage_pages':coverage_pages,
            'visual_review':'Pending human/agent inspection of rendered contacts and sample full pages'}
    (output/'pdf-verification.json').write_text(json.dumps(checks, indent=2))
    print(json.dumps(checks, indent=2))


if __name__ == '__main__':
    main()

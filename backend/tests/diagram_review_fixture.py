"""Generate an isolated browser fixture without touching saved user assessments."""
import io
import base64
import json
from pathlib import Path
import sys

from PIL import Image, ImageDraw, PngImagePlugin

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.services.diagram_import import extract_diagram
from app.services.model_review import ModelReviewRequest, prepare_model


def build():
    image = Image.new('RGB', (1000, 440), 'white')
    draw = ImageDraw.Draw(image)
    for bounds, name in [((70, 130, 260, 250), 'React'), ((400, 130, 590, 250), 'Orders API'), ((730, 130, 920, 250), 'PostgreSQL')]:
        draw.rectangle(bounds, outline='#164e63', width=3)
        draw.text((bounds[0]+20, bounds[1]+45), name, fill='#172026', font_size=24)
    for left, right in [(260, 400), (590, 730)]:
        draw.line((left, 190, right, 190), fill='#334155', width=3)
        draw.polygon([(right, 190), (right-12, 183), (right-12, 197)], fill='#334155')
    draw.text((295, 150), 'HTTPS', fill='#172026', font_size=20)
    draw.text((640, 150), 'TLS', fill='#172026', font_size=20)
    raw = io.BytesIO()
    image.save(raw, format='PNG')
    # Browser fixture uses structured extraction, with one deliberate review task.
    xml = '''<mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>
    <mxCell id="a" value="React" vertex="1" parent="1"><mxGeometry x="70" y="130" width="190" height="120"/></mxCell>
    <mxCell id="b" value="Orders API" vertex="1" parent="1"><mxGeometry x="400" y="130" width="190" height="120"/></mxCell>
    <mxCell id="c" value="PostgreSQL" vertex="1" parent="1"><mxGeometry x="730" y="130" width="190" height="120"/></mxCell>
    <mxCell id="e" edge="1" source="a" target="b" value="HTTPS request"/>
    <mxCell id="f" edge="1" source="b" target="c" value="TLS query"/>
    </root></mxGraphModel>'''
    info = PngImagePlugin.PngInfo()
    info.add_text('mxfile', xml)
    raw = io.BytesIO()
    image.save(raw, format='PNG', pnginfo=info)
    _, _, meta = extract_diagram('commerce.png', raw.getvalue())
    for c in meta['diagram_model']['components']:
        g = c['evidence'][0]['diagram_geometry']
        c['evidence'][0]['bbox'] = [g[0]/1000, g[1]/440, g[2]/1000, g[3]/440]
        c['evidence'][0].pop('region_alignment', None)
    meta['diagram_model']['flows'][0]['assumed'] = True
    payload = ModelReviewRequest(project_name='Commerce diagram review', sources=[{'id': 'drawing', 'name': 'commerce.png',
        'kind': 'png', 'text': 'React\nOrders API\nPostgreSQL', 'metadata': meta}])
    preview = prepare_model(payload)
    preview['readiness']['dfd_generated'] = True
    return {'payload': payload.model_dump(), 'preview': preview}


if __name__ == '__main__':
    output = Path('evaluation_reports/diagram-review')
    output.mkdir(parents=True, exist_ok=True)
    fixture = build()
    (output / 'fixture.json').write_text(json.dumps(fixture), encoding='utf-8')
    (output / 'raster.jpg').write_bytes(base64.b64decode(fixture['payload']['sources'][0]['metadata']['source_preview'].split(',', 1)[1]))
    (output / 'raster-manifest.json').write_text(json.dumps([{'file': 'raster.jpg', 'components': ['React', 'Orders API', 'PostgreSQL'],
        'flows': [['React', 'Orders API'], ['Orders API', 'PostgreSQL']], 'boundaries': []}]), encoding='utf-8')
    print(output / 'fixture.json')

import base64
import io
import json
import urllib.parse
import zlib

import pytest
from PIL import Image, PngImagePlugin

from app.models import Component, SystemArchitecture
from app.services import diagram_vision as vision
from app.services.diagram_import import extract_diagram
from app.services.model_review import ModelReviewRequest, prepare_model


DRAWING = '''<mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>
<mxCell id="group" value="AWS account" vertex="1" parent="1" style="swimlane;"><mxGeometry x="0" y="0" width="600" height="250"/></mxCell>
<mxCell id="a" value="Orders API" vertex="1" parent="group"><mxGeometry x="40" y="40" width="100" height="60"/></mxCell>
<mxCell id="b" value="PostgreSQL" vertex="1" parent="group" style="shape=cylinder;"><mxGeometry x="400" y="40" width="100" height="60"/></mxCell>
<mxCell id="e" edge="1" source="a" target="b" value="TLS query" style="endArrow=classic;"/>
</root></mxGraphModel>'''


def png(text=None, size=(600, 250)):
    output = io.BytesIO()
    info = PngImagePlugin.PngInfo()
    if text is not None:
        info.add_text('mxfile', text, zip=True)
    Image.new('RGB', size, 'white').save(output, format='PNG', pnginfo=info)
    return output.getvalue()


def source(meta, name='architecture.png'):
    return {'id': 'drawing', 'name': name, 'kind': 'png', 'text': 'Orders API\nPostgreSQL', 'metadata': meta}


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.delenv('AEGIS_DIAGRAM_VISION_URL', raising=False)
    monkeypatch.delenv('AEGIS_DIAGRAM_VISION_MODEL', raising=False)
    monkeypatch.delenv('AEGIS_ALLOW_REMOTE_DIAGRAMS', raising=False)
    monkeypatch.setattr(vision, 'regions', lambda image: ([], 'test-ocr'))
    monkeypatch.setattr(vision, 'connector_segments', lambda image: [])


def test_embedded_png_bypasses_vision_and_retains_geometry(monkeypatch, offline):
    monkeypatch.setattr(vision, 'extract_raster', lambda *args: pytest.fail('Embedded XML must bypass raster processing'))
    _, _, meta = extract_diagram('architecture.png', png(urllib.parse.quote(DRAWING)))
    model = meta['diagram_model']
    assert model['metadata']['diagram_extraction']['method'] == 'embedded_drawio'
    assert len(model['components']) == 2 and len(model['flows']) == 1
    assert model['flows'][0]['protocol'] == 'TLS'
    assert model['components'][0]['evidence'][0]['bbox'] == pytest.approx([40/600, 40/250, 100/600, 60/250])
    assert not model['trust_boundaries']
    assert len(model['metadata']['diagram_relationships']) == 2
    assert meta['source_preview'].startswith('data:image/jpeg;base64,')


def test_compressed_embedded_graph_and_xml_safety(offline):
    compressor = zlib.compressobj(wbits=-15)
    packed = base64.b64encode(compressor.compress(urllib.parse.quote(DRAWING).encode()) + compressor.flush()).decode()
    _, _, meta = extract_diagram('graph.png', png(f'<mxfile><diagram>{packed}</diagram></mxfile>'))
    assert len(meta['diagram_model']['flows']) == 1
    with pytest.raises(ValueError):
        extract_diagram('unsafe.png', png('<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><mxfile>&x;</mxfile>'))


@pytest.mark.parametrize('caption,arrow,kind', [('hosts', 'classic', 'hosts'), ('depends on', 'classic', 'depends_on'), ('network', 'none', 'unknown')])
def test_non_runtime_links_do_not_become_flows(caption, arrow, kind):
    raw = DRAWING.replace('TLS query', caption).replace('endArrow=classic', f'endArrow={arrow}')
    _, _, meta = extract_diagram('system.drawio', raw.encode())
    assert not meta['diagram_model']['flows']
    assert any(r['kind'] == kind for r in meta['diagram_model']['metadata']['diagram_relationships'])


def test_privacy_guard_rejects_remote_without_admin_opt_in(monkeypatch, offline):
    monkeypatch.setenv('AEGIS_DIAGRAM_VISION_URL', 'https://example.org')
    monkeypatch.setenv('AEGIS_DIAGRAM_VISION_MODEL', 'vision')
    monkeypatch.setattr(vision, 'query_vision', lambda *args: pytest.fail('No remote request allowed'))
    with pytest.raises(ValueError, match='administrator opt-in'):
        extract_diagram('private.png', png())
    monkeypatch.setenv('AEGIS_ALLOW_REMOTE_DIAGRAMS', 'true')
    monkeypatch.setenv('AEGIS_DIAGRAM_VISION_URL', 'http://example.org')
    with pytest.raises(ValueError, match='HTTPS'):
        vision.vision_endpoint()


def test_tile_budget_overlap_and_coordinate_validation():
    assert len(vision.tiles(Image.new('RGB', (800, 500)))) == 1
    views = vision.tiles(Image.new('RGB', (2000, 1000)))
    assert len(views) == 5 and views[1][0] == [0, 0, .6, .6]
    assert vision.box([0, 0, 1, 1])
    for invalid in ([float('nan'), 0, 1, 1], [-1, 0, 1, 1], [0, 0, 0, 1], [0, 0, 2, 1], 'bad'):
        assert vision.box(invalid) is None


def proposal():
    return {'components': [{'id': 'a', 'name': 'Orders API', 'type': 'Go Gin', 'bbox': [.1, .2, .2, .2],
            'trust_level': 'public', 'properties': {'mfa_enabled': False}},
        {'id': 'b', 'name': 'PostgreSQL', 'bbox': [.7, .2, .2, .2]}],
        'flows': [{'source_id': 'a', 'target_id': 'b', 'protocol': 'TLS', 'description': 'query', 'bbox': [.3, .25, .4, .05]}],
        'trust_boundaries': [{'name': 'AWS account', 'components': ['a', 'b']}], 'relationships': []}


def test_raster_is_advisory_and_ocr_disagreement_is_visible(monkeypatch, offline):
    monkeypatch.setattr(vision, 'vision_endpoint', lambda: ('http://localhost/api/generate', 'test-model', True))
    monkeypatch.setattr(vision, 'query_vision', lambda *args: proposal())
    monkeypatch.setattr(vision, 'regions', lambda image: ([{'text': 'Billing API', 'bbox': [.1, .2, .2, .2]}], 'test-ocr'))
    _, _, meta = extract_diagram('visual.png', png())
    model = meta['diagram_model']
    api = model['components'][0]
    assert api['type'] == 'API' and api['trust_level'] == 'unknown'
    assert 'mfa_enabled' not in api['properties']
    assert model['flows'][0]['assumed']
    assert not model['trust_boundaries']
    assert model['metadata']['diagram_issues'][0]['kind'] == 'label_disagreement'
    preview = prepare_model(ModelReviewRequest(project_name='Image only', sources=[source(meta, 'visual.png')]), render=False)
    assert all(c['properties']['evidence_status'] == 'inferred' for c in preview['architecture']['components'])
    assert all(c['confidence'] == 'Low' for c in preview['architecture']['components'])
    assert preview['diagram_questions'][0]['priority'] == 'High'


def test_overlapping_views_merge_only_same_spatial_component(monkeypatch, offline):
    monkeypatch.setattr(vision, 'vision_endpoint', lambda: ('http://localhost', 'test', True))
    monkeypatch.setattr(vision, 'tiles', lambda image: [([0, 0, 1, 1], image), ([0, 0, 1, 1], image)])
    p = proposal()
    p['components'].append({'id': 'c', 'name': 'Orders API', 'bbox': [.1, .7, .2, .2]})
    monkeypatch.setattr(vision, 'query_vision', lambda *args: p)
    model, _ = vision.extract_raster(Image.new('RGB', (600, 400)), 'diagram.png')
    assert len(model.components) == 3
    assert len(model.flows) == 1
    assert sum(c.name == 'Orders API' for c in model.components) == 2


def test_failed_vision_falls_back_to_bounded_ocr(monkeypatch, offline):
    monkeypatch.setattr(vision, 'vision_endpoint', lambda: ('http://localhost', 'test', True))
    def fail(*args):
        raise OSError('provider unavailable')
    monkeypatch.setattr(vision, 'query_vision', fail)
    monkeypatch.setattr(vision, 'regions', lambda image: ([{'text': 'Orders API', 'bbox': [.1, .2, .2, .2]}], 'test-ocr'))
    model, warnings = vision.extract_raster(Image.new('RGB', (600, 400)), 'diagram.png')
    assert len(model.components) == 1 and not model.flows
    assert any('failed' in note for note in warnings)


def test_review_decision_changes_only_topology_and_invalidates_on_reupload(monkeypatch, offline):
    monkeypatch.setattr(vision, 'vision_endpoint', lambda: ('http://localhost', 'test', True))
    monkeypatch.setattr(vision, 'query_vision', lambda *args: proposal())
    _, _, meta = extract_diagram('visual.png', png())
    payload = ModelReviewRequest(project_name='Review', sources=[source(meta)])
    preview = prepare_model(payload, render=False)
    task = next(q for q in preview['diagram_questions'] if q['kind'] == 'flow')
    record = {'task_id': task['id'], 'artifact_hash': task['artifact_hash'], 'action': 'reverse', 'note': 'Architect verified response direction.'}
    reviewed = ModelReviewRequest(**{**payload.model_dump(), 'diagram_decisions': [record]})
    result = prepare_model(reviewed, render=False)
    before, after = preview['flows'][0], result['flows'][0]
    assert after['source_id'] == before['target_id'] and not after['assumed']
    assert not any('authenticated' in c['properties'] for c in result['architecture']['components'])
    reviewed.sources[0].metadata['artifact_hash'] = 'new-image'
    stale = prepare_model(reviewed, render=False)
    assert stale['flows'][0]['assumed']
    assert any(w['type'] == 'stale_diagram_decision' for w in stale['warnings'])


def test_exact_name_correlation_preserves_control_conflicts_and_scopes():
    from app.services.diagram_review import import_sources
    from app.services.model_review import ReviewSource
    base = SystemArchitecture(components=[Component(id='orders', name='Orders API', type='API', properties={'mfa_enabled': True})], flows=[])
    _, _, meta = extract_diagram('diagram.drawio', DRAWING.encode())
    import_sources(base, [ReviewSource(**source(meta))], [])
    assert len(base.components) == 2
    assert base.flows[0].source_id == 'orders'
    assert base.components[0].properties['mfa_enabled'] is True
    assert base.components[0].evidence[0]['source_id'] == 'drawing'
    prod = SystemArchitecture(components=[Component(id='orders', name='Orders API', type='API', properties={'environment': 'production'})], flows=[])
    import_sources(prod, [ReviewSource(**{**source(meta), 'environment': 'staging'})], [])
    assert len(prod.components) == 3


def test_ambiguous_exact_names_are_not_collapsed():
    from app.services.diagram_review import import_sources
    from app.services.model_review import ReviewSource
    base = SystemArchitecture(components=[Component(id=i, name='Orders API', type='API') for i in ['one', 'two']], flows=[])
    _, _, meta = extract_diagram('diagram.drawio', DRAWING.encode())
    import_sources(base, [ReviewSource(**source(meta))], [])
    assert len(base.components) == 4


def test_drawing_text_is_not_promoted_to_security_control_evidence(offline):
    drawing = DRAWING.replace('Orders API', 'Orders API no MFA')
    _, _, meta = extract_diagram('diagram.drawio', drawing.encode())
    preview = prepare_model(ModelReviewRequest(project_name='Control evidence', sources=[source(meta)]), render=False)
    assert not [f for f in preview['correlation']['facts'] if f.get('kind') == 'control']


def test_diagram_correlation_with_document_controls_and_saved_model():
    _, _, meta = extract_diagram('diagram.drawio', DRAWING.encode())
    baseline = SystemArchitecture(components=[Component(id='orders', name='Orders API', type='API')], flows=[])
    payload = ModelReviewRequest(project_name='Correlated', baseline=baseline, sources=[source(meta),
        {'id': 'control-doc', 'name': 'Controls.txt', 'text': 'Orders API has MFA enabled. Orders API has rate limiting enabled.'}])
    result = prepare_model(payload, render=False)
    orders = [c for c in result['architecture']['components'] if c['name'] == 'Orders API']
    assert len(orders) == 1
    assert orders[0]['properties']['mfa_enabled'] is True
    assert orders[0]['properties']['rate_limiting'] is True
    assert any(e.get('source_type') == 'diagram_import' for e in orders[0]['evidence'])


def test_conflicting_flow_protocols_get_a_targeted_question():
    from app.models import DataFlow
    _, _, meta = extract_diagram('diagram.drawio', DRAWING.encode())
    baseline = SystemArchitecture(components=[Component(id='api', name='Orders API', type='API'), Component(id='db', name='PostgreSQL', type='Database')],
        flows=[DataFlow(id='original', source_id='api', target_id='db', protocol='HTTP', description='query')])
    result = prepare_model(ModelReviewRequest(project_name='Conflict', baseline=baseline, sources=[source(meta)]), render=False)
    assert any('different protocols' in q['question'] for q in result['diagram_questions'])
    assert {f['protocol'] for f in result['flows']} == {'HTTP', 'TLS'}


def test_pixel_lines_cannot_infer_arrows_or_security_controls():
    a, b = [.1, .2, .2, .2], [.7, .2, .2, .2]
    assert vision.connector_support([[[.3, .3], [.7, .3]]], a, b)
    assert not vision.connector_support([[[.1, .2], [.3, .2]]], a, b)


def test_real_opencv_line_geometry_handles_installed_output_shape():
    from PIL import ImageDraw
    image = Image.new('RGB', (500, 200), 'white')
    ImageDraw.Draw(image).line((30, 100, 470, 100), fill='black', width=3)
    segments = vision.connector_segments(image)
    assert segments
    assert all(0 <= v <= 1 for line in segments for point in line for v in point)


def test_benchmark_distinguishes_same_named_component_instances():
    from scripts.evaluate_diagram_extraction import score
    from pathlib import Path
    fixtures = Path(__file__).parent / 'fixtures' / 'diagrams'
    case = json.loads((fixtures / 'manifest.json').read_text())[1]
    _, _, meta = extract_diagram(case['file'], (fixtures / case['file']).read_bytes())
    assert score(case, meta['diagram_model'])['instance_flows']['recall'] == 1
    model = meta['diagram_model']
    wrong = next(c for c in model['components'] if c['evidence'][0]['source_key'] == '0:b')
    model['flows'][0]['source_id'] = wrong['id']
    scores = score(case, model)
    assert scores['directed_flows']['recall'] == 1  # Labels alone cannot catch this defect.
    assert scores['instance_flows']['recall'] == 0

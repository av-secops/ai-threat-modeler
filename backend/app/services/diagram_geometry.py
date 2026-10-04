"""Local raster candidates. Text and geometry never establish security controls."""

import re
import unicodedata


def compact(text):
    return re.sub(r'[^a-z0-9]', '', unicodedata.normalize('NFKC', text).lower())


RESOURCE_NAMES = {
    'applicationloadbalancer': 'Application Load Balancer',
    'awssystemsmanagerparameterstore': 'AWS Systems Manager Parameter Store',
    'elasticacheforredis': 'ElastiCache for Redis',
    'amazonrelationaldatabaseserviceamazonrds': 'Amazon RDS',
    'amazonelasticcontainerregistryamazonecr': 'Amazon ECR',
    'amazonelasticcontainerserviceamazonecs': 'Amazon ECS',
    'amazonsimplestorageserviceamazons3': 'Amazon S3',
    'amazondynamodb': 'Amazon DynamoDB',
    'amazoncloudwatch': 'Amazon CloudWatch',
    'awsfargate': 'AWS Fargate',
}
GROUP_LABEL = re.compile(r'^(?:aws\s*cloud|region|(?:virtual\s*private\s*cloud\s*)?\(?vpc\)?|(?:public|private)\s*subnet|availability\s*zone|resource\s*group|aws\s*account)\b', re.I)


def union(boxes):
    boxes = [b for b in boxes if b]
    if not boxes:
        return None
    x, y = min(b[0] for b in boxes), min(b[1] for b in boxes)
    return [x, y, max(b[0]+b[2] for b in boxes)-x, max(b[1]+b[3] for b in boxes)-y]


def inside(inner, outer):
    return bool(inner and outer and outer[0] <= inner[0]+inner[2]/2 <= outer[0]+outer[2]
        and outer[1] <= inner[1]+inner[3]/2 <= outer[1]+outer[3])


def group_labels(rows):
    """Join only adjacent continuations of recognized resource labels, not services."""
    pending = [{**r, 'parts': [r]} for r in rows]
    changed = True
    while changed:
        changed = False
        for a in pending:
            if not a.get('bbox'):
                continue
            x, y, w, h = a['bbox']
            candidates = []
            for b in pending:
                if a is b or not b.get('bbox'):
                    continue
                bx, by, bw, bh = b['bbox']
                combined = compact(a['text'] + b['text'])
                if not (y < by and -.4*h <= by-(y+h) <= max(h, bh)*.8
                        and abs(x+w/2-bx-bw/2) <= max(.012, min(w, bw)*.5)):
                    continue
                if combined in RESOURCE_NAMES or any(k.startswith(combined) for k in RESOURCE_NAMES):
                    candidates.append(b)
            if len(candidates) == 1:
                b = candidates[0]
                a.update(text=a['text']+' '+b['text'], bbox=union([a['bbox'], b['bbox']]), parts=a['parts']+b['parts'])
                pending.remove(b)
                changed = True
                break
    labels, annotations = [], []
    for row in pending:
        text = row['text'].strip()
        letters = ''.join(c for c in text if c.isalnum())
        # Retain rejected regions as annotations so a reviewer can recover them.
        if len(letters) < 2 or compact(text) == 'aws' or not any(c.isalpha() for c in letters):
            annotations.append(row)
        elif re.fullmatch(r'(?:\(?\d+\)?[.: -]*)?(?:HTTPS?|m?TLS|WSS?|TCP|gRPCS?|request|response)', text, re.I):
            annotations.append(row)
        else:
            row['text'] = RESOURCE_NAMES.get(compact(text), text)
            labels.append(row)
    return labels, annotations


def shapes(image):
    """Bounded shape proposals; containers and service icons remain separate."""
    try:
        import cv2
        import numpy as np
    except ImportError:
        return [], []
    small = image.convert('RGB')
    small.thumbnail((1800, 1800))
    rgb = np.asarray(small)
    h, w = rgb.shape[:2]
    hsv = cv2.cvtColor(rgb, cv2.COLOR_RGB2HSV)
    masks = [(hsv[:, :, 1] > 65).astype('uint8')*255,
             (cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY) < 160).astype('uint8')*255]
    # Adjacent subnets often share an edge but use different outline colours.
    masks.extend(((hsv[:, :, 1] > 65) & (hsv[:, :, 0] >= hue) & (hsv[:, :, 0] < hue+15)).astype('uint8')*255
        for hue in range(0, 180, 15))
    containers, icons = [], []
    for index, mask in enumerate(masks):
        closed = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, np.ones((3, 3), np.uint8))
        contours, _ = cv2.findContours(closed, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
        for contour in contours:
            x, y, cw, ch = cv2.boundingRect(contour)
            b = [x/w, y/h, cw/w, ch/h]
            area = cw*ch
            if cw < 18 or ch < 18:
                continue
            polygon = cv2.approxPolyDP(contour, .015*cv2.arcLength(contour, True), True)
            if len(polygon) == 4 and cw > 95 and ch > 75 and cv2.contourArea(contour)/area > .90:
                if not any(abs(c[0]-b[0])+abs(c[1]-b[1])+abs(c[2]-b[2])+abs(c[3]-b[3]) < .02 for c in containers):
                    containers.append(b)
            elif index in {0, 1} and .45 < cw/ch < 2.0 and 26 < cw < 140 and 26 < ch < 140:
                if not any(inside(b, c) and c[2]*c[3] >= b[2]*b[3] for c in icons):
                    icons = [c for c in icons if not inside(c, b)]
                    icons.append(b)
    # Recover thin enclosing rectangles whose contours are interrupted by a crossing.
    segments = []
    for mask in masks:
        lines = cv2.HoughLinesP(mask, 1, 3.141592653589793/180, 60, minLineLength=95, maxLineGap=8)
        if lines is not None:
            segments.extend(lines.reshape(-1, 4).tolist()[:100])
    segments = list(dict.fromkeys(tuple(segment) for segment in segments))[:500]
    hs = [(min(a, c), b, max(a, c)) for a, b, c, d in segments if abs(b-d) <= 2 and abs(a-c) > 120]
    vs = [(a, min(b, d), max(b, d)) for a, b, c, d in segments if abs(a-c) <= 2 and abs(b-d) > 80]
    for x1, top, x2 in hs:
        for left, y1, y2 in vs:
            if abs(left-x1) > 5 or y1 > top+5 or y2 < top+80:
                continue
            for right, ry1, ry2 in vs:
                bottom = min(y2, ry2)
                if abs(right-x2) <= 5 and ry1 <= top+5 and bottom > top+80 and any(abs(by-bottom) <= 5 and bx1 <= left+5 and bx2 >= right-5 for bx1, by, bx2 in hs):
                    containers.append([left/w, top/h, (right-left)/w, (bottom-top)/h])
    return containers, icons


def local_candidates(image, rows):
    labels, annotations = group_labels(rows)
    rectangles, icons = shapes(image)
    groups, components = [], []
    for row in labels:
        bounds = row.get('bbox')
        containing = [r for r in rectangles if inside(bounds, r) and bounds[1]-r[1] < min(.08, r[3]*.3)
            and r[2] > bounds[2]*1.15 and r[3] > bounds[3]*3]
        is_group = bool(GROUP_LABEL.match(row['text']))
        if containing:
            container = min(containing, key=lambda b: b[2]*b[3])
            other_labels = [r for r in labels if r is not row and inside(r.get('bbox'), container)]
            is_group = is_group or (compact(row['text']) == 'awsfargate' and len(other_labels) >= 2)
        else:
            container = None
        if is_group:
            groups.append({**row, 'bbox': container, 'label_bbox': bounds})
            continue
        nearby = [b for b in icons if bounds and -.015 <= bounds[1]-(b[1]+b[3]) <= .065
            and abs(bounds[0]+bounds[2]/2-b[0]-b[2]/2) < max(.02, b[2]/2)]
        icon = min(nearby, key=lambda b: abs(bounds[1]-b[1]-b[3])) if nearby else None
        components.append({**row, 'label_bbox': bounds, 'bbox': union([bounds, icon]), 'icon_bbox': icon})
    return components, groups, annotations


def connection_candidates(image, components, groups):
    """Trace dark line networks after removing labels and symbols. Direction stays unknown.

    A branch or crossing with more than two endpoints is retained as an unresolved
    network, never expanded into a guessed all-to-all set of data flows.
    """
    try:
        import cv2
        import numpy as np
    except ImportError:
        return [], []
    small = image.convert('RGB')
    small.thumbnail((1800, 1800))
    rgb = np.asarray(small)
    h, w = rgb.shape[:2]
    mask = ((rgb.max(axis=2) < 185) & (rgb.max(axis=2).astype(int)-rgb.min(axis=2) < 65)).astype('uint8')*255
    for row in components + groups:
        for b in [p.get('bbox') for p in row.get('parts', [])] + ([row.get('icon_bbox')] if row.get('icon_bbox') else []):
            if b:
                x, y, bw, bh = b
                mask[max(0, round(y*h)-3):min(h, round((y+bh)*h)+3), max(0, round(x*w)-3):min(w, round((x+bw)*w)+3)] = 0
    horizontal = cv2.morphologyEx(mask, cv2.MORPH_OPEN, np.ones((1, 12), np.uint8))
    vertical = cv2.morphologyEx(mask, cv2.MORPH_OPEN, np.ones((12, 1), np.uint8))
    lines = cv2.bitwise_or(horizontal, vertical)
    lines = cv2.morphologyEx(lines, cv2.MORPH_CLOSE, np.ones((5, 5), np.uint8))
    count, cc, stats, _ = cv2.connectedComponentsWithStats(lines)
    links, unresolved = [], []
    for i in range(1, min(count, 1000)):
        x, y, bw, bh, area = stats[i]
        if max(bw, bh) < 30 or area < 25:
            continue
        network = [x/w, y/h, bw/w, bh/h]
        endpoints = []
        for index, row in enumerate(components):
            b = row.get('icon_bbox') or row.get('bbox')
            if not b:
                continue
            # Only proximity to actual line pixels, not the network bounding box.
            bx, by, cw, ch = b
            region = cc[max(0, round(by*h)-15):min(h, round((by+ch)*h)+15), max(0, round(bx*w)-15):min(w, round((bx+cw)*w)+15)]
            if np.any(region == i):
                endpoints.append(index)
        # A connector ending on a hosting group is not a connection between
        # every nearby datastore. Keep the entire network unresolved instead.
        group_contacts = []
        for index, row in enumerate(groups):
            b = row.get('bbox')
            if not b:
                continue
            gx, gy, gw, gh = [round(v*s) for v, s in zip(b, (w, h, w, h))]
            strips = [cc[max(0, gy+8):min(h, gy+gh-8), max(0, gx-8):min(w, gx+8)],
                cc[max(0, gy+8):min(h, gy+gh-8), max(0, gx+gw-8):min(w, gx+gw+8)]]
            if any(np.any(strip == i) for strip in strips):
                group_contacts.append(index)
        if len(endpoints) == 2 and not group_contacts:
            pair = tuple(sorted(endpoints))
            if not any(tuple(link['endpoints']) == pair for link in links):
                links.append({'endpoints': list(pair), 'bbox': network})
        elif len(endpoints) > 2 or (endpoints and group_contacts):
            unresolved.append({'endpoints': endpoints, 'groups': group_contacts, 'bbox': network, 'reason': 'branch_or_crossing'})
    return links, unresolved

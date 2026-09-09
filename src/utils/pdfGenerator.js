import jsPDF from 'jspdf';
import mermaid from 'mermaid';

const COLORS = {
    ink: [23, 31, 46],
    muted: [99, 110, 128],
    line: [225, 230, 238],
    panel: [246, 248, 252],
    brand: [16, 16, 16],
    success: [22, 163, 74],
    warning: [217, 119, 6],
    danger: [220, 38, 38],
    info: [16, 16, 16],
};

const SEVERITY_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1 };

const SEVERITY_THEME = {
    Critical: { fill: [220, 38, 38], soft: [254, 226, 226] },
    High: { fill: [234, 88, 12], soft: [255, 237, 213] },
    Medium: { fill: [217, 119, 6], soft: [254, 243, 199] },
    Low: { fill: [37, 99, 235], soft: [219, 234, 254] },
};

const LENS_THEME = {
    high: { fill: [254, 226, 226], ink: [153, 27, 27] },
    medium: { fill: [255, 237, 213], ink: [154, 52, 18] },
    low: { fill: [220, 252, 231], ink: [22, 101, 52] },
};

export const generateReport = async (data, projectName, reviewStates = {}) => {
    try {
        if (!data) {
            alert('No data to export.');
            return;
        }
        const qualityGate = data.engine_status?.quality_gate || {};
        const publicationLabel = qualityGate.publication_status === 'ready' ? 'Publication ready' : 'Technical review';
        if (qualityGate.status === 'blocked' || qualityGate.publication_status === 'blocked') {
            const reasons = (qualityGate.integrity_violations || [])
                .map((item) => item.detail)
                .join(' ');
            throw new Error(
                `Report publication is blocked because the model contradicts itself. ${reasons}`.trim()
            );
        }

        const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
        const pageWidth = doc.internal.pageSize.getWidth();
        const pageHeight = doc.internal.pageSize.getHeight();
        const footerTop = pageHeight - 13;
        const contentBottomLimit = footerTop - 4;
        const left = 14;
        const right = 14;
        const contentWidth = pageWidth - left - right;
        const lineGap = 4.5;
        let y = 16;

        const allThreats = [...(data.threats || [])].sort((a, b) => {
            const sevDelta = (SEVERITY_RANK[b.severity] || 1) - (SEVERITY_RANK[a.severity] || 1);
            if (sevDelta !== 0) return sevDelta;
            return (b.risk_score || 0) - (a.risk_score || 0);
        });
        const excluded = allThreats.filter((t) => reviewStates[t.id] === 'false_positive');
        const included = allThreats.filter((t) => reviewStates[t.id] !== 'false_positive');
        const confirmed = included.filter((t) => String(t.tier).toLowerCase() === 'confirmed');
        const potential = included.filter((t) => String(t.tier).toLowerCase() !== 'confirmed');
        const score = data.score || 0;
        const aiLens = data.ai_security_lens || { overview: '', items: [] };
        const priorityActions = Object.values(reviewStates).some((state) => state !== 'open')
            ? included.filter((t) => !['mitigated', 'accepted'].includes(reviewStates[t.id]) && t.finding_type !== 'validation_question').slice(0, 3).map((t) => ({
                title: t.title, priority: t.severity, why_now: `${t.tier} finding; ${t.severity} severity.`,
                action: t.mitigation, focus_area: t.affected_components,
            }))
            : (data.priority_actions || []).slice(0, 3);

        const checkPageBreak = (requiredHeight = 24) => {
            if (y + requiredHeight > contentBottomLimit) {
                doc.addPage();
                y = 16;
                drawPageHeader();
            }
        };

        const writeText = (text, options = {}) => {
            const {
                size = 10,
                style = 'normal',
                color = COLORS.ink,
                maxWidth = contentWidth,
                x = left,
                leading = lineGap,
            } = options;

            doc.setFontSize(size);
            doc.setFont('helvetica', style);
            doc.setTextColor(...color);
            const lines = doc.splitTextToSize(String(text || ''), maxWidth);
            doc.text(lines, x, y);
            y += Math.max(lines.length, 1) * leading;
            checkPageBreak(0);
        };

        const drawSectionTitle = (title, subtitle) => {
            y += 2;
            checkPageBreak(28);
            doc.setDrawColor(...COLORS.line);
            doc.setFillColor(...COLORS.brand);
            doc.roundedRect(left, y - 1.5, 1.8, 8, 0.8, 0.8, 'F');
            writeText(title, { size: 14, style: 'bold', x: left + 5, leading: 6.5 });
            if (subtitle) {
                writeText(subtitle, { size: 9, color: COLORS.muted, x: left + 5, leading: 4.3 });
            }
            y += 1;
            doc.line(left + 3.8, y, pageWidth - right, y);
            y += 4;
        };

        const drawCard = (x, w, h, fill = COLORS.panel) => {
            doc.setFillColor(...fill);
            doc.setDrawColor(...COLORS.line);
            doc.roundedRect(x, y, w, h, 2.4, 2.4, 'FD');
        };

        const drawMetricCards = () => {
            const critical = confirmed.filter((t) => t.severity === 'Critical').length;
            const high = confirmed.filter((t) => t.severity === 'High').length;

            const cards = [
                { label: 'Confirmed critical', value: critical, color: COLORS.danger },
                { label: 'Confirmed high', value: high, color: [234, 88, 12] },
                { label: 'Confirmed risks', value: confirmed.length, color: COLORS.brand },
                { label: 'Potential risks', value: potential.length, color: COLORS.warning },
            ];

            const gap = 4;
            const cardW = (contentWidth - gap * 3) / 4;
            const cardH = 20;
            checkPageBreak(cardH + 6);

            cards.forEach((card, i) => {
                const x = left + i * (cardW + gap);
                doc.setFillColor(248, 250, 253);
                doc.setDrawColor(...COLORS.line);
                doc.roundedRect(x, y, cardW, cardH, 2.2, 2.2, 'FD');
                doc.setFillColor(...card.color);
                doc.roundedRect(x, y, cardW, 4.4, 2.2, 2.2, 'F');

                doc.setFontSize(7.5);
                doc.setTextColor(...COLORS.muted);
                doc.setFont('helvetica', 'bold');
                doc.text(card.label, x + 2.3, y + 9);

                doc.setFontSize(15);
                doc.setTextColor(...COLORS.ink);
                doc.setFont('helvetica', 'bold');
                doc.text(String(card.value), x + 2.3, y + 16.2);
            });

            y += cardH + 6;
        };

        const drawPageHeader = () => {
            doc.setFillColor(250, 251, 254);
            doc.rect(0, 0, pageWidth, 10.5, 'F');
            doc.setDrawColor(...COLORS.line);
            doc.line(0, 10.5, pageWidth, 10.5);

            doc.setFontSize(7.5);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(...COLORS.brand);
            doc.text('Aegis Threat Report', left, 7);

            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...COLORS.muted);
            doc.text(projectName || 'Untitled Project', pageWidth - right, 7, { align: 'right' });
        };

        const drawCover = () => {
            doc.setFillColor(255, 255, 255);
            doc.rect(0, 0, pageWidth, 44, 'F');
            doc.setDrawColor(...COLORS.line);
            doc.line(left, 41, pageWidth - right, 41);

            doc.setTextColor(...COLORS.ink);
            doc.setFont('helvetica', 'bold');
            doc.setFontSize(9);
            doc.text('AEGIS THREAT', left, 12);
            doc.setFontSize(20);
            doc.text('Technical Threat Model', left, 23);
            doc.setFontSize(11);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...COLORS.muted);
            doc.text(projectName || 'Untitled Project', left, 30);

            const generatedAt = new Date().toLocaleString();
            doc.setFontSize(8);
            doc.text(`Generated ${generatedAt} | ${publicationLabel}`, left, 36);

            const scoreColor = score >= 70 ? COLORS.success : score >= 40 ? COLORS.warning : COLORS.danger;
            doc.setFillColor(255, 255, 255);
            doc.setDrawColor(...scoreColor);
            doc.roundedRect(pageWidth - 52, 10, 38, 23, 1.5, 1.5, 'FD');
            doc.setFont('helvetica', 'bold');
            doc.setFontSize(16);
            doc.setTextColor(...COLORS.ink);
            doc.text(`${score}/100`, pageWidth - 33, 21.5, { align: 'center' });
            doc.setFontSize(7);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...COLORS.muted);
            doc.text('Security score', pageWidth - 33, 27.5, { align: 'center' });

            y = 52;
        };

        const drawAILens = () => {
            drawSectionTitle('AI Security Lens', aiLens.overview || 'Focused AI-native risk storytelling across prompt, data, model, tool, and training surfaces.');
            if (!aiLens.items?.length) {
                writeText('No AI-specific lens was generated for this analysis run.', { color: COLORS.muted, size: 9 });
                return;
            }

            const gap = 4;
            const boxW = (contentWidth - gap) / 2;
            const boxH = 24;
            for (let i = 0; i < aiLens.items.length; i += 2) {
                checkPageBreak(boxH + 6);
                const rowItems = aiLens.items.slice(i, i + 2);
                rowItems.forEach((item, col) => {
                    const x = left + col * (boxW + gap);
                    const tone = LENS_THEME[item.level] || LENS_THEME.low;

                    doc.setFillColor(...tone.fill);
                    doc.setDrawColor(...COLORS.line);
                    doc.roundedRect(x, y, boxW, boxH, 2.2, 2.2, 'FD');

                    doc.setFont('helvetica', 'bold');
                    doc.setFontSize(8);
                    doc.setTextColor(...tone.ink);
                    doc.text(item.label, x + 2.5, y + 5.6);

                    doc.setFontSize(13);
                    doc.text(String(item.count || 0), x + 2.5, y + 12.5);

                    doc.setFont('helvetica', 'normal');
                    doc.setFontSize(7.3);
                    doc.text((item.summary || '').substring(0, 120), x + 2.5, y + 18.2, {
                        maxWidth: boxW - 5,
                    });
                });
                y += boxH + gap;
            }
            y += 3;
        };

        const drawTopActions = () => {
            drawSectionTitle('Top 3 Things To Fix First', 'Highest-leverage actions based on severity, confidence, and architectural exposure.');
            if (!priorityActions.length) {
                writeText('No priority actions available for this run.', { color: COLORS.muted, size: 9 });
                return;
            }

            priorityActions.forEach((action, index) => {
                checkPageBreak(36);
                const theme = SEVERITY_THEME[action.priority] || SEVERITY_THEME.Low;
                const cardH = 31;
                const x = left;
                drawCard(x, contentWidth, cardH);

                doc.setFillColor(...theme.fill);
                doc.roundedRect(x, y, 10, 10, 1.8, 1.8, 'F');
                doc.setTextColor(255, 255, 255);
                doc.setFont('helvetica', 'bold');
                doc.setFontSize(9);
                doc.text(String(index + 1), x + 5, y + 6.6, { align: 'center' });

                doc.setTextColor(...COLORS.ink);
                doc.setFontSize(9.5);
                doc.setFont('helvetica', 'bold');
                doc.text(action.title || 'Priority action', x + 13, y + 4.8, { maxWidth: contentWidth - 17 });

                doc.setFontSize(7.4);
                doc.setFont('helvetica', 'normal');
                doc.setTextColor(...COLORS.muted);
                doc.text(`Why now: ${action.why_now || 'High risk finding with immediate mitigation value.'}`, x + 13, y + 9.2, {
                    maxWidth: contentWidth - 17,
                });

                doc.setTextColor(...COLORS.success);
                doc.setFont('helvetica', 'bold');
                doc.text('Action', x + 13, y + 17.5);
                doc.setFont('helvetica', 'normal');
                doc.setTextColor(...COLORS.ink);
                doc.text(action.action || 'Apply mitigation guidance from this finding.', x + 13, y + 21.3, {
                    maxWidth: contentWidth - 17,
                });

                if (action.focus_area?.length) {
                    doc.setTextColor(...COLORS.muted);
                    doc.setFontSize(7);
                    doc.text(`Focus area: ${action.focus_area.join(', ')}`, x + 13, y + 27.6, {
                        maxWidth: contentWidth - 17,
                    });
                }

                y += cardH + 4;
            });
        };

        const drawArchitectureSnapshot = async () => {
            drawSectionTitle('Architecture Snapshot', 'A compact view of key components, flows, and rendered system diagram.');

            const components = data.architecture?.components || [];
            const flows = data.architecture?.flows || [];

            const compPreview = components.slice(0, 8).map((c) => `${c.name || c.id} (${c.type || 'Service'})`);
            const flowPreview = flows.slice(0, 8).map((f) => `${f.source_id} -> ${f.target_id} (${(f.protocol || 'n/a').toUpperCase()})`);

            writeText(`Components modeled: ${components.length}`, { size: 9, style: 'bold', color: COLORS.brand });
            writeText(compPreview.join(' | ') || 'No components parsed.', { size: 8.5, color: COLORS.muted });
            y += 1;
            writeText(`Data flows modeled: ${flows.length}`, { size: 9, style: 'bold', color: COLORS.brand });
            writeText(flowPreview.join(' | ') || 'No flows parsed.', { size: 8.5, color: COLORS.muted });

            if (!data.diagram) return;

            let diagramPlaced = false;
            try {
                mermaid.initialize({
                    startOnLoad: false,
                    theme: 'default',
                    securityLevel: 'strict',
                    fontFamily: 'Arial, sans-serif',
                    flowchart: { useMaxWidth: false, htmlLabels: false, curve: 'basis' },
                });

                const diagramId = `pdf-diagram-${Date.now()}`;
                const { svg } = await mermaid.render(diagramId, data.diagram);

                const parser = new DOMParser();
                const svgDoc = parser.parseFromString(svg, 'image/svg+xml');
                const svgNode = svgDoc.querySelector('svg');
                if (svgNode) {
                    const viewBox = (svgNode.getAttribute('viewBox') || '0 0 900 620').split(/\s+/).map(Number);
                    const vbW = viewBox[2] || 900;
                    const vbH = viewBox[3] || 620;
                    const renderW = 1280;
                    const renderH = Math.round(renderW * (vbH / vbW));

                    svgNode.setAttribute('width', String(renderW));
                    svgNode.setAttribute('height', String(renderH));
                    svgNode.setAttribute('xmlns', 'http://www.w3.org/2000/svg');

                    const bgRect = svgDoc.createElementNS('http://www.w3.org/2000/svg', 'rect');
                    bgRect.setAttribute('x', '0');
                    bgRect.setAttribute('y', '0');
                    bgRect.setAttribute('width', '100%');
                    bgRect.setAttribute('height', '100%');
                    bgRect.setAttribute('fill', '#ffffff');
                    svgNode.insertBefore(bgRect, svgNode.firstChild);

                    const serialized = new XMLSerializer().serializeToString(svgNode);
                    const encoded = btoa(unescape(encodeURIComponent(serialized)));
                    const src = `data:image/svg+xml;base64,${encoded}`;

                    const image = new Image();
                    const loaded = await new Promise((resolve) => {
                        image.onload = () => resolve(true);
                        image.onerror = () => resolve(false);
                        image.src = src;
                    });

                    if (loaded && image.naturalWidth > 0) {
                        const canvas = document.createElement('canvas');
                        canvas.width = renderW;
                        canvas.height = renderH;
                        const ctx = canvas.getContext('2d');
                        ctx.fillStyle = '#ffffff';
                        ctx.fillRect(0, 0, renderW, renderH);
                        ctx.drawImage(image, 0, 0, renderW, renderH);
                        const png = canvas.toDataURL('image/png');

                        checkPageBreak(88);
                        const maxH = 82;
                        let pdfW = contentWidth;
                        let pdfH = (renderH / renderW) * pdfW;
                        if (pdfH > maxH) {
                            pdfH = maxH;
                            pdfW = (renderW / renderH) * pdfH;
                        }
                        const x = left + (contentWidth - pdfW) / 2;
                        doc.setDrawColor(...COLORS.line);
                        doc.roundedRect(x - 1.4, y - 1.4, pdfW + 2.8, pdfH + 2.8, 2, 2, 'S');
                        doc.addImage(png, 'PNG', x, y, pdfW, pdfH);
                        y += pdfH + 5;
                        diagramPlaced = true;
                    }
                }
            } catch (error) {
                console.error('Diagram rendering failed for PDF export:', error);
            } finally {
                mermaid.initialize({
                    startOnLoad: false,
                    theme: document.documentElement.classList.contains('dark') ? 'dark' : 'default',
                    securityLevel: 'loose',
                    fontFamily: 'Arial, sans-serif',
                });
            }

            if (!diagramPlaced) {
                writeText('Diagram preview could not be rendered. Mermaid source is included below for reference.', {
                    size: 8,
                    color: COLORS.muted,
                });
                const previewLines = data.diagram.split('\n').slice(0, 18);
                checkPageBreak(35);
                doc.setFillColor(250, 251, 254);
                doc.setDrawColor(...COLORS.line);
                doc.roundedRect(left, y, contentWidth, 30, 2, 2, 'FD');
                doc.setFont('courier', 'normal');
                doc.setFontSize(6.7);
                doc.setTextColor(...COLORS.muted);
                doc.text(previewLines.map((line) => line.substring(0, 110)), left + 2.2, y + 4.6);
                y += 33;
            }
        };

        const drawThreatSection = (title, threats, toneColor) => {
            drawSectionTitle(title, `${threats.length} ${threats.length === 1 ? 'finding' : 'findings'} in this section.`);
            if (!threats.length) {
                writeText('No findings in this section.', { size: 9, color: COLORS.muted });
                return;
            }

            threats.forEach((threat) => {
                const severity = threat.severity || 'Low';
                const theme = SEVERITY_THEME[severity] || SEVERITY_THEME.Low;
                doc.setFont('helvetica', 'normal');
                doc.setFontSize(8.2);
                const descLines = doc.splitTextToSize(threat.description || '', contentWidth - 5.2).slice(0, 2);
                const refs = [];
                if (threat.cwe?.length) refs.push(`CWE ${threat.cwe.join(', ')}`);
                if (threat.mitre_attack?.length) refs.push(`MITRE ATT&CK ${threat.mitre_attack.join(', ')}`);
                if (threat.mitre_atlas?.length) refs.push(`MITRE ATLAS ${threat.mitre_atlas.join(', ')}`);
                if (threat.owasp_top_10?.length) refs.push(`OWASP ${threat.owasp_top_10.map((o) => String(o).split('-')[0]).join(', ')}`);
                for (const mapping of threat.explanation?.framework_mappings || []) {
                    refs.push(`${mapping.framework_name} ${mapping.version}: ${mapping.id}`);
                }
                doc.setFontSize(7);
                const refLines = refs.length ? doc.splitTextToSize(refs.join(' | '), contentWidth - 5.2) : [];
                doc.setFontSize(7.3);
                const mitigationLines = doc.splitTextToSize(`Mitigation: ${threat.mitigation || 'N/A'}`, contentWidth - 7).slice(0, 3);
                const descTop = 14.2;
                const refsTop = descTop + Math.max(descLines.length, 1) * 3.6 + 1.2;
                const mitigationTop = refsTop + refLines.length * 3.4 + 1.3;
                const mitigationHeight = Math.max(8, mitigationLines.length * 3.3 + 3.2);
                const boxHeight = mitigationTop + mitigationHeight + 1.5;
                checkPageBreak(boxHeight + 6);

                doc.setFillColor(252, 253, 255);
                doc.setDrawColor(...COLORS.line);
                doc.roundedRect(left, y, contentWidth, boxHeight, 2.4, 2.4, 'FD');

                doc.setFillColor(...theme.fill);
                doc.roundedRect(left, y, contentWidth, 5.6, 2.4, 2.4, 'F');
                doc.setFont('helvetica', 'bold');
                doc.setFontSize(8.2);
                doc.setTextColor(255, 255, 255);
                doc.text(`${severity.toUpperCase()} | ${threat.title || 'Untitled threat'}`.substring(0, 112), left + 2.6, y + 3.9);

                doc.setTextColor(...COLORS.muted);
                doc.setFontSize(7.2);
                doc.setFont('helvetica', 'normal');
                const meta = [
                    threat.category || 'Unknown category',
                    `Confidence: ${threat.confidence || 'Medium'}`,
                    ...(reviewStates[threat.id] && reviewStates[threat.id] !== 'open' ? [`Review: ${reviewStates[threat.id].replaceAll('_', ' ')}`] : []),
                    `STRIDE: ${(threat.affected_stride_categories?.length ? threat.affected_stride_categories : [threat.stride_category || threat.category]).join(', ')}`,
                ].filter(Boolean);
                doc.text(doc.splitTextToSize(meta.join(' | '), contentWidth - 5.2).slice(0, 1), left + 2.6, y + 10.1);

                doc.setTextColor(...COLORS.ink);
                doc.setFontSize(8.2);
                doc.text(descLines, left + 2.6, y + descTop);

                if (refLines.length) {
                    doc.setTextColor(...toneColor);
                    doc.setFontSize(7);
                    doc.text(refLines, left + 2.6, y + refsTop);
                }

                doc.setFillColor(...theme.soft);
                doc.roundedRect(left + 2, y + mitigationTop, contentWidth - 4, mitigationHeight, 1.8, 1.8, 'F');
                doc.setTextColor(...COLORS.ink);
                doc.setFontSize(7.3);
                doc.text(mitigationLines, left + 3.2, y + mitigationTop + 4.1);

                y += boxHeight + 4;
            });
        };

        // What the analyst still needs from the architecture owner. Grouped by the
        // control each question resolves, so the reader gets a handful of asks
        // rather than one line per unresolved STRIDE cell.
        const drawEvidenceRequests = () => {
            const evidence = data.evidence_requests || {};
            const requests = evidence.requests || [];
            if (!requests.length) return;

            checkPageBreak(65);
            drawSectionTitle('Evidence Requests', evidence.summary || 'Questions that would resolve the unassessed parts of this model.');

            requests.forEach((request) => {
                checkPageBreak(30);
                const theme = SEVERITY_THEME[request.priority] || SEVERITY_THEME.Low;

                doc.setFillColor(...theme.fill);
                doc.roundedRect(left, y, 3, 9, 1, 1, 'F');
                writeText(`${request.rank}. ${request.title} (${request.priority})`, {
                    size: 9.5, style: 'bold', color: COLORS.brand, x: left + 5.5, maxWidth: contentWidth - 5.5,
                });
                writeText(request.question, { size: 8.6, color: COLORS.ink, x: left + 5.5, maxWidth: contentWidth - 5.5 });
                writeText(
                    `Resolves ${request.resolves_cells} STRIDE cell(s) across ${request.elements.length} element(s): `
                    + request.elements.slice(0, 8).map((element) => element.label).join(', ')
                    + (request.elements.length > 8 ? `, and ${request.elements.length - 8} more` : ''),
                    { size: 7.8, color: COLORS.muted, x: left + 5.5, maxWidth: contentWidth - 5.5 },
                );
                writeText(`Evidence that closes it: ${request.accepted_evidence.join('; ')}`, {
                    size: 7.8, color: COLORS.muted, x: left + 5.5, maxWidth: contentWidth - 5.5,
                });
                y += 2;
            });
        };

        const drawFooterOnAllPages = () => {
            const pages = doc.internal.getNumberOfPages();
            for (let i = 1; i <= pages; i += 1) {
                doc.setPage(i);
                doc.setDrawColor(...COLORS.line);
                doc.line(left, pageHeight - 13, pageWidth - right, pageHeight - 13);

                doc.setFontSize(7);
                doc.setTextColor(...COLORS.muted);
                doc.setFont('helvetica', 'normal');
                doc.text(`Aegis Threat | ${projectName || 'Untitled Project'}`, left, pageHeight - 8.4);
                doc.text(`Page ${i} / ${pages}`, pageWidth - right, pageHeight - 8.4, { align: 'right' });
                doc.text(new Date().toLocaleDateString(), pageWidth / 2, pageHeight - 8.4, { align: 'center' });
            }
        };

        drawCover();
        drawSectionTitle('Assessment Summary');
        writeText(excluded.length
            ? `${confirmed.length} confirmed risks and ${potential.length} potential risks after reviewer exclusions. ${excluded.length} ${excluded.length === 1 ? 'finding marked false positive is' : 'findings marked false positive are'} retained in the Reviewer Exclusions section.`
            : data.summary || 'No summary available.', { size: 9.5, color: COLORS.ink });
        if (excluded.length) writeText('The security score is the original analysis score; reviewer decisions do not recalculate it.', { size: 8, color: COLORS.muted });
        if (qualityGate.completeness_warnings?.length) {
            writeText('Review required: ' + qualityGate.completeness_warnings.map((item) => item.detail).join(' '), { size: 8, color: COLORS.muted });
        }
        writeText('Confirmed means supported by submitted evidence, not independently verified exploitation.', { size: 8, color: COLORS.muted });
        drawMetricCards();

        drawTopActions();
        if (aiLens.items?.length) drawAILens();
        await drawArchitectureSnapshot();

        drawThreatSection('Confirmed Risks', confirmed, COLORS.brand);
        drawThreatSection('Potential Risks', potential, COLORS.warning);
        if (excluded.length) drawThreatSection('Reviewer Exclusions', excluded, COLORS.muted);
        drawEvidenceRequests();
        const inventory = data.engine_status?.issue_inventory;
        if (inventory?.declared) {
            drawSectionTitle('Source Issue Accountability');
            writeText(`${inventory.reported} reported, ${inventory.out_of_scope || 0} outside scope, ${inventory.unaccounted} needing review.`, { size: 9, color: COLORS.ink });
            for (const issue of inventory.issues) {
                writeText(`${issue.status.replaceAll('_', ' ')}: ${issue.statement}`, { size: 9, color: COLORS.ink });
                writeText(`${issue.document || 'Submitted source'}${issue.line ? `, line ${issue.line}` : ''}. ${issue.reason}`, { size: 8, color: COLORS.muted });
            }
        }

        drawFooterOnAllPages();
        doc.save(`${(projectName || 'Aegis_Threat_Report').replace(/\s+/g, '_')}.pdf`);
    } catch (error) {
        console.error('PDF Generation Error:', error);
        alert(`PDF generation failed: ${error.message}`);
    }
};

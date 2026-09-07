from datetime import datetime
from typing import List

from ..models import AnalysisResult, Threat


class ReportGenerator:
    @staticmethod
    def generate_markdown(result: AnalysisResult) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines: List[str] = [
            f"# Threat Model Report: {result.project_name}",
            f"Generated: {now}",
            f"Publication status: {((result.engine_status or {}).get('quality_gate') or {}).get('publication_status', 'review')}",
            "",
        ]

        lines.extend(ReportGenerator._technical_scope(result))
        lines.extend(ReportGenerator._architecture_model(result))
        lines.extend(ReportGenerator._assets_section(result))
        lines.extend(ReportGenerator._data_flows_section(result))
        lines.extend(ReportGenerator._findings_by_type(result))
        lines.extend(ReportGenerator._attack_paths(result))
        lines.extend(ReportGenerator._risk_table(result))
        lines.extend(ReportGenerator._stride_coverage(result))
        lines.extend(ReportGenerator._evidence_requests(result))
        lines.extend(ReportGenerator._engine_status(result))
        lines.extend(ReportGenerator._mitigations(result))
        lines.extend(ReportGenerator._missing_information(result))
        return "\n".join(lines)

    @staticmethod
    def _technical_scope(result: AnalysisResult) -> List[str]:
        confirmed = len([threat for threat in result.threats if threat.tier == "Confirmed"])
        return [
            "## 1. Technical Scope and Evidence",
            result.summary,
            f"- Components modeled: {len(result.architecture.components)}",
            f"- Data flows modeled: {len(result.architecture.flows)}",
            f"- Assets classified: {len(result.architecture.assets)}",
            f"- Confirmed findings: {confirmed}",
            f"- Risk model: {(result.risk_methodology or {}).get('version', 'technical-v1')}",
            *ReportGenerator._unread_sources(result),
            "",
        ]

    @staticmethod
    def _unread_sources(result: AnalysisResult) -> List[str]:
        """Say up front which uploaded content the model never saw.

        Stated beside the scope counts rather than in a footnote, because it
        qualifies every count above it.
        """
        gate = (result.engine_status or {}).get("quality_gate") or {}
        unread = gate.get("unread_document_content") or []
        if not unread:
            return []

        lines = ["- Documents not fully read:"]
        for record in unread:
            pages = record.get("unread_pages") or []
            where = f"pages {', '.join(pages)}" if pages else record.get("detail", "")
            lines.append(f"  - {record.get('document')}: {where}")
        return lines

    @staticmethod
    def _architecture_model(result: AnalysisResult) -> List[str]:
        lines = ["## 2. System Model", "### Components"]
        for component in result.architecture.components:
            lines.append(f"- {component.name} ({component.type}) trust={component.trust_level}")
        lines.append("")
        lines.append("### Trust Boundaries")
        for boundary in result.architecture.trust_boundaries:
            lines.append(f"- {boundary.name} ({boundary.boundary_type}): {', '.join(boundary.components)}")
        lines.append("")
        return lines

    @staticmethod
    def _stride_coverage(result: AnalysisResult) -> List[str]:
        coverage = result.stride_coverage or {}
        lines = [
            "## 8. STRIDE Coverage Matrix",
            f"- Elements assessed: {coverage.get('elements_assessed', 0)}",
            f"- Applicable STRIDE cells: {coverage.get('applicable_cells', 0)}",
            f"- STRIDE cells assessed: {coverage.get('assessment_percent', 100)}%",
            f"- Evidence resolution by findings or stated controls: {coverage.get('evidence_resolution_percent', coverage.get('coverage_percent', 0))}%",
            f"- Unknown cells requiring architecture clarification: {coverage.get('unknown_cells', 0)}",
            "",
            "| STRIDE category | Findings | Controls present | Unknown | Not applicable |",
            "|---|---:|---:|---:|---:|",
        ]
        for category in coverage.get("categories", []):
            summary = (coverage.get("category_summary") or {}).get(category, {})
            lines.append(
                f"| {category} | {summary.get('finding', 0)} | {summary.get('control_present', 0)} | "
                f"{summary.get('unknown', 0) + summary.get('potential', 0)} | {summary.get('not_applicable', 0)} |"
            )
        unknown = [cell for cell in coverage.get("cells", []) if cell.get("status") in {"unknown", "potential"}]
        if unknown:
            lines.append("")
            lines.append(
                f"{len(unknown)} cells are unresolved because the design does not state the "
                "relevant control. Section 8a groups them into the questions that would resolve them."
            )
        lines.append("")
        return lines

    @staticmethod
    def _evidence_requests(result: AnalysisResult) -> List[str]:
        """The questions to take back to the architect, ordered by what they unblock."""
        evidence = result.evidence_requests or {}
        requests = evidence.get("requests", [])
        if not requests:
            return []

        lines = [
            "## 8a. Evidence Requests",
            evidence.get("summary", ""),
            "",
        ]
        for request in requests:
            lines.append(f"### {request['rank']}. {request['title']} [{request['priority']}]")
            lines.append(f"**Question:** {request['question']}")
            lines.append(
                f"- Resolves {request['resolves_cells']} STRIDE cell(s) across "
                f"{len(request['elements'])} element(s): {', '.join(request['stride_categories'])}"
            )
            shown = request["elements"][:10]
            for element in shown:
                lines.append(
                    f"  - {element['label']} [{element['exposure'].replace('_', ' ')}]: "
                    f"{', '.join(element['stride_categories'])}"
                )
            remaining = len(request["elements"]) - len(shown)
            if remaining:
                lines.append(f"  - and {remaining} further element(s) waiting on the same answer")
            lines.append("- Evidence that would close this:")
            for item in request["accepted_evidence"]:
                lines.append(f"  - {item}")
            lines.append(f"- Why it matters: {request['why_it_matters']}")
            lines.append("")
        return lines

    @staticmethod
    def _engine_status(result: AnalysisResult) -> List[str]:
        lines = ["## 9. Analysis Engine Status"]
        for name, status in (result.engine_status or {}).items():
            state = status.get("status", "unknown") if isinstance(status, dict) else str(status)
            details = ""
            if isinstance(status, dict) and status.get("errors"):
                details = f"; errors={'; '.join(status['errors'])}"
            lines.append(f"- {name}: {state}{details}")
        for issue in (result.architecture_validation or {}).get("issues", []):
            lines.append(f"- Architecture gap [{issue.get('severity')}]: {issue.get('message')}")
        lines.append("")
        return lines

    @staticmethod
    def _assets_section(result: AnalysisResult) -> List[str]:
        lines = ["## 3. Assets and Data Classification"]
        for asset in result.architecture.assets:
            lines.append(f"- {asset.name}: sensitivity={asset.sensitivity}, location={asset.location}")
        lines.append("")
        return lines

    @staticmethod
    def _data_flows_section(result: AnalysisResult) -> List[str]:
        lines = ["## 4. Data Flows and Trust Boundaries"]
        for flow in result.architecture.flows:
            suffix = "assumed" if flow.assumed else "explicit"
            lines.append(f"- {flow.source_id} -> {flow.target_id} [{flow.protocol}] data={flow.data_type} ({suffix})")
        lines.append("")
        return lines

    @staticmethod
    def _findings_by_type(result: AnalysisResult) -> List[str]:
        labels = {
            "architecture": "Architecture Threats",
            "code": "Code Vulnerabilities",
            "iac": "IaC Misconfigurations",
            "control_gap": "Control Gaps",
            "validation_question": "Validation Questions",
        }
        groups = result.finding_groups or {}
        lines = ["## 5. Technical Findings"]
        for finding_type, label in labels.items():
            lines.append(f"### {label}")
            findings = groups.get(finding_type, [])
            if not findings:
                lines.append("- No findings in this category.")
                continue
            for threat in findings:
                lines.extend(ReportGenerator._format_threat(threat))
        lines.append("")
        return lines

    @staticmethod
    def _format_flows(threat: Threat) -> str:
        """The flows this finding is about, or the paths that reach its component.

        Where neither exists the reason is written out, because "n/a" reads the
        same whether the finding is local to one component or the architecture
        never described a single path.
        """
        scoped = threat.affected_data_flows or ([threat.data_flow] if threat.data_flow else [])
        if scoped:
            return ', '.join(scoped)
        explanation = threat.explanation or {}
        related = explanation.get('component_flows') or []
        if related:
            return (
                'none specific to this finding; paths touching the component: '
                + ', '.join(f"{flow['label']} ({flow['direction']})" for flow in related)
            )
        if explanation.get('flow_context') == 'no_flows_modeled':
            return 'no data flows are modeled for this architecture'
        return 'n/a'

    @staticmethod
    def _format_threat(threat: Threat) -> List[str]:
        lines = [
            f"### {threat.title}",
            f"- STRIDE: {', '.join(threat.affected_stride_categories or [threat.stride_category or threat.category])}",
            f"- Severity: {threat.severity}",
            f"- Tier and confidence: {threat.tier} / {threat.confidence}",
            f"- Finding type: {threat.finding_type}",
            f"- Likelihood: {threat.likelihood}",
            f"- Impact: {threat.impact}",
            f"- Components: {', '.join(threat.affected_components or ([threat.component] if threat.component else [])) or 'n/a'}",
            f"- Data flows: {ReportGenerator._format_flows(threat)}",
            f"- Assets: {', '.join(threat.affected_assets or ([threat.asset] if threat.asset else [])) or 'n/a'}",
            f"- Root cause: {threat.root_cause or 'n/a'}",
            f"- Attack scenario: {threat.attack_scenario or threat.realistic_attack_scenario or threat.description}",
            f"- Business impact: {threat.business_impact or 'n/a'}",
            f"- Mappings: CWE={', '.join(threat.cwe or []) or 'n/a'} | MITRE={', '.join(threat.mitre_attack or []) or 'n/a'} | OWASP={', '.join(threat.owasp_top_10 or []) or 'n/a'}",
        ]
        for mapping in (threat.explanation or {}).get("framework_mappings") or []:
            lines.append(f"- Framework reference: [{mapping['framework_name']} {mapping['version']} / {mapping['id']}: {mapping['name']}]({mapping['url']}) (taxonomy alignment, not compliance certification)")
        if threat.evidence_details:
            lines.append("- Evidence:")
            for item in threat.evidence_details:
                # A cited record names the document, page and line it came from.
                # Anything else falls back to the element the evidence points at.
                reference = item.get("cite") or item.get("source_ref", "architecture input")
                if not item.get("cite") and item.get("line"):
                    reference = f"{reference}:{item['line']}"
                lines.append(f"  - [{item.get('source_type', 'architecture')}] {reference}: {item.get('statement', '')}")
        if threat.preconditions:
            lines.append(f"- Preconditions: {' '.join(threat.preconditions)}")
        if threat.attack_path:
            lines.append("- Attack path:")
            for step in threat.attack_path.get("steps", []):
                lines.append(f"  - {step}")
        return lines

    @staticmethod
    def _attack_paths(result: AnalysisResult) -> List[str]:
        lines = ["## 6. Evidence-Backed Attack Paths"]
        for path in (result.attack_chains or {}).get("paths", []):
            lines.append(f"### {path.get('id', path.get('related_threat_id', 'Attack path'))}")
            lines.append(f"- Entry point: {path.get('entry_point', 'unknown')}")
            lines.append(f"- Target: {path.get('target_component', 'unknown')}")
            lines.append(f"- Severity: {path.get('severity', 'unknown')} | Confidence: {path.get('confidence', 'unknown')}")
            lines.append(f"- Path status: {path.get('path_status', 'unknown')} | Inferred hops: {path.get('inferred_hops', 0)}")
            for step in path.get("steps", []):
                lines.append(f"  - {step}")
        lines.append("")
        return lines

    @staticmethod
    def _risk_table(result: AnalysisResult) -> List[str]:
        lines = [
            "## 7. Risk Calculation",
            "| Threat | Exposure | Data Sensitivity | Exploit Complexity | Privilege Required | Evidence | Likelihood | Impact | Severity |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for threat in sorted(result.threats, key=lambda item: item.risk_score or 0, reverse=True):
            lines.append(
                f"| {threat.id} | {threat.exposure or 'n/a'} | {threat.data_sensitivity or 'n/a'} | "
                f"{threat.exploit_complexity or 'n/a'} | {threat.privilege_required or 'n/a'} | {threat.risk_factors.get('evidence_confidence', 'n/a')} | "
                f"{threat.likelihood} | {threat.impact} | {threat.severity} |"
            )
        lines.append("")
        return lines

    @staticmethod
    def _mitigations(result: AnalysisResult) -> List[str]:
        lines = ["## 10. Remediation Backlog"]
        for threat in sorted(result.threats, key=lambda item: item.risk_score or 0, reverse=True):
            lines.append(f"### {threat.title}")
            lines.append(f"- Specific control: {threat.specific_control or threat.mitigation}")
            lines.append(f"- Implementation detail: {threat.implementation_detail or threat.mitigation}")
            if threat.optional_config_example:
                lines.append(f"- Example: {threat.optional_config_example}")
        lines.append("")
        return lines

    @staticmethod
    def _missing_information(result: AnalysisResult) -> List[str]:
        lines = ["## 11. Coverage Gaps"]
        for item in (result.coverage or {}).get("missing_information", []):
            lines.append(f"- {item.get('message', 'Missing context identified.')}")
        assumptions = (result.coverage or {}).get("assumptions", [])
        for assumption in assumptions:
            lines.append(f"- Assumption: {assumption.get('message', 'Context was inferred.')}")
        lines.append("")
        return lines

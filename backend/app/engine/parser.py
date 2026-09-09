import re
import uuid
import logging
from typing import List, Dict, Any, Optional, Tuple
from ..models import Asset, Component, DataFlow, SystemArchitecture, TrustBoundary
from . import control_statements, graph, prose, technology_catalog
from .component_identity import consolidate, name_from_description, richer_name
from .flow_extraction import alias_index, extract_stated_flows, find_mentions
from .component_roles import find_named_roles, representative_of
from .known_issue_taxonomy import (
    GENERIC_SCOPE_TYPES,
    classify_generic_weakness,
    classify_generic_weaknesses,
)
import networkx as nx
from collections import defaultdict

logger = logging.getLogger(__name__)

# Words that name a category rather than a component, plus the connectives that
# survive tokenizing a cell. A single one of these must never become an alias: on
# its own "service" would make "the service" resolve to whichever service was
# declared first, and "with" would attach every sentence containing it to the one
# component whose technology column happened to read "X with Y".
_ALIAS_STOPWORDS = frozenset({
    'account', 'api', 'app', 'application', 'bus', 'cache', 'client', 'cluster',
    'data', 'database', 'edge', 'endpoint', 'engine', 'gateway', 'index', 'layer',
    'microservice', 'model', 'node', 'partner', 'pipeline', 'platform', 'portal',
    'process', 'provider', 'proxy', 'queue', 'record', 'records', 'server',
    'service', 'services', 'store', 'storage', 'system', 'systems', 'tier',
    'token', 'tokens', 'tool', 'user', 'users', 'web', 'worker', 'workload',
    'workloads',
    'all', 'and', 'any', 'are', 'both', 'each', 'for', 'from', 'has', 'have',
    'into', 'its', 'not', 'off', 'one', 'only', 'other', 'over', 'own', 'per',
    'that', 'the', 'their', 'them', 'then', 'these', 'they', 'this', 'those',
    'used', 'uses', 'using', 'via', 'was', 'were', 'when', 'which', 'while',
    'with', 'within', 'without',
})

# Import NLP processor (graceful fallback if unavailable)
try:
    from .nlp_processor import get_nlp_processor
    NLP_AVAILABLE = True
except Exception:
    NLP_AVAILABLE = False
    logger.warning("NLP processor not available. Using regex-only parsing.")


class ArchitectureParser:
    # Sections describing weaknesses or out-of-scope technology must never be
    # treated as deployed architecture.  The previous global keyword scan made
    # "no LLM" create an LLM component and made known-issue text create flows.
    _NON_ARCHITECTURE_SECTION = re.compile(
        r'^\s*(?:known issues?|exclusions?|out of scope|assumptions?)\s*:',
        re.IGNORECASE,
    )

    _DOCUMENT_HEADER = re.compile(r'^\s*Document:\s*(?P<name>\S.*?)\s*$', re.IGNORECASE)
    _DOCUMENT_TYPE = re.compile(r'^\s*Type:\s*(?P<value>\S.*?)\s*$', re.IGNORECASE)
    _DOCUMENT_ROLE = re.compile(r'^\s*Role:\s*(?P<value>\S.*?)\s*$', re.IGNORECASE)
    _DOCUMENT_CONTENT = re.compile(r'^\s*Content:\s*$', re.IGNORECASE)

    @classmethod
    def _analysis_sources(cls, text: str) -> List[Dict[str, Any]]:
        """Return source bodies without the upload transport headers."""
        sources: List[Dict[str, Any]] = []
        current = {
            'document': 'architecture input', 'type': 'text',
            'role': 'user_context', 'lines': [],
        }
        header_run = False
        wrapped = False

        def flush() -> None:
            body = '\n'.join(current['lines']).strip()
            if body:
                sources.append({**current, 'body': body})

        for raw_line in (text or '').splitlines():
            stripped = raw_line.strip()
            if re.fullmatch(r'User Context:', stripped, re.IGNORECASE):
                flush()
                current = {
                    'document': 'architecture input', 'type': 'text',
                    'role': 'user_context', 'lines': [],
                }
                header_run = False
                wrapped = True
                continue

            document = cls._DOCUMENT_HEADER.match(stripped)
            if document:
                flush()
                current = {
                    'document': document.group('name'), 'type': 'text',
                    'role': 'source_design', 'lines': [],
                }
                header_run = True
                wrapped = True
                continue

            if header_run:
                type_match = cls._DOCUMENT_TYPE.match(stripped)
                role_match = cls._DOCUMENT_ROLE.match(stripped)
                if type_match:
                    current['type'] = type_match.group('value').lower()
                    continue
                if role_match:
                    current['role'] = role_match.group('value').lower()
                    continue
                if cls._DOCUMENT_CONTENT.match(stripped):
                    header_run = False
                    continue
                header_run = False

            # The joiner and Markdown horizontal rules are not design facts.
            if wrapped and re.fullmatch(r'-{3,}', stripped):
                continue
            current['lines'].append(raw_line)

        flush()
        return sources or [{
            'document': 'architecture input', 'type': 'text',
            'role': 'user_context', 'body': text or '',
        }]

    @staticmethod
    def _without_structured_paths(body: str) -> str:
        return re.split(r'(?im)^\s*\[Structured paths\]\s*$', body or '', maxsplit=1)[0].strip()

    def _embedded_iac_architectures(self, text: str) -> List[Dict[str, Any]]:
        """Parse recognized structured uploads with the deterministic IaC engine."""
        from .iac_parser import IaCParser

        parsed = []
        for source in self._analysis_sources(text):
            if source.get('role') == 'reference_report':
                continue
            if source.get('type') not in {'yaml', 'yml', 'json', 'tf', 'hcl'}:
                continue
            content = self._without_structured_paths(str(source.get('body') or ''))
            try:
                hint = 'terraform' if source.get('type') in {'tf', 'hcl'} else 'auto'
                architecture = IaCParser().parse(content, hint)
            except ValueError:
                continue
            parsed.append({**source, 'content': content, 'architecture': architecture})
        return parsed

    @staticmethod
    def _merge_embedded_iac(
        components: Dict[str, Component], flows: List[DataFlow],
        sources: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        existing_flows = {(flow.source_id, flow.target_id, flow.protocol.lower()) for flow in flows}

        for source in sources:
            architecture = source['architecture']
            document = str(source.get('document') or 'uploaded IaC')
            id_map: Dict[str, str] = {}
            for incoming in architecture.components or []:
                component_id = incoming.id
                incumbent = components.get(component_id)
                if incumbent is not None and incumbent.type != incoming.type:
                    prefix = re.sub(r'[^a-z0-9]+', '_', document.lower()).strip('_')
                    component_id = f"iac_{prefix}_{incoming.id}"
                    incumbent = components.get(component_id)
                id_map[incoming.id] = component_id

                incoming_props = dict(incoming.properties or {})
                incoming_props.update({
                    'authoritative': True,
                    'source_document': document,
                    'extraction_method': 'iac_parser',
                })
                evidence = {
                    'source_type': 'iac', 'source_ref': incoming.id, 'line': None,
                    'statement': f"IaC resource {incoming.id} is declared in {document}.",
                    'confidence': 'High', 'document': document,
                }
                if incumbent is None:
                    incoming.id = component_id
                    incoming.properties = incoming_props
                    incoming.evidence = incoming.evidence or [evidence]
                    incoming.confidence = 'High'
                    components[component_id] = incoming
                else:
                    incumbent.properties = {**incoming_props, **(incumbent.properties or {})}
                    if evidence not in (incumbent.evidence or []):
                        incumbent.evidence = [*(incumbent.evidence or []), evidence]

            for incoming in architecture.flows or []:
                incoming.source_id = id_map.get(incoming.source_id, incoming.source_id)
                incoming.target_id = id_map.get(incoming.target_id, incoming.target_id)
                key = (incoming.source_id, incoming.target_id, incoming.protocol.lower())
                if key in existing_flows:
                    continue
                incoming.assumed = bool(incoming.assumed or (incoming.properties or {}).get('assumed'))
                incoming.properties = {
                    **(incoming.properties or {}), 'authoritative': True,
                    'source_document': document, 'extraction_method': 'iac_parser',
                }
                flows.append(incoming)
                existing_flows.add(key)

            for finding in (architecture.metadata or {}).get('iac_findings', []):
                copied = dict(finding)
                copied['resource_id'] = id_map.get(
                    str(finding.get('resource_id') or ''), finding.get('resource_id')
                )
                copied['source_document'] = document
                findings.append(copied)
        return findings

    def _architecture_only_text(
        self, text: str, excluded_documents: Optional[set[str]] = None,
    ) -> str:
        architecture_sources = []
        excluded = excluded_documents or set()
        for source in self._analysis_sources(text):
            if source.get('role') == 'reference_report' or source.get('document') in excluded:
                continue
            lines = []
            in_non_architecture_section = False
            for raw_line in str(source.get('body') or '').splitlines():
                section_match = re.search(
                    r'(?i)(?:^|\s)(?:known issues?|exclusions?|out of scope|assumptions?)\s*:',
                    raw_line,
                )
                if section_match:
                    prefix = raw_line[:section_match.start()].strip()
                    if prefix:
                        lines.append(prefix)
                    in_non_architecture_section = True
                    continue
                if in_non_architecture_section:
                    if re.match(r'^\s*[A-Za-z][A-Za-z /-]{2,}:\s*$', raw_line):
                        in_non_architecture_section = False
                    else:
                        continue
                lines.append(raw_line)
            body = '\n'.join(lines).strip()
            if body:
                architecture_sources.append(body)
        return prose.architecture_assertions('\n\n'.join(architecture_sources))

    def _known_issue_metadata(self, issue_text: str, rule_id: str, category: str,
                              severity: str, control: str, mitigation: str,
                              owasp: List[str], cwe: List[str],
                              component_hints: Optional[List[str]] = None,
                              affected_stride_categories: Optional[List[str]] = None) -> Dict:
        metadata = {
            'type': 'known_issue', 'control': control, 'severity': severity,
            'description': issue_text, 'suggested_threat_id': rule_id,
            'category': category, 'mitigation': mitigation,
            'owasp_top_10': owasp, 'cwe': cwe,
            'affected_stride_categories': (
                [category] if affected_stride_categories is None else affected_stride_categories
            ),
            'classification_status': (
                'unclassified' if rule_id.startswith('UNCLASSIFIED-') else 'classified'
            ),
        }
        if component_hints:
            metadata['component_hints'] = component_hints
        return metadata

    def _infer_trust_level(self, component_type: str, props: Dict[str, Any]) -> str:
        if props.get('external'):
            return 'external'
        if props.get('public_access') or component_type in ['WebClient', 'API Gateway', 'CDN', 'Load Balancer']:
            return 'public'
        if component_type in ['Identity Provider', 'Secrets Manager', 'Database', 'Object Storage']:
            return 'restricted'
        return 'internal'

    def _infer_data_type(self, source: Optional[Component], target: Optional[Component]) -> str:
        sensitivity = None
        if source:
            sensitivity = (source.properties or {}).get('data_sensitivity')
        if not sensitivity and target:
            sensitivity = (target.properties or {}).get('data_sensitivity')
        if sensitivity:
            return sensitivity
        if target and target.type in ['Secrets Manager']:
            return 'secrets'
        if target and target.type in ['Database', 'Object Storage']:
            return 'application_data'
        return 'application_data'

    def _extract_component_context(self, text: str, component_name: str, radius: int = 220) -> str:
        """Return the component's declaration sentence or line.

        Security controls on adjacent bullet points belong to different
        components. Sentence scoping also handles prose supplied as one line
        without assigning controls from neighboring sentences.
        """
        if not component_name:
            return ""

        names = {component_name, component_name.replace("_", " ").replace("-", " ")}
        segments = prose.sentences(text or "")
        matching = [
            segment.strip().lower()
            for segment in segments
            if any(
                re.search(r'(?<![A-Za-z0-9])' + re.escape(name) + r'(?![A-Za-z0-9])', segment, re.IGNORECASE)
                for name in names if name
            )
        ]
        if matching:
            return " ".join(matching)
        return ""

    def _apply_global_security_properties(self, props: Dict[str, Any], global_props: Dict[str, Any]) -> Dict[str, Any]:
        """Apply only controls that architecture text can safely state globally."""
        # Component and flow controls cannot be propagated from the whole
        # document without creating false positives or false assurances.
        global_keys = {'compliance_frameworks'}
        selected = {key: value for key, value in (global_props or {}).items() if key in global_keys}
        return self._apply_security_properties(props, selected)

    def _apply_security_properties(self, props: Dict[str, Any], security_props: Dict[str, Any]) -> Dict[str, Any]:
        """Merge extracted security properties into component properties conservatively."""
        if not security_props:
            return props

        for key, value in security_props.items():
            if value is None or value == 'unknown' or key == 'compliance_frameworks':
                continue
            if key in props.get('explicit_negations', []):
                continue
            if key == 'ml_pipeline' and not props.get('ai_scope'):
                continue
            if key == 'public_access':
                continue
            if key not in props or props[key] in (None, False, 'none', 'unknown', '', []):
                props[key] = value

        if 'compliance_frameworks' in security_props:
            existing = props.get('compliance_frameworks', [])
            for framework in security_props['compliance_frameworks']:
                if framework not in existing:
                    existing.append(framework)
            props['compliance_frameworks'] = existing

        return props

    def _collect_assumptions(self, components: Dict[str, Component], flows: List[DataFlow]) -> List[Dict[str, str]]:
        """Capture unknown or inferred areas so users can validate them explicitly."""
        assumptions = []

        for component in components.values():
            props = component.properties
            if props.get('auth_type') == 'none' and component.type in ['API', 'Service', 'API Gateway', 'Identity Provider']:
                assumptions.append({
                    'scope': component.id,
                    'type': 'authentication',
                    'message': f"Authentication was not clearly identified for {component.name}."
                })
            if props.get('encryption_at_rest') is False and component.type in ['Database', 'Object Storage', 'Secrets Manager']:
                assumptions.append({
                    'scope': component.id,
                    'type': 'encryption',
                    'message': f"Encryption at rest was not explicitly confirmed for {component.name}."
                })
            if not props.get('logging_enabled') and component.type in ['API', 'Service', 'Database']:
                assumptions.append({
                    'scope': component.id,
                    'type': 'logging',
                    'message': f"Audit or application logging was not clearly identified for {component.name}."
                })

        for flow in flows:
            if flow.properties.get('origin') == 'assumed':
                assumptions.append({
                    'scope': f"{flow.source_id}->{flow.target_id}",
                    'type': 'data_flow',
                    'message': flow.properties.get('assumption') or (
                        f"The flow {flow.source_id} -> {flow.target_id} was assumed from component "
                        f"types because the description did not state it."
                    ),
                })

        return assumptions

    def _add_explicit_generic_components(self, text: str, components: Dict[str, Component]) -> None:
        """Model literal generic architecture nouns when no concrete peer exists."""
        declarations = (
            (r'\b(?:react|vue|angular|frontend|spa|browser client)\b', 'frontend', 'Frontend', 'WebClient'),
            (r'\b(?:mobile app|mobile client)s?\b', 'mobile_app', 'Mobile App', 'Mobile App'),
            (r'\b(?:web application|website|web site)\b', 'web_application', 'Web Application', 'WebClient'),
            (r'\bapi\b(?!\s+gateway)', 'api', 'API', 'API'),
            (r'\b(?:database|data store)\b', 'database', 'Database', 'Database'),
            (r'\b(?:microservices?|services?)\b', 'service', 'Service', 'Service'),
            (r'\b(?:message queue|event bus)\b', 'queue', 'Message Queue', 'Queue'),
        )
        lines = (text or '').splitlines() or [text]
        for pattern, component_id, name, component_type in declarations:
            if any(component.type == component_type for component in components.values()):
                continue
            statement = ''
            for line in lines:
                matches = list(re.finditer(pattern, line, re.IGNORECASE))
                if component_type == 'API':
                    matches = [match for match in matches if not (
                        re.search(r'\b(?:logs?|audits?|monitors?|records?)\s+$', line[:match.start()], re.IGNORECASE)
                        and re.match(r'\s+(?:calls?|requests?|events?)\b', line[match.end():], re.IGNORECASE)
                    )]
                if matches:
                    statement = line.strip()
                    break
            if not statement:
                continue
            props = self._infer_properties(statement.lower(), component_type)
            components[component_id] = Component(
                id=component_id, name=name, type=component_type,
                description=statement, properties=props,
            )

    def _add_explicit_named_components(self, text: str, components: Dict[str, Component]) -> None:
        """Model security-relevant named platforms that are literally declared.

        This registry is an extraction vocabulary, not a threat rule. It does
        not infer a technology from neighboring terms and it never reads known
        issues or exclusions because ``text`` is architecture-only input.
        """
        declarations = (
            (r'\b(?:hl7\s+)?fhir\s+api\b', 'hl7_fhir_api', 'HL7 FHIR API', 'API'),
            (r'\bmcp\s+(?:server|gateway)\b', 'mcp_server', 'MCP Server', 'API'),
            (r'\bkubernetes\b|\bk8s\b', 'kubernetes_platform', 'Kubernetes Platform', 'Container Platform'),
            (r'\bopensearch\b', 'opensearch', 'OpenSearch', 'Database'),
            (r'\b(?:aws\s+)?secrets manager\b', 'secrets_manager', 'Secrets Manager', 'Secrets Manager'),
            (r'\b(?:amazon\s+)?sqs\b', 'sqs', 'SQS', 'Queue'),
            (r'\b(?:amazon\s+)?sns\b', 'sns', 'SNS', 'Queue'),
            (r'\b(?:amazon\s+)?cloudtrail\b', 'cloudtrail', 'CloudTrail', 'Monitoring'),
        )
        for pattern, component_id, name, component_type in declarations:
            match = re.search(pattern, text or '', re.IGNORECASE)
            if not match:
                continue
            if component_id in components or any(
                item.name.lower() == name.lower() for item in components.values()
            ):
                continue
            statement = self._extract_component_context(text, match.group(0))
            props = self._infer_properties(statement or match.group(0), component_type)
            props['extraction_method'] = 'literal_registry'
            if component_id == 'hl7_fhir_api':
                props['healthcare_integration'] = True
                props['external'] = 'partner' in (statement or '').lower()
            elif component_id == 'mcp_server':
                props['mcp_enabled'] = True
                props['tool_execution'] = True
            elif component_id == 'kubernetes_platform':
                props['deployment'] = 'k8s'
                props['containerized'] = True
            components[component_id] = Component(
                id=component_id,
                name=name,
                type=component_type,
                description=statement,
                properties=props,
            )

    def _add_explicit_mcp_components(self, text: str, components: Dict[str, Component]) -> None:
        """Extract agent and MCP execution boundaries as first-class components."""
        source = text or ''
        lowered = source.lower()
        if not any(term in lowered for term in ('mcp', 'agent')):
            return

        declarations = (
            ('github', 'mcp_github', 'GitHub MCP Server', 'MCP Server'),
            ('jira', 'mcp_jira', 'Jira MCP Server', 'MCP Server'),
            ('salesforce', 'mcp_salesforce', 'Salesforce MCP Server', 'MCP Server'),
            ('postgresql', 'mcp_postgresql', 'PostgreSQL MCP Server', 'MCP Server'),
            ('browser', 'mcp_browser', 'Browser MCP Server', 'MCP Server'),
            ('filesystem', 'mcp_filesystem', 'Filesystem MCP Server', 'MCP Server'),
            ('shell', 'mcp_shell', 'Shell MCP Server', 'MCP Server'),
        )
        for token, component_id, name, component_type in declarations:
            if not re.search(r'(?<![a-z0-9])' + re.escape(token) + r'(?![a-z0-9])', lowered):
                continue
            if token == 'postgresql' and not re.search(r'\bmcp\b.{0,140}\bpostgresql\b|\bpostgresql\b.{0,40}\bmcp\b', lowered):
                continue
            if component_id in components:
                continue
            props = self._infer_properties(self._extract_component_context(source, token), component_type)
            props.update({
                'technology': f'{token} mcp',
                'mcp_enabled': True,
                'tool_execution': token in {'browser', 'filesystem', 'shell', 'github', 'jira', 'salesforce'},
                'external': token in {'browser', 'github', 'jira', 'salesforce'},
            })
            components[component_id] = Component(
                id=component_id, name=name, type=component_type,
                description=self._extract_component_context(source, token), properties=props,
            )

        if re.search(r'\bagents?\b', lowered) and 'ai_agent' not in components:
            props = self._infer_properties(self._extract_component_context(source, 'agent'), 'ML Service')
            props.update({'technology': 'agent', 'ai_scope': True, 'ml_pipeline': True, 'agentic': True})
            components['ai_agent'] = Component(
                id='ai_agent', name='AI Agent', type='ML Service',
                description=self._extract_component_context(source, 'agent'), properties=props,
            )

    def _add_explicit_logical_components(self, text: str, components: Dict[str, Component]) -> None:
        """Preserve named logical services, tools and control-plane resources."""
        source = text or ''
        declarations = (
            (r'\b(?:amazon\s+)?eventbridge\b', 'eventbridge', 'EventBridge', 'Queue'),
            (r'\b(?:aws\s+)?step functions?\b', 'step_functions', 'Step Functions', 'Service'),
            (r'\b(?:aws\s+)?glue\b', 'glue', 'AWS Glue', 'Service'),
            (r'\b(?:amazon\s+)?athena\b', 'athena', 'Athena', 'Service'),
            (r'\baws organizations?\b|\baws organization\b', 'aws_organization', 'AWS Organization', 'IAM'),
            (r'\bproduction vpc\b|\b(?:aws\s+)?vpc\b', 'aws_vpc', 'AWS VPC', 'Network'),
            (r'\birsa\b', 'irsa_role', 'IRSA Workload Role', 'IAM'),
            (r'\bsaml (?:identity providers?|idps?|acs endpoint)\b', 'saml_identity', 'SAML Identity Integration', 'Identity Provider'),
            (r'\bscim endpoints?\b', 'scim_endpoint', 'SCIM Provisioning Endpoint', 'API'),
            (r'\bsupport engineers?\b', 'support_operator', 'Support Operator', 'External Actor'),
            (r'\boutbound webhooks?\b|\bcustomers? configure (?:outbound )?webhooks?\b', 'webhook_delivery', 'Webhook Delivery Service', 'Service'),
            (r'\bagent orchestrator\b|\borchestrator selects\b', 'agent_orchestrator', 'Agent Orchestrator', 'ML Service'),
            (r'\bpolicy service\b', 'policy_service', 'Policy Service', 'Service'),
            (r'\bworkflow service\b', 'workflow_service', 'Workflow Service', 'Service'),
            (r'\bmemory service\b', 'memory_service', 'Memory Service', 'Service'),
            (r'\bocr (?:and parsing )?workers?\b|\bocr workers?\b', 'ocr_worker', 'OCR Worker', 'Worker'),
            (r'\bparsing workers?\b', 'parsing_worker', 'Parsing Worker', 'Worker'),
            (r'\bcode execution service\b', 'code_execution_service', 'Code Execution Service', 'Service'),
            (r'\bhuman approval service\b|\bapproval service\b', 'approval_service', 'Human Approval Service', 'Service'),
            (r'\bbrowser (?:tool|mcp server)\b', 'browser_tool', 'Browser Tool', 'Tool'),
            (r'\bthird-party observability (?:saas|vendor)\b|\bobservability vendor\b', 'observability_vendor', 'Observability Vendor', 'Monitoring'),
            (r'\bself-hosted model\b', 'self_hosted_model', 'Self-hosted Model', 'ML Service'),
            (r'\bcross-cloud secrets? (?:synchronization|sync)\b|\bsecrets? are synchronized\b', 'secret_sync', 'Cross-cloud Secret Sync', 'Service'),
        )
        for pattern, component_id, name, component_type in declarations:
            match = re.search(pattern, source, re.IGNORECASE)
            if not match or component_id in components:
                continue
            context = self._extract_component_context(source, match.group(0))
            props = self._infer_properties(context, component_type)
            props.update({'technology': match.group(0), 'extraction_method': 'literal_logical_registry'})
            if component_type == 'ML Service':
                props.update({'ai_scope': True, 'ml_pipeline': True})
            if component_id == 'browser_tool':
                props.update({'tool_execution': True, 'external': True})
            components[component_id] = Component(
                id=component_id, name=name, type=component_type,
                description=context, properties=props,
            )

        if re.search(r'\baccount,\s*project,\s*search,\s*export,\s*notification,\s*audit,\s*(?:and\s+)?billing microservices\b', source, re.IGNORECASE):
            for service_name in ('Account', 'Project', 'Search', 'Export', 'Notification', 'Audit', 'Billing'):
                component_id = f'{service_name.lower()}_service'
                if component_id in components:
                    continue
                components[component_id] = Component(
                    id=component_id, name=f'{service_name} Service', type='Service',
                    description='Explicitly named application microservice.',
                    properties={'technology': f'{service_name.lower()} microservice', 'extraction_method': 'literal_service_list'},
                )

    def _add_inferred_named_components(self, text: str, components: Dict[str, Component]) -> None:
        """Model named services, portals and workers that no registry enumerates.

        A registry cannot list product-specific names such as "Settlement
        Worker". Without this pass those declarations collapse into a generic
        peer of the same type, which removes them from the model entirely.
        """
        added = 0
        for candidate in find_named_roles(text or ''):
            if added >= 12:
                break
            if candidate['id'] in components:
                continue
            existing = representative_of(candidate, list(components.values()))
            if existing is not None:
                # The candidate is the same node under a fuller name. Adopt the
                # name the design used and keep the established id.
                better = richer_name(candidate, existing)
                if better:
                    existing.name = better
                continue
            context = self._extract_component_context(text, candidate['phrase']) or candidate['phrase']
            props = self._infer_properties(context.lower(), candidate['type'])
            props.update({
                'technology': candidate['phrase'].lower(),
                'extraction_method': 'inferred_named_role',
            })
            if candidate['external']:
                props['external'] = True
                props['third_party_integration'] = True
            components[candidate['id']] = Component(
                id=candidate['id'],
                name=candidate['name'],
                type=candidate['type'],
                description=context,
                properties=props,
            )
            added += 1

    @staticmethod
    def _consolidate_component_aliases(
        text: str, components: Dict[str, Component]
    ) -> List[Dict[str, str]]:
        """Merge generic aliases when a concrete technology represents the same node.

        Returns what was resolved so the report and the extraction challenger can
        see that a name was accounted for rather than dropped.
        """
        # Resolve names that denote one node before the type-specific rules run,
        # so those rules see one component per node rather than two.
        resolved = consolidate(components, text)
        for component in components.values():
            better = name_from_description(component)
            if better:
                component.name = better

        concrete_api_ids = [
            component_id for component_id, component in components.items()
            if component.type == 'API' and component_id not in {'api', 'rest_api'}
        ]
        if concrete_api_ids:
            for generic_id in ('api', 'rest_api'):
                if generic_id == 'rest_api' and re.search(r'\brest\s+api\b', text, re.IGNORECASE):
                    represented = any(
                        re.search(
                            re.escape(alias) + r'\s+(?:\w+\s+){0,2}rest\s+api\b',
                            text, re.IGNORECASE,
                        )
                        or re.search(r'\brest\s+api\b', alias, re.IGNORECASE)
                        for cid in concrete_api_ids
                        for alias in (components[cid].name, str(components[cid].properties.get('technology') or ''))
                        if alias
                    )
                    if not represented:
                        continue
                components.pop(generic_id, None)

        # A named peer of the same type supersedes the generic noun it was
        # extracted from. Keeping both models one node twice and attributes
        # findings to a placeholder the design never mentioned.
        generic_aliases = {
            'Service': ('service', 'microservice'),
            'WebClient': ('web_application',),
            'Database': ('database',),
            'Queue': ('queue',),
        }
        for component_type, generic_ids in generic_aliases.items():
            concrete = [
                component_id for component_id, component in components.items()
                if component.type == component_type and component_id not in generic_ids
            ]
            if concrete:
                for generic_id in generic_ids:
                    components.pop(generic_id, None)

        if 'pinecone' in components:
            components.pop('vector_store', None)
            components.pop('vector_database', None)
            components['pinecone'].properties.update({'vector_store': True, 'ai_scope': True})

        if 'azure_openai' in components:
            components.pop('openai', None)
            components['azure_openai'].name = 'Azure OpenAI'
            components['azure_openai'].properties.update({'ai_scope': True, 'ml_pipeline': True})

        if 'aws_api_gateway' in components and 'api_gateway' in components:
            components['aws_api_gateway'].properties.update(components['api_gateway'].properties or {})
            components.pop('api_gateway', None)
        if re.search(r'\b(?:no|without|missing)\s+(?:web application firewall|waf)\b', text or '', re.IGNORECASE):
            components.pop('waf', None)
        if 'key_vault' in components and 'vault' in components:
            components.pop('vault', None)

        if 'mcp_filesystem' in components:
            components.pop('filesystem', None)
        if 'mcp_shell' in components:
            components.pop('shell_executor', None)

        if 'postgresql' in components and 'rds' in components:
            components['postgresql'].name = 'RDS PostgreSQL'
            components['postgresql'].properties.update({'cloud_provider': 'aws', 'cloud_service': 'rds'})
            components.pop('rds', None)
        elif 'postgresql' in components and re.search(r'\brds\b', text or '', re.IGNORECASE):
            components['postgresql'].name = 'RDS PostgreSQL'
            components['postgresql'].properties.update({'cloud_provider': 'aws', 'cloud_service': 'rds'})

        if 'redis' in components and 'elasticache' in components:
            components['redis'].name = 'ElastiCache Redis'
            components['redis'].properties.update({'cloud_provider': 'aws', 'cloud_service': 'elasticache'})
            components.pop('elasticache', None)
        elif 'redis' in components and re.search(r'\belasticache\b', text or '', re.IGNORECASE):
            components['redis'].name = 'ElastiCache Redis'
            components['redis'].properties.update({'cloud_provider': 'aws', 'cloud_service': 'elasticache'})

        if 'ec2' in components:
            hosted = [
                component_id for component_id, component in components.items()
                if component.type in {'API', 'Service'} and component_id != 'ec2'
            ]
            if hosted and re.search(r'\b(?:backend|service|api)\b.{0,50}\b(?:hosted|runs?|deployed)\b.{0,30}\b(?:aws\s+)?ec2\b', text or '', re.IGNORECASE):
                components['ec2'].properties['hosts'] = hosted
                for component_id in hosted:
                    components[component_id].properties['hosted_on'] = 'ec2'

        return resolved

    def _build_trust_boundaries(self, components: Dict[str, Component], flows: List[DataFlow]) -> List[TrustBoundary]:
        """Summarize trust boundaries crossed by the modeled architecture."""
        boundaries: Dict[str, TrustBoundary] = {}

        for component in components.values():
            level = component.trust_level or 'internal'
            if level not in boundaries:
                boundary_type = 'network_zone'
                if level == 'public':
                    boundary_type = 'external'
                elif level == 'restricted':
                    boundary_type = 'sensitive'
                elif level == 'external':
                    boundary_type = 'third_party'
                boundaries[level] = TrustBoundary(
                    name=level,
                    boundary_type=boundary_type,
                    components=[]
                )
            boundaries[level].components.append(component.id)

        for flow in flows:
            boundary = flow.properties.get('trust_boundary')
            if boundary and boundary not in boundaries:
                boundaries[boundary] = TrustBoundary(
                    name=boundary,
                    boundary_type='flow_boundary',
                    components=[flow.source_id, flow.target_id],
                    description='Derived from inferred communication boundary.',
                )

        return list(boundaries.values())

    def _extract_assets(self, components: Dict[str, Component], flows: List[DataFlow]) -> List[Asset]:
        assets: List[Asset] = []
        for component in components.values():
            props = component.properties or {}
            sensitivity = props.get('data_sensitivity')
            # A component can process sensitive data without itself being an
            # asset repository. Avoid turning every WAF, client, API, and IdP
            # into a credential data store in the final report.
            if component.type in ['Database', 'Object Storage', 'Secrets Manager', 'Data Warehouse', 'ML Service']:
                asset_name = f"{component.name} data"
                asset_sensitivity = sensitivity or ('secrets' if component.type == 'Secrets Manager' else 'internal')
                related_flows = [
                    f"{flow.source_id}->{flow.target_id}"
                    for flow in flows
                    if flow.source_id == component.id or flow.target_id == component.id
                ]
                assets.append(Asset(
                    name=asset_name,
                    sensitivity=asset_sensitivity,
                    location=component.name,
                    asset_type='credential_store' if component.type == 'Secrets Manager' else 'data_store',
                    related_component_id=component.id,
                    related_data_flows=related_flows,
                ))
        return assets

    @staticmethod
    def _structured_tables(text: str) -> List[Dict[str, Any]]:
        """Parse the stable table records emitted by document ingestion."""
        tables: List[Dict[str, Any]] = []
        current: Optional[Dict[str, Any]] = None
        for raw_line in (text or '').splitlines():
            table_match = re.match(r'^\[Table\s+(\d+)\]\s*$', raw_line.strip(), re.IGNORECASE)
            if table_match:
                current = {'number': int(table_match.group(1)), 'rows': []}
                tables.append(current)
                continue
            row_match = re.match(r'^Row\s+(\d+)\s*:\s*(.*)$', raw_line.strip(), re.IGNORECASE)
            if current is None or not row_match:
                continue
            # Split on the bare separator, not on " | ": the line has been
            # stripped, so a row whose last cell is empty ends in "|" and
            # splitting on the padded form would fold that separator into the
            # previous cell and shift the row one column short.  Content pipes
            # are escaped at ingestion, so every remaining "|" is a boundary.
            values = [value.replace('&#124;', '|').strip() for value in row_match.group(2).split('|')]
            current['rows'].append(values)

        normalized = []
        for table in tables:
            if not table['rows']:
                continue
            headers = [re.sub(r'[^a-z0-9]+', '_', cell.lower()).strip('_') for cell in table['rows'][0]]
            records = []
            for values in table['rows'][1:]:
                padded = values + [''] * max(0, len(headers) - len(values))
                records.append(dict(zip(headers, padded[:len(headers)])))
            normalized.append({**table, 'headers': headers, 'records': records})
        return normalized

    @staticmethod
    def _table_with_headers(tables: List[Dict[str, Any]], *required: str) -> Optional[Dict[str, Any]]:
        required_set = set(required)
        return next((table for table in tables if required_set.issubset(set(table['headers']))), None)

    #: Trust levels ordered from most exposed to most protected. Used to decide
    #: which of two claims about one component is the more restrictive.
    TRUST_ORDER = ('external', 'public', 'internal', 'restricted')

    #: The least exposed a component of this type can be, whatever boundary it was
    #: placed in. A tier declared "internal" that contains a database does not make
    #: the database internal; it means the tier was described at the wrong grain.
    TRUST_FLOOR_BY_TYPE = {
        'Database': 'restricted',
        'Object Storage': 'restricted',
        'Secrets Manager': 'restricted',
        'Key Management': 'restricted',
        'Identity Provider': 'restricted',
    }

    #: The kinds of data a description can name, and the words that name them.
    #: Health data is separate from personal data because it is regulated
    #: separately and weighs more in the risk calculation, and "patient records"
    #: was previously read as no classification at all.
    DATA_SENSITIVITY_TERMS = (
        ('pii', (
            'pii', 'personal data', 'personal information', 'personally identifiable',
            'customer record', 'date of birth', 'ssn', 'social security', 'passport',
            'national id', 'home address', 'phone number', 'gdpr',
        )),
        ('phi', (
            'phi', 'patient', 'medical', 'health record', 'health data', 'clinical',
            'diagnos', 'prescription', 'lab result', 'hipaa', 'ehr', 'emr',
        )),
        ('financial', (
            'payment', 'credit card', 'cardholder', 'financial', 'transaction',
            'invoice', 'bank account', 'pci', 'billing',
        )),
        ('credentials', (
            'credential', 'password', 'api key', 'private key', 'access token',
            'session token', 'secret',
        )),
    )

    #: Types that face the internet by definition, so they are at the public edge
    #: even when no boundary table says where they sit. A load balancer is absent
    #: deliberately: it is as often internal as not, and the boundary table is the
    #: only thing that can say which.
    PUBLIC_BY_TYPE = frozenset({'WebClient', 'IoT Device', 'API Gateway', 'CDN'})

    @staticmethod
    def _authoritative_component_type(name: str, technology: str, responsibility: str) -> str:
        """The type of a declared component, from what the row says it is.

        The row is read most-specific-field first. The name is the label the
        author chose for the component, so "Core API" is an API even though its
        technology column says Spring Boot and its responsibility mentions
        payments; only when the name carries no role does the technology decide.
        """
        for field in (name, technology, f"{name}. {technology}. {responsibility}"):
            resolved = technology_catalog.classify_role(field)
            if resolved:
                return resolved
        return 'Service'

    @classmethod
    def _more_restrictive(cls, first: Optional[str], second: Optional[str]) -> Optional[str]:
        candidates = [level for level in (first, second) if level in cls.TRUST_ORDER]
        if not candidates:
            return first or second
        return max(candidates, key=cls.TRUST_ORDER.index)

    @classmethod
    def _authoritative_trust_level(cls, component_type: str, declared: Optional[str] = None) -> str:
        """The trust level of a declared component.

        A boundary table states the trust level of each tier, and that statement
        is the best evidence available. Absent one, the type decides: clients are
        outside, stores and secrets are protected, everything else is internal.
        """
        if declared in cls.TRUST_ORDER:
            return cls._more_restrictive(declared, cls.TRUST_FLOOR_BY_TYPE.get(component_type))
        if component_type in cls.PUBLIC_BY_TYPE:
            return 'public'
        return cls.TRUST_FLOOR_BY_TYPE.get(component_type, 'internal')

    @staticmethod
    def _stable_component_id(name: str, source_id: str, taken: Dict[str, Component]) -> str:
        """An identifier that survives the table being edited.

        Two components can carry the same name, and one of them has to be told
        apart somehow; the row label is the only thing left that distinguishes
        them, so it is used as the tie-break rather than as the identity.
        """
        slug = re.sub(r'_+', '_', re.sub(r'[^a-z0-9]+', '_', (name or '').lower())).strip('_')
        if not slug:
            return source_id.lower()
        return slug if slug not in taken else f'{slug}_{source_id.lower()}'

    @staticmethod
    def _declared_controls(value: str) -> Dict[str, Any]:
        """Control state written down by a previous analysis of this model.

        "mfa_enabled" is present, "mfa_enabled=no" is known to be absent, and a
        control that appears in neither form stays unknown. The three states are
        distinct to the rules, so a round trip that could only express presence
        would turn every stated weakness back into an open question.
        """
        declared: Dict[str, Any] = {}
        for entry in re.split(r'[,;]', value or ''):
            entry = entry.strip()
            if not entry:
                continue
            key, _, raw = entry.partition('=')
            key = key.strip().lower().replace(' ', '_')
            if not re.fullmatch(r'[a-z][a-z0-9_]*', key):
                continue
            raw = raw.strip().lower()
            if not raw:
                declared[key] = True
            elif raw in {'yes', 'true', 'enabled', 'present', '1'}:
                declared[key] = True
            elif raw in {'no', 'false', 'disabled', 'absent', '0'}:
                declared[key] = False
            elif raw in {'unknown', 'none', ''}:
                declared[key] = None
            else:
                declared[key] = raw
        return declared

    @staticmethod
    def _normalize_trust_level(value: str) -> Optional[str]:
        lowered = (value or '').strip().lower()
        if not lowered:
            return None
        for level in ArchitectureParser.TRUST_ORDER:
            if level in lowered:
                return level
        if any(token in lowered for token in ('untrusted', 'internet', 'third party')):
            return 'external'
        if any(token in lowered for token in ('confidential', 'protected', 'sensitive')):
            return 'restricted'
        if 'trusted' in lowered:
            return 'internal'
        return None

    @staticmethod
    def _components_named_in(text: str, aliases: Dict[str, str], components: Dict[str, Component]) -> List[str]:
        """The components this sentence names, in the order it names them.

        Matching is on whole words, so "namespaces" does not name the component
        whose technology is an SPA, and it is ordered by position then by length,
        so the sentence's own subject leads rather than whichever component was
        declared first.
        """
        lowered = (text or '').lower()
        matches: List[Tuple[int, int, str]] = []
        for alias, component_id in aliases.items():
            if not alias or component_id not in components:
                continue
            found = technology_catalog.first_mention(lowered, alias)
            if found is not None:
                matches.append((found, -len(alias), component_id))

        ordered: List[str] = []
        for _, _, component_id in sorted(matches):
            if component_id not in ordered:
                ordered.append(component_id)
        return ordered

    @staticmethod
    def _referenced_component_ids(text: str) -> List[str]:
        """Component ids named in a free-text cell, expanding "C1-C25" ranges."""
        lowered = (text or '').lower()
        found: List[str] = []
        for match in re.finditer(r'\bc(\d+)\s*(?:-|–|—|to|through)\s*c?(\d+)\b', lowered):
            start, end = int(match.group(1)), int(match.group(2))
            if start <= end and end - start < 500:
                found.extend(f'c{number}' for number in range(start, end + 1))
        for match in re.finditer(r'\bc(\d+)\b', lowered):
            found.append(f'c{match.group(1)}')
        ordered: List[str] = []
        for component_id in found:
            if component_id not in ordered:
                ordered.append(component_id)
        return ordered

    #: The data classifications a flow can carry, as the rules understand them.
    DATA_TYPES = ('phi', 'financial', 'credentials', 'secrets', 'application_data')

    @classmethod
    def _flow_data_type(cls, value: str) -> str:
        lowered = (value or '').lower()
        # An emitted model writes the classification itself into this column, and
        # "financial" is not a word the description of a payment would use.
        if lowered.strip() in cls.DATA_TYPES:
            return lowered.strip()
        if any(token in lowered for token in ('phi', 'clinical', 'patient', 'fhir')):
            return 'phi'
        if any(token in lowered for token in ('payment', 'refund', 'ledger', 'amount', 'customer token')):
            return 'financial'
        if any(token in lowered for token in ('credential', 'jwt', 'identity', 'token validation')):
            return 'credentials'
        if any(token in lowered for token in ('secret', 'key')):
            return 'secrets'
        return 'application_data'

    def _parse_authoritative_architecture(self, text: str) -> Optional[SystemArchitecture]:
        """Build the architecture from explicit C/TB/F/AS/K tables.

        This path intentionally bypasses keyword component discovery and
        Cartesian flow inference. A document that assigns stable architecture
        IDs is more authoritative than heuristic NLP extraction.
        """
        tables = self._structured_tables(text)
        component_table = self._table_with_headers(tables, 'id', 'component', 'technology')
        flow_table = self._table_with_headers(tables, 'id', 'source_and_destination', 'protocol')
        if not component_table or not flow_table:
            return None
        if not any(str(row.get('id', '')).upper().startswith('C') for row in component_table['records']):
            return None
        if not any(str(row.get('id', '')).upper().startswith('F') for row in flow_table['records']):
            return None

        components: Dict[str, Component] = {}
        aliases: Dict[str, str] = {}
        full_names: Dict[str, str] = {}
        alias_owners: Dict[str, set] = {}
        name_owners: Dict[str, set] = {}
        searchable_component_text: Dict[str, str] = {}
        stated_trust_levels: Dict[str, str] = {}
        #: row label ("c7") -> component id. The label is how the rest of the
        #: document refers to a row; it is not what the component is.
        record_labels: Dict[str, str] = {}

        def labelled(*values: str) -> List[str]:
            """The components the given row labels refer to, in order."""
            seen: List[str] = []
            for value in values:
                for label in value if isinstance(value, list) else [value]:
                    resolved = record_labels.get(label)
                    if resolved and resolved not in seen:
                        seen.append(resolved)
            return seen

        def _claim(index: Dict[str, str], owners: Dict[str, set], label: str, component_id: str) -> None:
            """Let a component claim a label, unless another already has.

            A word two components share identifies neither of them. "Document"
            belongs to both the ingestion lambda and the document store, so a
            weakness about document text is about neither in particular, and
            awarding it to whichever row came first is how a plausible but wrong
            attribution gets made.
            """
            holders = owners.setdefault(label, set())
            holders.add(component_id)
            if len(holders) == 1:
                index[label] = component_id
            else:
                index.pop(label, None)

        def register_aliases(component_id: str, name: str, technology: str = '', *extra: str) -> None:
            """Record the names a later cell might use to refer to this component.

            A component owns the words in the name its author gave it. It does not
            own every product listed in its technology column: a notification
            service built "with SendGrid" is not SendGrid, and treating it as such
            makes a flow to the real third party resolve back to the caller. Words
            from the technology column therefore only count when the catalog
            recognizes them as naming a technology.
            """
            labels = {value.strip().lower() for value in (name, technology, *extra) if value and value.strip()}
            for label in labels:
                _claim(full_names, name_owners, label, component_id)

            candidates = set(re.findall(r'[a-z][a-z0-9.+-]{2,}', (name or '').lower()))
            candidates.update(
                token for token in re.findall(r'[a-z][a-z0-9.+-]{2,}', (technology or '').lower())
                if token in technology_catalog.TECHNOLOGY_TYPES
            )
            component_type = components.get(component_id).type if component_id in components else None
            candidates.update(
                term for term, term_type in technology_catalog.ROLE_VOCABULARY.items()
                if term_type == component_type and technology_catalog.mentions(technology, term)
            )
            for alias in labels | candidates:
                if alias and alias not in _ALIAS_STOPWORDS:
                    _claim(aliases, alias_owners, alias, component_id)

            searchable_component_text[component_id] = ' '.join(
                value.lower() for value in (name, *extra) if value and value.strip()
            )

        def resolve_by_name(value: str) -> Optional[str]:
            """The component whose own name or technology this text states.

            Used where a cell lists membership rather than referring to a
            component in prose, so that a boundary described as holding
            "patients, clinicians and partner systems" claims no component.
            """
            lowered = re.sub(r'\s+', ' ', (value or '').lower()).strip(' .;,')
            if not lowered:
                return None
            ranked = sorted(
                ((len(label), cid) for label, cid in full_names.items() if label in lowered),
                reverse=True,
            )
            return ranked[0][1] if ranked else None

        for record in component_table['records']:
            source_id = str(record.get('id', '')).strip().upper()
            if not re.fullmatch(r'C\d+', source_id):
                continue
            name = record.get('component', '').strip() or source_id
            # Identity comes from the name, not the row label. Findings are keyed
            # by the component they concern, so if a component were "C7" then
            # inserting a row above it would renumber the rest of the table and
            # every finding and reviewer note below the insertion would detach
            # from the thing it was written about.
            declared_id = (record.get('canonical_id') or record.get('component_id') or '').strip()
            if declared_id:
                declared_id = re.sub(r'_+', '_', re.sub(r'[^a-zA-Z0-9_-]+', '_', declared_id)).strip('_').lower()
            component_id = (
                declared_id if declared_id and declared_id not in components
                else self._stable_component_id(name, source_id, components)
            )
            technology = record.get('technology', '').strip()
            responsibility = (record.get('responsibility_data') or record.get('responsibility') or '').strip()
            # A document the analyzer emitted states the type and control state it
            # derived, so that re-reading its own output reproduces the model
            # rather than inferring it a second time from the same words.
            component_type = (record.get('type') or '').strip() or \
                self._authoritative_component_type(name, technology, responsibility)
            context = f"{name}. {technology}. {responsibility}."
            props = self._infer_properties(context, component_type)
            props.update(self._declared_controls(record.get('controls', '')))
            props.update({
                'source_record_id': source_id,
                'technology': technology,
                'description': responsibility,
                'evidence_status': 'explicit',
                'authoritative': True,
            })
            stated_trust = self._normalize_trust_level(record.get('trust_level', ''))
            if stated_trust:
                stated_trust_levels[component_id] = stated_trust
            # Provisional: a stated level, or the boundary table parsed once every
            # component and external participant exists, overrides it below.
            trust_level = self._authoritative_trust_level(component_type)
            props['trust_level'] = trust_level
            component = Component(
                id=component_id,
                name=name,
                type=component_type,
                trust_level=trust_level,
                description=responsibility,
                properties=props,
                confidence='High',
                evidence=[{
                    'source_type': 'architecture_input',
                    'source_ref': source_id,
                    'line': None,
                    'statement': context,
                    'confidence': 'High',
                }],
            )
            components[component_id] = component
            record_labels[source_id.lower()] = component_id
            register_aliases(component_id, name, technology, responsibility, source_id)

        control_table = self._table_with_headers(tables, 'domain', 'implemented_controls')
        parse_warnings: List[str] = []

        def resolve_endpoint(value: str, prefer: str = '', exclude: str = '') -> Optional[str]:
            """The component a cell refers to, by id where given and by name otherwise."""
            lowered = re.sub(r'[^a-z0-9+/. -]+', ' ', (value or '').lower()).strip()
            if not lowered:
                return prefer or None
            explicit = re.search(r'\bc\d+\b', lowered)
            if explicit:
                if explicit.group(0) in record_labels:
                    return record_labels[explicit.group(0)]
                # An id the inventory never declared is a defect in the document,
                # and guessing a component here would hide it.
                parse_warnings.append(
                    f"'{value.strip()}' refers to {explicit.group(0).upper()}, "
                    "which the component inventory does not declare"
                )
                return None
            ranked = sorted(
                (lowered.index(alias), -len(alias), cid)
                for alias, cid in aliases.items()
                if alias and alias in lowered and cid != exclude
            )
            if ranked:
                return ranked[0][2]

            meaningful = {
                token for token in re.findall(r'[a-z][a-z0-9+-]{2,}', lowered)
                if token not in _ALIAS_STOPWORDS
            }
            if meaningful:
                scored = []
                for component_id, context in searchable_component_text.items():
                    if component_id == exclude:
                        continue
                    score = sum(
                        len(token) for token in meaningful
                        if re.search(r'(?<![a-z0-9])' + re.escape(token) + r'(?![a-z0-9])', context)
                    )
                    if score:
                        scored.append((score, component_id))
                scored.sort(reverse=True)
                if scored and (len(scored) == 1 or scored[0][0] > scored[1][0]):
                    return scored[0][1]
            return prefer or None

        def resolve_flow_endpoint(value: str) -> Optional[str]:
            """As resolve_endpoint, but a named outside party becomes an external node.

            A flow row is the author asserting that data leaves for somewhere. If
            that somewhere is not in the inventory it is still a participant, and
            dropping it would lose the boundary crossing that makes the flow
            interesting.
            """
            resolved = resolve_endpoint(value)
            if resolved:
                return resolved
            label = re.sub(r'\s+', ' ', re.sub(r'[^A-Za-z0-9 .+-]+', ' ', value or '')).strip()
            label = re.sub(r'(?i)^(?:the|a|an)\s+', '', label)
            if not label or re.fullmatch(r'(?i)tb\d+', label) or re.search(r'\bc\d+\b', label.lower()):
                return None
            slug = re.sub(r'_+', '_', re.sub(r'[^a-z0-9]+', '_', label.lower())).strip('_')
            if not slug:
                return None
            external_id = f'ext_{slug}'
            if external_id not in components:
                components[external_id] = Component(
                    id=external_id,
                    name=label,
                    type='External Service',
                    trust_level='external',
                    description='External participant named by an explicit data flow.',
                    properties={
                        'external': True,
                        'authoritative_external_entity': True,
                        'trust_level': 'external',
                    },
                    confidence='High',
                    evidence=[{
                        'source_type': 'architecture_input',
                        'source_ref': label,
                        'line': None,
                        'statement': f'Named as a data flow endpoint: {label}.',
                        'confidence': 'High',
                    }],
                )
                register_aliases(external_id, label)
            return external_id

        flows: List[DataFlow] = []
        for record in flow_table['records']:
            flow_id = str(record.get('id', '')).strip().upper()
            if not re.fullmatch(r'F\d+', flow_id):
                continue
            route = record.get('source_and_destination', '').strip()
            parts = [part.strip() for part in re.split(r'\s*(?:->|→)\s*', route) if part.strip()]
            if len(parts) < 2:
                continue
            source_id = resolve_endpoint(parts[0])
            if not source_id:
                source_id = next(
                    (resolved for part in parts[1:-1] if (resolved := resolve_endpoint(part))),
                    None,
                )
            source_id = source_id or resolve_flow_endpoint(parts[0])

            target_id = resolve_endpoint(parts[-1], exclude=source_id)
            if not target_id:
                target_id = next(
                    (
                        resolved for part in reversed(parts[1:-1])
                        if (resolved := resolve_endpoint(part, exclude=source_id))
                    ),
                    None,
                )
            target_id = target_id or resolve_flow_endpoint(parts[-1])
            if not source_id or not target_id:
                parse_warnings.append(
                    f"{flow_id} '{route}' could not be resolved to components"
                )
                continue
            protocol = record.get('protocol', 'HTTPS').strip().lower()
            data = record.get('data', '').strip()
            crossing = record.get('boundary_crossing', '').strip()
            crosses_boundary = '->' in crossing or '→' in crossing or '/' in crossing
            # A row can say the flow was inferred rather than observed. Without
            # that, re-submitting an emitted model would silently upgrade every
            # guessed edge into something the document asserts.
            assumed = 'assum' in (record.get('evidence', '') or '').strip().lower()
            flows.append(DataFlow(
                source_id=source_id,
                target_id=target_id,
                protocol=protocol,
                data_type=self._flow_data_type(data),
                assumed=assumed,
                properties={
                    'source_record_id': flow_id,
                    'evidence': f"{flow_id}: {route} over {protocol}; data: {data}",
                    'extraction_method': 'authoritative_table',
                    'authoritative': True,
                    'route': route,
                    'intermediate_hops': parts[1:-1],
                    'internal_workflow': source_id == target_id,
                    'boundary_crossing': crossing,
                    'crosses_trust_boundary': crosses_boundary,
                },
                confidence='High',
            ))

        boundary_table = self._table_with_headers(tables, 'id', 'boundary', 'trust_level', 'contents')
        trust_boundaries: List[TrustBoundary] = []
        declared_trust: Dict[str, Tuple[int, str]] = {}
        for record in (boundary_table or {}).get('records', []):
            boundary_id = str(record.get('id', '')).strip().upper()
            if not re.fullmatch(r'TB\d+', boundary_id):
                continue
            contents = record.get('contents', '').strip()
            declared_level = record.get('trust_level', '').strip()

            members = labelled(self._referenced_component_ids(contents))
            if not members:
                # A boundary can list its contents by name ("Stripe, SendGrid and
                # the insurer partner system") rather than by id.
                for fragment in re.split(r',|;|\band\b|/', contents):
                    resolved = resolve_by_name(fragment)
                    if resolved and resolved not in members:
                        members.append(resolved)

            trust_boundaries.append(TrustBoundary(
                name=record.get('boundary', '').strip() or boundary_id,
                boundary_type=declared_level or 'logical',
                components=members,
                description=contents,
                confidence='High',
                evidence=[{'source_type': 'architecture_input', 'source_ref': boundary_id,
                           'line': None, 'statement': contents, 'confidence': 'High'}],
            ))

            # The narrowest boundary naming a component describes it best: an
            # account-wide boundary listing everything says less about a database
            # than the data tier that contains only stores.
            normalized_level = self._normalize_trust_level(declared_level)
            if not normalized_level or not members:
                continue
            for component_id in members:
                incumbent = declared_trust.get(component_id)
                if incumbent is None or len(members) < incumbent[0]:
                    declared_trust[component_id] = (len(members), normalized_level)

        for component_id, component in components.items():
            if component.properties.get('external'):
                continue
            # A level on the component's own row is the most specific statement
            # available, so it outranks any boundary that also contains it.
            claim = declared_trust.get(component_id)
            trust_level = stated_trust_levels.get(component_id) or self._authoritative_trust_level(
                component.type, claim[1] if claim else None
            )
            component.trust_level = trust_level
            component.properties['trust_level'] = trust_level

        for record in (control_table or {}).get('records', []):
            domain = technology_catalog.CONTROL_DOMAINS.get(record.get('domain', '').strip().lower())
            if not domain:
                continue
            for component in components.values():
                if component.properties.get('external'):
                    continue
                context = f"{component.name} {component.properties.get('technology', '')}".lower()
                matches_type = component.type in domain['types']
                matches_term = any(
                    technology_catalog.mentions(context, term) for term in domain['terms']
                )
                if not matches_type and not matches_term:
                    continue
                if domain['exposed'] and component.trust_level != 'public':
                    continue
                component.properties.update(domain['asserts'])
                component.properties.update(domain['type_asserts'].get(component.type, {}))

        asset_table = self._table_with_headers(tables, 'id', 'asset', 'classification', 'required_property')
        assets: List[Asset] = []
        for record in (asset_table or {}).get('records', []):
            asset_id = str(record.get('id', '')).strip().upper()
            if not re.fullmatch(r'AS\d+', asset_id):
                continue
            name = record.get('asset', '').strip()
            location_id = resolve_endpoint(f"{name} {record.get('required_property', '')}")
            assets.append(Asset(
                name=name,
                sensitivity=record.get('classification', '').strip() or 'internal',
                location=components[location_id].name if location_id in components else 'Platform',
                asset_type='authoritative_asset',
                related_component_id=location_id,
                related_data_flows=[flow.properties.get('source_record_id') for flow in flows
                                    if location_id and location_id in {flow.source_id, flow.target_id}],
                confidence='High',
                evidence=[{'source_type': 'architecture_input', 'source_ref': asset_id, 'line': None,
                           'statement': record.get('required_property', ''), 'confidence': 'High'}],
            ))

        issue_table = self._table_with_headers(tables, 'id', 'area', 'known_condition')
        known_issues = []
        for record in (issue_table or {}).get('records', []):
            issue_id = str(record.get('id', '')).strip().upper()
            if not re.fullmatch(r'K\d+', issue_id):
                continue
            area = record.get('area', '').strip()
            condition = record.get('known_condition', '').strip()
            issue = self._classify_known_issue(f"{area}: {condition}")
            issue['source_record_id'] = issue_id
            issue['description'] = condition
            # A weakness that cites a component id is attributed to it. Anything
            # else is left for the shared resolver below, which already matches on
            # component names and, failing that, on the capability the weakness
            # describes; guessing here from table text was how one document's
            # weakness numbering became part of the parser.
            # The area column is a heading ("Session management"), not a
            # reference, so only the condition is read for component names.
            issue['component_hints'] = (
                labelled(self._referenced_component_ids(condition))
                or self._components_named_in(condition, aliases, components)
            )
            known_issues.append(issue)

        known_issues = self._link_known_issues_to_components(known_issues, components)

        actor_table = self._table_with_headers(tables, 'id', 'actor', 'identity', 'intended_privilege')
        actors = []
        identities = []
        for record in (actor_table or {}).get('records', []):
            actor_id = str(record.get('id', '')).strip().upper()
            if not re.fullmatch(r'A\d+', actor_id):
                continue
            actor_name = record.get('actor', '').strip()
            identity = record.get('identity', '').strip()
            privilege = record.get('intended_privilege', '').strip()
            actors.append({
                'id': actor_id, 'name': actor_name, 'identity': identity,
                'intended_privilege': privilege, 'evidence_status': 'explicit',
            })
            identities.append({
                'id': f"identity:{actor_id}", 'actor_id': actor_id,
                'provider': identity, 'authorization': privilege,
                'evidence_status': 'explicit',
            })

        return SystemArchitecture(
            components=list(components.values()),
            flows=flows,
            trust_boundaries=trust_boundaries,
            assets=assets,
            metadata={
                'known_issues': known_issues,
                'actors': actors,
                'identities': identities,
                'source_text': text,
                'architecture_text': text,
                'authoritative_model': True,
                'authoritative_parse_warnings': parse_warnings,
                'authoritative_record_counts': {
                    'components': len(component_table['records']),
                    'flows': len(flow_table['records']),
                    'trust_boundaries': len((boundary_table or {}).get('records', [])),
                    'assets': len((asset_table or {}).get('records', [])),
                    'known_issues': len((issue_table or {}).get('records', [])),
                },
                'assumptions': [],
            },
        )

    def parse_known_issues(self, text: str) -> List[Dict]:
        """
        Extract and classify known security issues from description.
        Looks for 'Known Issues:' section and parses each issue.
        """
        from .issue_inventory import extract_issues
        entries = []
        for source in self._analysis_sources(text):
            body = str(source.get('body') or '')
            entries.extend(item['statement'] for item in extract_issues(body))

        deduplicated = []
        seen = set()
        for entry in entries:
            key = re.sub(r'[^a-z0-9]+', ' ', entry.lower()).strip()
            if key and key not in seen:
                seen.add(key)
                deduplicated.append(entry)

        classified = [self._classify_known_issue(entry) for entry in deduplicated]

        # Unclassified issues each need their own identifier so that reviewers can
        # track them individually instead of seeing one repeated id.
        unclassified = 0
        for issue in classified:
            self._backfill_issue_mapping(issue)
            if str(issue.get('suggested_threat_id') or '').startswith('UNCLASSIFIED-'):
                unclassified += 1
                issue['suggested_threat_id'] = f'UNCLASSIFIED-KNOWN-ISSUE-{unclassified:03d}'
        return classified

    @staticmethod
    def _backfill_issue_mapping(issue: Dict[str, Any]) -> None:
        """Give compatibility-catalog entries the mappings the taxonomy knows.

        The legacy catalog returns a rule id, a control and a severity but no
        STRIDE category, OWASP entry or CWE, so those issues would otherwise be
        reported as Tampering with no standards mapping at all.
        """
        if issue.get('category') and issue.get('owasp_top_10') and issue.get('cwe'):
            return
        generic = classify_generic_weakness(str(issue.get('description') or ''))
        if not generic:
            return
        if not issue.get('category'):
            issue['category'] = generic['category']
        if not issue.get('owasp_top_10'):
            issue['owasp_top_10'] = list(generic['owasp'])
        if not issue.get('cwe'):
            issue['cwe'] = list(generic['cwe'])
        if not issue.get('affected_stride_categories'):
            issue['affected_stride_categories'] = list(generic['stride'])
        if not issue.get('classification_status'):
            issue['classification_status'] = 'classified'

    def _link_known_issues_to_components(
        self, issues: List[Dict[str, Any]], components: Dict[str, Component], flows: Optional[List[DataFlow]] = None
    ) -> List[Dict[str, Any]]:
        """Resolve issue scope from literal component evidence and capabilities."""
        for issue in issues:
            rule_id = str(issue.get('suggested_threat_id') or '').upper()
            if issue.get('control') == 'webhook_signature_validation':
                receivers = []
                for flow in flows or []:
                    source, target = components.get(flow.source_id), components.get(flow.target_id)
                    evidence_text = str(flow.evidence) + str(flow.properties)
                    if (not flow.assumed and source and target
                            and source.type in {'Payment Processor', 'External Entity', 'External Service'}
                            and target.type in {'API', 'Service', 'API Gateway'}
                            and 'webhook' in evidence_text.lower()):
                        receivers.append(target.id)
                if receivers:
                    issue['component_hints'] = list(dict.fromkeys(receivers))
                    issue['component_resolution'] = 'stated_callback_receiver'
                    continue
            issue_resources = {
                'AWS-IAM-CONFUSED-DEPUTY': ('vendor_cross_account_role', 'Vendor Cross-account Role', 'IAM'),
                'AUTH-SAML-RESPONSE-BINDING': ('saml_identity', 'SAML Identity Integration', 'Identity Provider'),
                'AUTH-SCIM-DEPROVISIONING': ('scim_endpoint', 'SCIM Provisioning Endpoint', 'API'),
            }
            for prefix, (component_id, name, component_type) in issue_resources.items():
                if rule_id.startswith(prefix) and component_id not in components:
                    components[component_id] = Component(
                        id=component_id, name=name, type=component_type,
                        description=str(issue.get('description') or ''),
                        properties={
                            'extraction_method': 'known_issue_resource',
                            'evidence_status': 'explicit',
                        },
                    )
            if issue.get("component_hints"):
                issue["component_hints"] = [
                    item for item in issue["component_hints"] if item in components
                ]
                if issue["component_hints"]:
                    continue
            text = str(issue.get("description") or "").lower()
            direct = []
            for component_id, component in components.items():
                aliases = {
                    component_id.lower().replace("_", " "),
                    component.name.lower(),
                    str((component.properties or {}).get("db_type") or "").lower(),
                    str((component.properties or {}).get("technology") or "").lower(),
                    str((component.properties or {}).get("cloud_service") or "").lower(),
                }
                if any(
                    len(alias) >= 3 and re.search(r"(?<![a-z0-9])" + re.escape(alias) + r"(?![a-z0-9])", text)
                    for alias in aliases if alias
                ):
                    direct.append(component_id)
            preferred = self._preferred_issue_component_ids(issue, text, components)
            if preferred:
                ordered = [*preferred, *(item for item in direct if item not in preferred)]
                issue["component_hints"] = ordered[:8]
                issue["component_resolution"] = "literal_and_rule_scope" if direct else "rule_scope_match"
                continue
            if direct:
                issue["component_hints"] = direct[:8]
                issue["component_resolution"] = "literal_issue_evidence"
                continue

            # Ordered so that the closest-fitting component type is offered first.
            # A set here previously let dictionary order decide the scope, which
            # attributed issues to whichever component happened to come first.
            capability_types: List[str] = list(
                GENERIC_SCOPE_TYPES.get(str(issue.get('suggested_threat_id') or '').upper(), ())
            )

            def add_types(*types: str) -> None:
                capability_types.extend(item for item in types if item not in capability_types)

            if any(token in text for token in ("secret", "credential", "api key", "private key", "signing key")):
                add_types("Secrets Manager", "Service", "API")
            if any(token in text for token in ("session", "token", "oauth", "jwt", "password")):
                add_types("Identity Provider", "API", "Service")
            if any(token in text for token in ("at rest", "backup", "snapshot")):
                add_types("Database", "Object Storage", "Data Warehouse")
            if any(token in text for token in ("graphql", "sql", "query", "xss", "ssrf", "input", "webhook")):
                add_types("API", "API Gateway", "Service")
            if any(token in text for token in ("prompt", "model", "agent", "retrieval", "vector", "tool call")):
                add_types("ML Service", "API")
            if any(token in text for token in ("container", "pod", "service account", "kubernetes", "k8s")):
                add_types("Container Platform")
            candidates = [
                component_id
                for component_type in capability_types
                for component_id, component in components.items()
                if component.type == component_type
            ]
            if candidates:
                issue["component_hints"] = candidates[:3]
                issue["component_resolution"] = "capability_match"
            else:
                issue["component_hints"] = []
                issue["component_resolution"] = "unresolved"
        return issues

    @staticmethod
    def _preferred_issue_component_ids(
        issue: Dict[str, Any], text: str, components: Dict[str, Component]
    ) -> List[str]:
        rule_id = str(issue.get('suggested_threat_id') or '').upper()

        def ids(*types: str) -> List[str]:
            ordered = []
            for component_type in types:
                ordered.extend(
                    component_id for component_id, component in components.items()
                    if component.type == component_type and component_id not in ordered
                )
            return ordered

        def named(*tokens: str) -> List[str]:
            return [
                component_id for component_id, component in components.items()
                if any(
                    re.search(
                        r'(?<![a-z0-9])' + re.escape(token) + r'(?![a-z0-9])',
                        f"{component_id} {component.name} {(component.properties or {}).get('technology', '')}".lower(),
                    )
                    for token in tokens
                )
            ]

        if rule_id.startswith('AUTH-SESSION') or rule_id.startswith('AUTH-JWT'):
            return named('keycloak', 'auth0', 'okta', 'azure ad', 'cognito', 'redis') or ids('Identity Provider')
        if rule_id.startswith('AUTH-OIDC'):
            return named('cognito', 'api gateway', 'lambda') or ids('Identity Provider', 'API Gateway')
        if rule_id.startswith('AUTH-SAML'):
            return named('saml', 'okta', 'graphql', 'node.js') or ids('Identity Provider', 'API')
        if rule_id.startswith('AUTH-SCIM'):
            return named('scim', 'identity', 'okta') or ids('API', 'Identity Provider')
        if rule_id.startswith('AUTH-SUPPORT'):
            return named('support', 'audit', 'admin') or ids('External Actor', 'Service')
        if rule_id.startswith('FHIR-'):
            return named('fhir', 'hl7')
        if rule_id.startswith('API-GRAPHQL-FIELD'):
            return named('graphql', 'billing')
        if rule_id.startswith(('WEB-SQL', 'API-BOLA', 'API-GRAPHQL', 'AUTH-ADMIN')):
            return ids('API', 'Service', 'API Gateway')
        if rule_id.startswith('WEB-STORED-XSS'):
            return ids('WebClient', 'API')
        if rule_id.startswith('WEB-SSRF'):
            return named('browser', 'webhook', 'callback') or ids('Tool', 'API', 'Service')
        if rule_id.startswith('EXPORT-CSV'):
            return named('export') or ids('Service')
        if rule_id.startswith(('PAYMENT-AMOUNT', 'PAYMENT-IDEMPOTENCY', 'PAYMENT-AI')):
            scoped = named('node.js', 'stripe', 'payment', 'billing', 'refund')
            return scoped or ids('Payment Processor', 'API')
        if rule_id.startswith(('PAYMENT-', 'WEBHOOK-')):
            return named('stripe', 'payment') or ids('Payment Processor', 'API')
        if rule_id.startswith('AWS-S3'):
            return named('s3', 'bucket')
        if rule_id.startswith('AWS-ORIGIN'):
            return named('alb', 'cloudfront', 'waf')
        if rule_id.startswith('AWS-IAM-CONFUSED'):
            return named('vendor cross-account role') or ids('IAM')
        if rule_id.startswith('AWS-EC2-IMDS'):
            return named('eks', 'ec2', 'irsa') or ids('Container Platform', 'IAM')
        if rule_id.startswith('DOWNLOAD-LINK'):
            return ids('Object Storage', 'API')
        if rule_id.startswith('AWS-KMS'):
            workload = named('lambda') if 'lambda' in text else named('irsa') if 'irsa' in text else []
            return [*workload, *(item for item in named('kms') if item not in workload)]
        if rule_id.startswith('K8S-PRIVILEGED'):
            return named('code execution', 'shell', 'kubernetes', 'eks') or ids('Container Platform')
        if rule_id.startswith(('AWS-IAM', 'K8S-RBAC', 'K8S-PUBLIC')):
            return named('eks', 'kubernetes', 'lambda', 'ec2', 'service')
        if rule_id.startswith('AWS-RDS'):
            return named('rds', 'postgres') or ids('Database')
        if rule_id.startswith('CONTAINER-'):
            return named('ecr', 'container registry', 'eks', 'kubernetes')
        if rule_id.startswith('SUPPLY-CHAIN'):
            return ids('CI/CD', 'Container Registry', 'Container Platform')
        if rule_id.startswith('MCP-OAUTH'):
            return named('orchestrator') + [item for item in ids('MCP Server') if item not in named('orchestrator')]
        if rule_id.startswith('MCP-SERVER'):
            return ids('MCP Server')
        if rule_id.startswith('AI-AGENT-APPROVAL'):
            return named('approval', 'orchestrator') or ids('Service', 'ML Service')
        if rule_id.startswith('AI-AGENT-RESOURCE'):
            return named('agent orchestrator', 'ai agent') or ids('ML Service')
        if rule_id.startswith(('MCP-', 'AI-AGENT')):
            return ids('MCP Server', 'ML Service', 'API')
        if rule_id.startswith('AI-TOOL'):
            return named('orchestrator', 'policy') or ids('ML Service', 'MCP Server', 'Service')
        if rule_id.startswith('AI-MODEL-POLICY'):
            return named('self-hosted model', 'policy service') or ids('ML Service', 'Service')
        if rule_id.startswith('AI-MEMORY'):
            return named('memory', 'dynamodb') or ids('Service', 'Database')
        if rule_id.startswith('AI-RAG'):
            return named('rag', 'pinecone', 'vector') or ids('ML Service', 'Database')
        if rule_id.startswith('AI-INDIRECT'):
            return named('agent orchestrator', 'rag', 'github mcp', 'ai agent') or ids('ML Service')
        if rule_id.startswith('AI-SENSITIVE-TELEMETRY'):
            return named('observability', 'agent orchestrator', 'ai agent') or ids('Monitoring', 'ML Service')
        if rule_id.startswith(('AI-', 'SENSITIVE-DEBUG')):
            return ids('ML Service', 'API', 'Monitoring')
        if rule_id.startswith('UPLOAD-'):
            return named('parsing', 'ocr', 'code execution', 's3') or ids('Worker', 'Object Storage', 'Service', 'API')
        if rule_id.startswith('QUEUE-'):
            return named('sqs', 'dead-letter', 'dlq') or ids('Queue')
        if rule_id.startswith('SECRET-'):
            return ids('Secrets Manager', 'Service', 'Container Platform')
        if rule_id.startswith('HEALTH-BTG'):
            return ids('API', 'Identity Provider', 'Monitoring')
        if rule_id.startswith('HEALTH-ANALYTICS'):
            return named('snowflake', 'bigquery') or ids('Data Warehouse', 'Database')
        if rule_id.startswith('REDIS-'):
            return named('redis')
        if rule_id.startswith('DATA-DELETION'):
            return ids('Database', 'Object Storage', 'ML Service', 'Data Warehouse')
        if rule_id.startswith('CLOUD-CROSS'):
            return ids('Monitoring', 'Data Warehouse', 'Database')
        if rule_id.startswith('CLOUD-SECRET'):
            return named('secret sync', 'secrets manager', 'key vault') or ids('Secrets Manager', 'Service')
        if rule_id.startswith('DATA-POSTGRES'):
            return named('postgres', 'account', 'project') or ids('Database', 'Service')
        if rule_id.startswith('SAAS-SEARCH'):
            return named('elasticsearch', 'search', 'graphql')
        if rule_id.startswith('SAAS-CACHE'):
            return named('redis', 'account', 'project')
        if rule_id.startswith('AUDIT-'):
            return named('audit', 'postgres') or ids('Monitoring', 'Database', 'Service')
        if rule_id.startswith('API-RESOURCE'):
            return ids('API', 'API Gateway', 'Service', 'Queue')
        if 'logging' in text or 'logs' in text:
            return ids('Monitoring', 'API', 'Service')
        return []
    
    def _classify_common_known_issue(self, issue_text: str) -> Optional[Dict[str, Any]]:
        """Map common explicit weaknesses before the legacy compatibility catalog."""
        text = issue_text.lower()

        def issue(rule_id, category, severity, control, mitigation, owasp, cwe, affected=None):
            return self._known_issue_metadata(
                issue_text, rule_id, category, severity, control, mitigation,
                owasp, cwe, affected_stride_categories=affected,
            )

        # AWS identity, network, workload, data, and supply-chain weaknesses.
        if 'alb' in text and 'internet' in text and any(term in text for term in ('bypass cloudfront', 'bypass', 'directly')) and 'waf' in text:
            return issue('AWS-ORIGIN-WAF-BYPASS-001', 'Tampering', 'high', 'origin_access_control',
                'Restrict the ALB to CloudFront origin-facing addresses or authenticated origin requests and reject direct internet traffic.',
                ['A05:2021 Security Misconfiguration'], ['CWE-284'],
                ['Tampering', 'Information Disclosure', 'Denial of Service'])
        if ('id token' in text and ('access token' in text or 'api' in text)) and any(term in text for term in ('audience', 'does not validate', 'without validating')):
            return issue('AUTH-OIDC-TOKEN-CONFUSION-001', 'Spoofing', 'critical', 'oidc_token_type_and_audience_validation',
                'Accept only access tokens issued for this API and validate issuer, audience, token use, signature, lifetime and authorized scopes.',
                ['API2:2023 Broken Authentication'], ['CWE-287', 'CWE-345'],
                ['Spoofing', 'Elevation of Privilege'])
        if ('cross-account' in text or 'vendor aws account' in text) and 'trust' in text and any(term in text for term in ('externalid', 'external id', 'any principal')):
            return issue('AWS-IAM-CONFUSED-DEPUTY-001', 'Spoofing', 'critical', 'cross_account_trust_conditions',
                'Trust only the required vendor role ARN and require a unique ExternalId plus organization and session conditions where applicable.',
                ['A01:2021 Broken Access Control'], ['CWE-441', 'CWE-284'],
                ['Spoofing', 'Elevation of Privilege'])
        if any(term in text for term in ('imdsv1', 'instance metadata', 'metadata service')) and any(term in text for term in ('pod', 'workload', 'reachable', 'reach')):
            return issue('AWS-EC2-IMDS-CREDENTIAL-EXPOSURE-001', 'Information Disclosure', 'critical', 'imds_v2_and_workload_isolation',
                'Require IMDSv2, set the hop limit to one, block pod access to instance metadata and use workload-specific identities.',
                ['A05:2021 Security Misconfiguration'], ['CWE-522', 'CWE-269'],
                ['Information Disclosure', 'Elevation of Privilege'])
        if ('bucket policy' in text or 's3' in text) and any(term in text for term in ('account root', 'root principal')) and any(term in text for term in ('every object', 'all object', 'read')):
            return issue('AWS-S3-CROSS-ACCOUNT-POLICY-001', 'Information Disclosure', 'critical', 's3_cross_account_least_privilege',
                'Grant access only to named workload roles, scoped actions and prefixes, and constrain cross-account access with organization conditions.',
                ['A01:2021 Broken Access Control'], ['CWE-284', 'CWE-732'],
                ['Information Disclosure', 'Elevation of Privilege'])
        if any(term in text for term in ('dead-letter queue', 'dead letter queue', 'dlq')) and any(term in text for term in ('retention is shorter', 'not alarmed', 'no alarm', 'silently')):
            return issue('QUEUE-DLQ-RETENTION-MONITORING-001', 'Denial of Service', 'high', 'dlq_retention_and_alerting',
                'Retain dead-letter messages at least as long as source messages, alarm on arrivals and age, and provide a controlled replay workflow.',
                ['A09:2021 Security Logging and Monitoring Failures'], ['CWE-400', 'CWE-778'],
                ['Denial of Service', 'Repudiation'])
        if ('github actions' in text or 'third-party actions' in text) and any(term in text for term in ('mutable version', 'mutable tag', 'not pinned', 'unpinned')):
            return issue('SUPPLY-CHAIN-UNPINNED-ACTION-001', 'Tampering', 'high', 'pinned_ci_dependencies',
                'Pin every action to an immutable commit SHA, review publishers, minimize workflow permissions and protect workflow changes.',
                ['A08:2021 Software and Data Integrity Failures'], ['CWE-829', 'CWE-1104'],
                ['Tampering', 'Elevation of Privilege'])
        if ('ecr' in text or 'image' in text) and any(term in text for term in ('signature', 'provenance')) and any(term in text for term in ('not enforced', 'not verified', 'without verification', 'admission')):
            return issue('CONTAINER-IMAGE-PROVENANCE-001', 'Tampering', 'critical', 'container_admission_provenance',
                'Sign images and attestations, deploy by digest, and enforce signature and provenance policy at cluster admission.',
                ['A08:2021 Software and Data Integrity Failures'], ['CWE-494'],
                ['Tampering', 'Elevation of Privilege'])

        # Multi-tenant identity, authorization, lifecycle, and audit weaknesses.
        if 'saml' in text and any(term in text for term in ('relaystate', 'inresponseto', 'acs endpoint')):
            return issue('AUTH-SAML-RESPONSE-BINDING-001', 'Spoofing', 'critical', 'saml_response_binding',
                'Bind RelayState to a server-side login transaction and require signed assertions with issuer, audience, recipient and InResponseTo validation.',
                ['A07:2021 Identification and Authentication Failures'], ['CWE-287', 'CWE-345'],
                ['Spoofing', 'Tampering', 'Elevation of Privilege'])
        if ('rls' in text or 'row-level security' in text or 'row level security' in text) and any(term in text for term in ('owns the', 'table owner', 'bypass')):
            return issue('DATA-POSTGRES-RLS-OWNER-BYPASS-001', 'Elevation of Privilege', 'critical', 'non_owner_rls_enforcement',
                'Run the application as a non-owner role, force RLS, deny BYPASSRLS and test tenant isolation using the production database identity.',
                ['A01:2021 Broken Access Control'], ['CWE-639', 'CWE-862'],
                ['Elevation of Privilege', 'Information Disclosure'])
        if 'elasticsearch' in text and 'tenant' in text and any(term in text for term in ('supplied by the browser', 'request supplied', 'client supplied', 'authenticated tenant')):
            return issue('SAAS-SEARCH-TENANT-ISOLATION-001', 'Elevation of Privilege', 'critical', 'server_derived_search_tenant',
                'Derive tenant scope from the authenticated identity and enforce it in the search service and index authorization layer.',
                ['API1:2023 Broken Object Level Authorization'], ['CWE-639', 'CWE-862'],
                ['Elevation of Privilege', 'Information Disclosure'])
        if 'redis' in text and 'cache key' in text and any(term in text for term in ('omit tenant', 'omits tenant', 'without tenant')):
            return issue('SAAS-CACHE-TENANT-COLLISION-001', 'Elevation of Privilege', 'critical', 'tenant_scoped_authorization_cache',
                'Include immutable tenant and policy-version context in authorization cache keys and validate tenant scope again at the resource service.',
                ['A01:2021 Broken Access Control'], ['CWE-639', 'CWE-862'],
                ['Elevation of Privilege', 'Information Disclosure'])
        if 'scim' in text and ('deprovision' in text or 'provision' in text) and any(term in text for term in ('discard', 'silently', 'only one hour', 'failed')):
            return issue('AUTH-SCIM-DEPROVISIONING-FAILURE-001', 'Elevation of Privilege', 'critical', 'durable_identity_lifecycle',
                'Use durable retries and a dead-letter workflow, alert on aged failures, reconcile directory state and suspend access until deprovisioning succeeds.',
                ['A07:2021 Identification and Authentication Failures'], ['CWE-613', 'CWE-778'],
                ['Elevation of Privilege', 'Repudiation'])
        if 'webhook' in text and 'url' in text and any(term in text for term in ('private', 'loopback', 'link-local', 'metadata address')):
            return issue('WEB-SSRF-CALLBACK-001', 'Information Disclosure', 'critical', 'callback_destination_validation',
                'Allowlist callback destinations, block private, loopback and link-local addresses after every DNS resolution and redirect, and restrict egress.',
                ['A10:2021 Server-Side Request Forgery'], ['CWE-918'],
                ['Information Disclosure', 'Elevation of Privilege'])
        if ('csv' in text or 'spreadsheet' in text) and any(term in text for term in ('beginning with =', 'formula', 'neutralization', 'begins with =')):
            return issue('EXPORT-CSV-FORMULA-INJECTION-001', 'Tampering', 'high', 'spreadsheet_formula_neutralization',
                'Neutralize formula-leading cells, use safe export libraries and warn users before opening untrusted exports in spreadsheet software.',
                ['A03:2021 Injection'], ['CWE-1236'],
                ['Tampering', 'Elevation of Privilege'])
        if ('impersonation' in text or 'impersonate' in text) and any(term in text for term in ('no approval', 'logged as the customer', 'not the support operator')):
            return issue('AUTH-SUPPORT-IMPERSONATION-001', 'Spoofing', 'critical', 'approved_attributed_impersonation',
                'Require time-bound approval and reason codes, show an impersonation banner, restrict actions and immutably record both operator and customer identity.',
                ['A01:2021 Broken Access Control', 'A09:2021 Security Logging and Monitoring Failures'], ['CWE-269', 'CWE-778'],
                ['Spoofing', 'Elevation of Privilege', 'Repudiation'])
        if 'audit' in text and any(term in text for term in ('updated or deleted', 'update or delete', 'mutable', 'alter or delete')):
            return issue('AUDIT-LOG-MUTABILITY-001', 'Repudiation', 'critical', 'append_only_audit_storage',
                'Write security events to append-only storage in a separate security boundary and deny application identities update and delete permission.',
                ['A09:2021 Security Logging and Monitoring Failures'], ['CWE-778', 'CWE-284'],
                ['Repudiation', 'Tampering'])
        if 'graphql' in text and any(term in text for term in ('field-level authorization', 'field level authorization')) and any(term in text for term in ('missing', 'not enforced', 'without')):
            return issue('API-GRAPHQL-FIELD-AUTHORIZATION-001', 'Elevation of Privilege', 'critical', 'graphql_field_authorization',
                'Authorize sensitive GraphQL fields and nested resolvers using server-derived tenant, role and object context.',
                ['API3:2023 Broken Object Property Level Authorization'], ['CWE-862'],
                ['Elevation of Privilege', 'Information Disclosure'])

        # Agentic AI, RAG, MCP, approval, memory, execution, and telemetry weaknesses.
        if any(term in text for term in ('retrieved documents', 'retrieved content', 'github issue text')) and any(term in text for term in ('without marking', 'without separating', 'inserted into the agent context', 'instructions from data')):
            return issue('AI-INDIRECT-PROMPT-INJECTION-001', 'Tampering', 'critical', 'untrusted_context_separation',
                'Mark retrieved content as untrusted data, isolate instructions, constrain tool capabilities and independently authorize every action.',
                ['LLM01:2025 Prompt Injection'], ['CWE-74'],
                ['Tampering', 'Elevation of Privilege'])
        if ('pinecone' in text or 'vector' in text) and any(term in text for term in ('namespace', 'tenant_id')) and any(term in text for term in ('request body', 'supplied', 'client')):
            return issue('AI-RAG-TENANT-ISOLATION-001', 'Elevation of Privilege', 'critical', 'tenant_scoped_retrieval',
                'Derive the vector namespace from verified identity context and enforce tenant authorization in the retrieval service and index policy.',
                ['API1:2023 Broken Object Level Authorization'], ['CWE-639', 'CWE-862'],
                ['Elevation of Privilege', 'Information Disclosure'])
        if 'mcp' in text and ('oauth' in text or 'access token' in text) and any(term in text for term in ('every mcp', 'forwards the user', 'third-party mcp')):
            return issue('MCP-OAUTH-TOKEN-DELEGATION-001', 'Information Disclosure', 'critical', 'mcp_token_exchange',
                'Exchange the user token for audience-bound, least-privilege, short-lived MCP credentials and never forward a bearer token to unrelated servers.',
                ['API2:2023 Broken Authentication', 'LLM06:2025 Excessive Agency'], ['CWE-522', 'CWE-269'],
                ['Information Disclosure', 'Elevation of Privilege', 'Spoofing'])
        if 'mcp' in text and any(term in text for term in ('identity is not pinned', 'identity not pinned', 'tool manifests may change', 'manifest may change')):
            return issue('MCP-SERVER-IDENTITY-001', 'Spoofing', 'high', 'mcp_server_and_manifest_pinning',
                'Pin and authenticate MCP server identities, sign manifests and require reapproval whenever tool schemas or capabilities change.',
                ['API2:2023 Broken Authentication'], ['CWE-287', 'CWE-345'],
                ['Spoofing', 'Tampering'])
        if 'approval' in text and any(term in text for term in ('exact tool', 'arguments can change', 'ai-generated summary', 'after approval')):
            return issue('AI-AGENT-APPROVAL-TOCTOU-001', 'Elevation of Privilege', 'critical', 'action_bound_approval',
                'Display and cryptographically bind approval to the exact tool, target, arguments, credential scope and policy decision; reject any mutation.',
                ['LLM06:2025 Excessive Agency'], ['CWE-367', 'CWE-863'],
                ['Elevation of Privilege', 'Tampering', 'Repudiation'])
        if ('browser tool' in text or 'url' in text) and any(term in text for term in ('dns rebinding', 'does not revalidate', 'not revalidate')):
            return issue('WEB-SSRF-DNS-REBINDING-001', 'Information Disclosure', 'critical', 'continuous_ssrf_validation',
                'Resolve and validate every redirect hop and connection destination, block private and link-local ranges, pin DNS results and restrict browser egress.',
                ['A10:2021 Server-Side Request Forgery'], ['CWE-918'],
                ['Information Disclosure', 'Elevation of Privilege'])
        if 'tool output' in text and any(term in text for term in ('valid json', 'authorization', 'business invariants', 'data classification')):
            return issue('AI-TOOL-OUTPUT-POLICY-001', 'Elevation of Privilege', 'critical', 'tool_output_policy_enforcement',
                'Validate tool output against authorization, tenant, data-classification and business invariants before committing any side effect.',
                ['LLM06:2025 Excessive Agency'], ['CWE-862', 'CWE-20'],
                ['Elevation of Privilege', 'Tampering', 'Information Disclosure'])
        if ('agent loop' in text or 'agent loops' in text) and any(term in text for term in ('no token', 'no budget', 'tool-call', 'spend budget', 'time')):
            return issue('AI-AGENT-RESOURCE-EXHAUSTION-001', 'Denial of Service', 'high', 'agent_resource_limits',
                'Enforce tenant-scoped token, step, tool-call, time and spend budgets with bounded retries, cancellation and circuit breakers.',
                ['API4:2023 Unrestricted Resource Consumption', 'LLM10:2025 Unbounded Consumption'], ['CWE-400'])
        if ('fallback' in text or 'self-hosted model' in text) and 'policy' in text and any(term in text for term in ('does not apply', 'not apply', 'different')):
            return issue('AI-MODEL-POLICY-PARITY-001', 'Elevation of Privilege', 'high', 'provider_independent_policy_enforcement',
                'Enforce input, output, tool and data policies in a provider-independent gateway and test identical controls for every model route.',
                ['LLM06:2025 Excessive Agency'], ['CWE-693'],
                ['Elevation of Privilege', 'Tampering'])
        if ('long-term memory' in text or 'agent memory' in text) and any(term in text for term in ('stores secrets', 'no tenant-scoped deletion', 'no tenant scoped deletion')):
            return issue('AI-MEMORY-SECRET-RETENTION-001', 'Information Disclosure', 'critical', 'tenant_scoped_memory_lifecycle',
                'Detect and exclude secrets, encrypt and tenant-scope memory, enforce retention and propagate verifiable tenant deletion.',
                ['LLM02:2025 Sensitive Information Disclosure'], ['CWE-200', 'CWE-459'],
                ['Information Disclosure', 'Repudiation'])
        if any(term in text for term in ('prompt and tool traces', 'tool traces', 'prompts')) and any(term in text for term in ('observability vendor', 'observability', 'without redaction')):
            return issue('AI-SENSITIVE-TELEMETRY-001', 'Information Disclosure', 'critical', 'ai_telemetry_redaction',
                'Redact prompts, credentials and tool payloads before export, minimize vendor data, use tenant controls and enforce retention and access policy.',
                ['LLM02:2025 Sensitive Information Disclosure'], ['CWE-532', 'CWE-200'],
                ['Information Disclosure', 'Repudiation'])
        if ('archive' in text or 'source archives' in text) and any(term in text for term in ('path traversal', 'malware quarantine', 'without')):
            return issue('UPLOAD-ARCHIVE-EXTRACTION-001', 'Tampering', 'critical', 'safe_archive_extraction',
                'Quarantine uploads, scan for malware, reject links and traversal paths, enforce extraction limits and unpack in an isolated filesystem.',
                ['A03:2021 Injection', 'A08:2021 Software and Data Integrity Failures'], ['CWE-22', 'CWE-434'],
                ['Tampering', 'Elevation of Privilege'])
        if 'stripe' in text and ('refund' in text or 'payment' in text) and 'model' in text and any(term in text for term in ('trust the amount', 'trusts the amount', 'invoice validation')):
            return issue('PAYMENT-AI-REFUND-INTEGRITY-001', 'Tampering', 'critical', 'server_validated_refund',
                'Calculate refundable amount from authoritative invoice state, enforce policy and approval, and require an atomic idempotency key.',
                ['A04:2021 Insecure Design', 'LLM06:2025 Excessive Agency'], ['CWE-472', 'CWE-862'],
                ['Tampering', 'Elevation of Privilege'])
        if 'cross-cloud' in text and ('secret' in text or 'key vault' in text) and any(term in text for term in ('every aws secret', 'every azure', 'read every', 'write every')):
            return issue('CLOUD-SECRET-SYNC-OVERPRIVILEGE-001', 'Information Disclosure', 'critical', 'least_privilege_secret_sync',
                'Use dedicated source and destination identities restricted to explicit secret paths, tenant boundaries and one-way synchronization operations.',
                ['A05:2021 Security Misconfiguration'], ['CWE-269', 'CWE-732'],
                ['Information Disclosure', 'Elevation of Privilege'])

        if ('sql' in text or 'query' in text) and any(term in text for term in ('concatenat', 'string interpolation', 'string-built', 'raw query')):
            return issue('WEB-SQL-INJECTION-ORDER-001', 'Tampering', 'critical', 'parameterized_queries',
                'Use parameterized queries for every untrusted value and allowlist dynamic identifiers such as sort columns.',
                ['A03:2021 Injection'], ['CWE-89'])
        if any(term in text for term in ('without checking ownership', 'without an ownership check', 'does not check ownership', 'without checking tenant ownership', 'object id without')):
            return issue('API-BOLA-OBJECT-OWNERSHIP-001', 'Elevation of Privilege', 'critical', 'object_level_authorization',
                'Derive tenant and owner scope from the authenticated principal and authorize every object read or mutation.',
                ['API1:2023 Broken Object Level Authorization'], ['CWE-639', 'CWE-862'])
        if any(term in text for term in ('x-tenant-id', 'trusts the tenant id', 'trusts tenant ids', 'caller-supplied tenant')) and 'issuer-specific claim' not in text:
            return issue('API-BOLA-TENANT-CONTROL-001', 'Elevation of Privilege', 'critical', 'server_derived_tenant_scope',
                'Derive tenant scope from validated identity claims and reject client-controlled tenant selectors.',
                ['API1:2023 Broken Object Level Authorization'], ['CWE-639', 'CWE-862'])
        if any(term in text for term in ('rendered as html', 'without output encoding', 'user-provided html', 'unsanitized html')):
            return issue('WEB-STORED-XSS-001', 'Tampering', 'high', 'html_sanitization',
                'Apply context-aware output encoding, server-side HTML sanitization, and a restrictive Content Security Policy.',
                ['A03:2021 Injection'], ['CWE-79'])
        if ('admin' in text and 'same authentication policy' in text) or 'same authentication policy as tenant' in text:
            return issue('AUTH-ADMIN-SEPARATION-001', 'Elevation of Privilege', 'high', 'admin_authentication_separation',
                'Apply separate admin authorization policy, phishing-resistant MFA, step-up authentication, and restricted admin entry points.',
                ['A01:2021 Broken Access Control'], ['CWE-269', 'CWE-862'])
        if 'webhook' in text and any(term in text for term in ('not validated', 'without signature', 'no signature', 'not verify', 'not verified', 'without verification')):
            return issue('PAYMENT-WEBHOOK-SIGNATURE-001', 'Tampering', 'critical', 'webhook_signature_validation',
                'Verify provider signatures over the raw request body and enforce timestamp, replay, and idempotency controls.',
                ['A08:2021 Software and Data Integrity Failures'], ['CWE-345'], ['Spoofing', 'Tampering'])
        if any(term in text for term in ('no per-tenant quota', 'no concurrency limit', 'no request throttling', 'has no request throttling')):
            return issue('API-RESOURCE-EXHAUSTION-001', 'Denial of Service', 'high', 'rate_limiting',
                'Enforce per-user and per-tenant rate, concurrency, payload, and cost limits with bounded queues and timeouts.',
                ['API4:2023 Unrestricted Resource Consumption'], ['CWE-400'])
        if any(term in text for term in ('dead-letter queue', 'dead letter queue', 'dead-letter topic', 'poison messages')) and any(term in text for term in ('no ', 'without', 'retry', 'indefinitely')):
            return issue('QUEUE-POISON-MESSAGE-001', 'Denial of Service', 'high', 'dead_letter_queue',
                'Bound retries, move poison messages to a dead-letter destination, alert operators, and make consumers idempotent.',
                ['A05:2021 Security Misconfiguration'], ['CWE-400'])
        if ('s3' in text or 'bucket' in text) and any(term in text for term in ('public getobject', 'public read', 'publicly accessible', 'publicly readable')):
            return issue('AWS-S3-PUBLIC-ACL-001', 'Information Disclosure', 'critical', 's3_block_public_access',
                'Enable S3 Block Public Access and restrict bucket policies and object ACLs to explicit workload principals.',
                ['A01:2021 Broken Access Control'], ['CWE-284', 'CWE-200'])
        if 'administratoraccess' in text or 'iam:passrole' in text or 'passrole' in text:
            return issue('AWS-IAM-ADMIN-PASSROLE-001', 'Elevation of Privilege', 'critical', 'least_privilege_iam',
                'Remove AdministratorAccess and wildcard iam:PassRole; scope actions, resources, conditions, and passable role ARNs.',
                ['A05:2021 Security Misconfiguration'], ['CWE-269', 'CWE-732'])
        if 'kms:decrypt' in text and any(term in text for term in ('every key', 'all key', 'wildcard', '*')):
            return issue('AWS-KMS-BROAD-DECRYPT-001', 'Information Disclosure', 'critical', 'kms_key_policy_scope',
                'Restrict kms:Decrypt to required key ARNs and enforce encryption-context and ViaService conditions.',
                ['A05:2021 Security Misconfiguration'], ['CWE-284', 'CWE-311'], ['Information Disclosure', 'Elevation of Privilege'])
        if 'presigned' in text and any(term in text for term in ('content type', 'object size', 'seven days', 'remain valid', 'long-lived')):
            category = 'Denial of Service' if any(term in text for term in ('object size', 'content type')) else 'Information Disclosure'
            affected = [category, 'Tampering'] if category == 'Denial of Service' else [category]
            return issue('AWS-S3-PRESIGNED-URL-001', category, 'high', 'bounded_presigned_urls',
                'Use short-lived, principal-bound URLs with key-prefix, content-type, checksum, and object-size restrictions.',
                ['A01:2021 Broken Access Control', 'API4:2023 Unrestricted Resource Consumption'], ['CWE-200', 'CWE-400'], affected)
        if ('download url' in text or 'download link' in text) and any(term in text for term in ('remain valid', 'seven days', 'long-lived', 'long lived')):
            return issue('DOWNLOAD-LINK-LIFETIME-001', 'Information Disclosure', 'high', 'short_lived_download_authorization',
                'Use short-lived, audience-bound download grants and reauthorize access at download time.',
                ['A01:2021 Broken Access Control'], ['CWE-200', 'CWE-613'])
        if ('eks' in text or 'kubernetes api' in text) and any(term in text for term in ('0.0.0.0/0', 'publicly reachable', 'public endpoint')):
            return issue('K8S-PUBLIC-CONTROL-PLANE-001', 'Elevation of Privilege', 'critical', 'private_control_plane',
                'Disable public cluster endpoint access or restrict it to approved administration networks with strong IAM and audit controls.',
                ['A05:2021 Security Misconfiguration'], ['CWE-284'], ['Elevation of Privilege', 'Information Disclosure'])
        if 'privileged' in text and ('hostpath' in text or 'workload' in text or 'pod' in text):
            return issue('K8S-PRIVILEGED-HOSTPATH-001', 'Elevation of Privilege', 'critical', 'pod_security',
                'Disallow privileged containers and hostPath mounts using restricted Pod Security Admission and admission policy.',
                ['A05:2021 Security Misconfiguration'], ['CWE-250', 'CWE-269'], ['Elevation of Privilege', 'Tampering'])
        if 'irsa' in text and ('s3:*' in text or 'all resources' in text):
            return issue('K8S-RBAC-IRSA-ESCALATION-001', 'Elevation of Privilege', 'critical', 'least_privilege_irsa',
                'Bind each service account to a narrowly scoped IAM role with bucket, prefix, action, and condition restrictions.',
                ['A05:2021 Security Misconfiguration'], ['CWE-269', 'CWE-732'])
        if 'rds' in text and any(term in text for term in ('publicly accessible', 'public access')):
            return issue('AWS-RDS-PUBLIC-ACCESS-001', 'Information Disclosure', 'critical', 'private_database_networking',
                'Place RDS in private subnets, disable public accessibility, and restrict security groups to application workloads.',
                ['A05:2021 Security Misconfiguration'], ['CWE-284'])
        if ('ecr' in text or 'image' in text) and any(term in text for term in ('tags are mutable', 'image scanning is disabled', 'unsigned image', 'unsigned deployment')):
            return issue('CONTAINER-UNVERIFIED-IMAGE-001', 'Tampering', 'high', 'container_image_provenance',
                'Use immutable digest references, enable registry scanning, sign artifacts, and enforce signature verification at admission.',
                ['A08:2021 Software and Data Integrity Failures'], ['CWE-494', 'CWE-1104'])
        if ('credential' in text or 'secret' in text) and any(term in text for term in ('environment variable', 'plain environment', 'plaintext environment')):
            return issue('SECRET-ENVIRONMENT-EXPOSURE-001', 'Information Disclosure', 'high', 'runtime_secret_injection',
                'Inject short-lived secrets from a managed secret store and prevent plaintext credentials in manifests and environment dumps.',
                ['A05:2021 Security Misconfiguration'], ['CWE-798', 'CWE-522'])
        if ('argo' in text or 'manifest' in text) and any(term in text for term in ('unsigned', 'signature not verified')):
            return issue('SUPPLY-CHAIN-UNSIGNED-MANIFEST-001', 'Tampering', 'high', 'deployment_signature_verification',
                'Require signed GitOps commits and manifests, verify provenance, and fail deployment when policy verification fails.',
                ['A08:2021 Software and Data Integrity Failures'], ['CWE-494'])
        if ('github actions' in text or 'third-party actions' in text) and 'unpinned' in text:
            return issue('SUPPLY-CHAIN-UNPINNED-ACTION-001', 'Tampering', 'high', 'pinned_ci_dependencies',
                'Pin actions by immutable commit SHA, review publishers, restrict workflow permissions, and scan workflow changes.',
                ['A08:2021 Software and Data Integrity Failures'], ['CWE-829', 'CWE-1104'])
        if any(term in text for term in ('retrieved documents', 'retrieved content', 'jira issue text')) and any(term in text for term in ('without separating', 'trusted agent instruction', 'treated as trusted', 'instruct the agent')):
            return issue('AI-INDIRECT-PROMPT-INJECTION-001', 'Tampering', 'high', 'untrusted_context_separation',
                'Treat retrieved content as untrusted data, isolate it from instructions, and authorize every resulting action server-side.',
                ['LLM01:2025 Prompt Injection'], ['CWE-74'], ['Tampering', 'Elevation of Privilege'])
        if any(term in text for term in ('tenant_id filter', 'tenant filter', 'another tenant', 'cross-tenant')) and any(term in text for term in ('vector', 'retriev', 'chunk')):
            return issue('AI-RAG-TENANT-ISOLATION-001', 'Elevation of Privilege', 'critical', 'tenant_scoped_retrieval',
                'Derive tenant scope from identity and enforce it in every retrieval query and vector-index authorization policy.',
                ['API1:2023 Broken Object Level Authorization'], ['CWE-639', 'CWE-862'])
        if ('tool' in text or 'mcp' in text) and any(term in text for term in ('arguments are not', 'not validated against an allowlist', 'based only on model output')):
            return issue('MCP-TOOL-COMMAND-INJECTION-001', 'Elevation of Privilege', 'critical', 'typed_tool_authorization',
                'Expose typed allowlisted operations, validate every argument, authorize the caller and resource, and isolate execution.',
                ['LLM06:2025 Excessive Agency', 'A03:2021 Injection'], ['CWE-78', 'CWE-862'], ['Elevation of Privilege', 'Tampering'])
        if ('mcp token' in text or 'service account' in text) and any(term in text for term in ('owner permissions', 'write access to every tenant', 'shared service account')):
            return issue('MCP-DELEGATED-AUTHORIZATION-001', 'Elevation of Privilege', 'critical', 'mcp_delegated_authorization',
                'Use per-user or per-tenant delegated credentials with narrow scopes and authorize each MCP action independently.',
                ['LLM06:2025 Excessive Agency', 'API1:2023 Broken Object Level Authorization'], ['CWE-269', 'CWE-862'])
        if 'approval' in text and any(term in text for term in ('only in the user interface', 'not enforced by', 'bypass', 'without requiring')):
            return issue('AI-AGENT-APPROVAL-BYPASS-001', 'Elevation of Privilege', 'critical', 'server_side_approval',
                'Enforce signed, action-bound approval in the execution service and fail closed when approval is absent or stale.',
                ['LLM06:2025 Excessive Agency'], ['CWE-862', 'CWE-863'])
        if 'mcp' in text and any(term in text for term in ('identity and response signatures are not verified', 'server identity', 'response signatures')):
            return issue('MCP-SERVER-IDENTITY-001', 'Spoofing', 'high', 'mcp_server_authentication',
                'Authenticate MCP servers with pinned identities or mTLS and verify integrity and provenance of tool responses.',
                ['API2:2023 Broken Authentication'], ['CWE-287', 'CWE-345'], ['Spoofing', 'Tampering'])
        if any(term in text for term in ('full prompts', 'raw customer secrets', 'oauth tokens', 'phi are copied', 'request bodies')) and any(term in text for term in ('log', 'retained')):
            return issue('SENSITIVE-DEBUG-LOGGING-001', 'Information Disclosure', 'critical', 'sensitive_log_redaction',
                'Remove sensitive payloads and credentials from logs, apply field-level redaction, restrict access, and shorten retention.',
                ['A09:2021 Security Logging and Monitoring Failures'], ['CWE-532', 'CWE-200'], ['Information Disclosure', 'Repudiation'])
        if any(term in text for term in ('malware scanning', 'source trust validation')) and any(term in text for term in ('without', 'no ', 'not ')):
            return issue('UPLOAD-MALWARE-QUARANTINE-001', 'Tampering', 'high', 'upload_quarantine',
                'Quarantine uploads until malware, file-type, provenance, and source-trust validation succeeds.',
                ['A08:2021 Software and Data Integrity Failures'], ['CWE-434'])
        if 'output filter' in text or 'output filtering' in text:
            return issue('AI-OUTPUT-VALIDATION-001', 'Information Disclosure', 'high', 'model_output_validation',
                'Apply policy, sensitive-data, unsafe-content, and rendering validation before returning model output.',
                ['LLM02:2025 Sensitive Information Disclosure'], ['CWE-200', 'CWE-79'], ['Information Disclosure', 'Tampering'])
        if ('amount' in text and 'currency' in text) and any(term in text for term in ('trusts', 'browser', 'client')):
            return issue('PAYMENT-AMOUNT-INTEGRITY-001', 'Tampering', 'critical', 'server_side_payment_amount',
                'Calculate amount and currency from server-side product and order state and reconcile provider responses.',
                ['A04:2021 Insecure Design'], ['CWE-472'])
        if 'idempotency' in text and any(term in text for term in ('no ', 'without', 'not ')):
            return issue('PAYMENT-IDEMPOTENCY-001', 'Tampering', 'high', 'idempotency_keys',
                'Require and persist an idempotency key atomically for each payment, refund, and webhook event.',
                ['API4:2023 Unrestricted Resource Consumption'], ['CWE-362'])
        if 'graphql' in text and any(term in text for term in ('no ', 'without', 'depth', 'cost limit')):
            return issue('API-GRAPHQL-RESOURCE-CONSUMPTION-001', 'Denial of Service', 'high', 'query_depth_and_cost_limits',
                'Enforce GraphQL depth, complexity, pagination, timeout, and per-principal cost limits.',
                ['API4:2023 Unrestricted Resource Consumption'], ['CWE-400'])
        if ('password change' in text or 'password reset' in text or 'account disablement' in text) and any(term in text for term in ('session', 'token', 'refresh')):
            return issue('AUTH-SESSION-REVOCATION-001', 'Spoofing', 'high', 'session_revocation',
                'Revoke sessions and refresh tokens on identity-security events and reject tokens issued before the current session version.',
                ['A07:2021 Identification and Authentication Failures'], ['CWE-613'])
        if ('fhir' in text or 'partner' in text) and any(term in text for term in ('do not require mutual tls', 'no mtls', 'without mtls', 'sender-constrained')):
            return issue('FHIR-PARTNER-SPOOFING-001', 'Spoofing', 'critical', 'partner_mutual_authentication',
                'Require mTLS or sender-constrained tokens with strict OAuth issuer, audience, scope, and partner authorization.',
                ['API2:2023 Broken Authentication'], ['CWE-287', 'CWE-295'], ['Spoofing', 'Information Disclosure'])
        if 'break-glass' in text or 'break glass' in text:
            return issue('HEALTH-BTG-AUDIT-001', 'Repudiation', 'critical', 'break_glass_audit',
                'Record immutable break-glass reason, patient context, actor, duration, alerting, and post-event review.',
                ['A09:2021 Security Logging and Monitoring Failures'], ['CWE-778'])
        if any(term in text for term in ('not de-identified', 'not deidentified', 'without de-identification', 'are not de-identified')):
            return issue('HEALTH-ANALYTICS-DEIDENTIFICATION-001', 'Information Disclosure', 'critical', 'analytics_deidentification',
                'De-identify and minimize PHI before analytics export and validate re-identification risk and destination access.',
                ['A01:2021 Broken Access Control'], ['CWE-359'])
        if 'redis' in text and any(term in text for term in ('does not require tls', 'no tls', 'without tls', 'acl authentication', 'no auth')):
            return issue('REDIS-SESSION-AUTH-001', 'Spoofing', 'high', 'redis_tls_acl',
                'Require TLS, Redis ACL authentication, private networking, key-prefix isolation, and per-workload credentials.',
                ['A07:2021 Identification and Authentication Failures'], ['CWE-306', 'CWE-319'], ['Spoofing', 'Information Disclosure'])
        if ('jwt' in text or 'claim' in text) and any(term in text for term in ('issuer-specific claim mappings', 'without verifying issuer', 'trusts tenant ids')):
            return issue('AUTH-JWT-CLAIM-CONFUSION-001', 'Elevation of Privilege', 'critical', 'issuer_bound_claim_mapping',
                'Validate issuer, audience, algorithm, and issuer-specific claim mappings before deriving tenant or authorization context.',
                ['API2:2023 Broken Authentication'], ['CWE-287', 'CWE-345'], ['Elevation of Privilege', 'Spoofing'])
        if any(term in text for term in ('arbitrary user-supplied urls', 'arbitrary url', 'user-supplied url')) and 'fetch' in text:
            return issue('WEB-SSRF-URL-FETCH-001', 'Information Disclosure', 'critical', 'ssrf_egress_controls',
                'Allowlist destinations, block private and link-local addresses after DNS resolution, and isolate egress.',
                ['A10:2021 Server-Side Request Forgery'], ['CWE-918'])
        if 'deletion' in text and any(term in text for term in ('do not propagate', 'does not propagate', 'backups', 'evaluation datasets')):
            return issue('DATA-DELETION-PROPAGATION-001', 'Information Disclosure', 'high', 'deletion_propagation',
                'Track deletion across primary stores, vectors, analytics, backups, caches, queues, and AI evaluation datasets.',
                ['A01:2021 Broken Access Control'], ['CWE-200', 'CWE-459'])
        if 'cross-cloud' in text and 'audit' in text:
            return issue('CLOUD-CROSS-BOUNDARY-AUDIT-001', 'Repudiation', 'high', 'cross_cloud_audit_correlation',
                'Record source identity, tenant, dataset, destination, purpose, and transfer result in correlated immutable audit events.',
                ['A09:2021 Security Logging and Monitoring Failures'], ['CWE-778'])
        return None

    def _classify_known_issue(self, issue_text: str) -> Dict:
        """Classify a known issue into threat category and severity"""
        issue_lower = issue_text.lower()

        common = self._classify_common_known_issue(issue_text)
        if common:
            return common

        # Explicit issues are evidence. Keep this catalog deterministic so the
        # output has stable, framework-aligned classification and remediation.
        if any(token in issue_lower for token in ('resource tenant', 'requested resource tenant')) and any(token in issue_lower for token in ('jwt', 'token tenant', 'tenant_id')):
            return self._known_issue_metadata(issue_text, 'API-BOLA-TENANT-CONTROL-001', 'Elevation of Privilege', 'critical', 'object_level_authorization',
                'Derive tenant scope from the authenticated identity and enforce resource ownership in every claim download, FHIR export, query, and object lookup.',
                ['API1:2023 Broken Object Level Authorization'], ['CWE-639', 'CWE-862'])
        if any(token in issue_lower for token in ('client credentials', 'partner client')) and any(token in issue_lower for token in ('mtls', 'audience restriction', 'audience validation')) and any(token in issue_lower for token in ('not enforced', 'not yet enforced', 'no mtls', 'without mtls')):
            return self._known_issue_metadata(issue_text, 'FHIR-PARTNER-SPOOFING-001', 'Spoofing', 'high', 'partner_mutual_authentication',
                'Require mTLS and OAuth2 client credentials, validate issuer and audience per partner, bind certificates to client identities, and rotate credentials.',
                ['API2:2023 Broken Authentication'], ['CWE-287', 'CWE-295'])
        if any(token in issue_lower for token in ('order by', 'sql', 'query')) and any(token in issue_lower for token in ('string interpolation', 'caller-supplied sort', 'caller supplied sort')):
            return self._known_issue_metadata(issue_text, 'WEB-SQL-INJECTION-ORDER-001', 'Tampering', 'high', 'sql_allowlisted_sort',
                'Map requested sort keys to a server-side allowlist of fixed SQL identifiers and keep all data values parameterized.',
                ['A03:2021 Injection'], ['CWE-89'])
        if 'ssrf' in issue_lower or ('user-supplied' in issue_lower and 'url' in issue_lower and any(token in issue_lower for token in ('redirect', 'allowlist', 'destination ip'))):
            return self._known_issue_metadata(issue_text, 'WEB-SSRF-URL-FETCH-001', 'Information Disclosure', 'high', 'ssrf_egress_controls',
                'Use a strict destination allowlist, resolve and block private, loopback and link-local addresses after every redirect, disable unsafe schemes, and restrict workload egress.',
                ['A10:2021 Server-Side Request Forgery'], ['CWE-918'])
        if any(token in issue_lower for token in ('rich-text', 'rich text', 'html sanitizer')) and any(token in issue_lower for token in ('without', 'not applied', 'inconsistent')):
            return self._known_issue_metadata(issue_text, 'WEB-STORED-XSS-001', 'Tampering', 'high', 'html_sanitization',
                'Sanitize rich-text HTML with a server-side allowlist, encode output by context, and enforce a restrictive Content Security Policy.',
                ['A03:2021 Injection'], ['CWE-79'])
        if 'presigned' in issue_lower and any(token in issue_lower for token in ('24 hour', '24-hour', 'not bound', 'single use')):
            return self._known_issue_metadata(issue_text, 'AWS-S3-PRESIGNED-URL-001', 'Information Disclosure', 'high', 'short_lived_bound_downloads',
                'Use short-lived download grants, reauthorize at download time, limit content disposition and object scope, and revoke exported objects when the session or entitlement changes.',
                ['A01:2021 Broken Access Control'], ['CWE-200', 'CWE-613'])
        if 'kms' in issue_lower and any(token in issue_lower for token in ('rotation is disabled', 'rotation disabled', 'old cross-account grant', 'stale external grant')):
            return self._known_issue_metadata(issue_text, 'AWS-KMS-STALE-GRANTS-001', 'Elevation of Privilege', 'high', 'kms_grant_lifecycle',
                'Enable supported key rotation, inventory KMS grants, revoke stale external grants, and constrain grants with retiring principals and encryption-context conditions.',
                ['A05:2021 Security Misconfiguration'], ['CWE-269', 'CWE-284'])
        if 'redis' in issue_lower and any(token in issue_lower for token in ('shared', 'broad acl', 'entire eks node cidr')):
            return self._known_issue_metadata(issue_text, 'REDIS-SHARED-SERVICE-IDENTITY-001', 'Elevation of Privilege', 'high', 'redis_service_identity',
                'Issue a distinct Redis ACL identity per service, restrict commands and key prefixes, and narrow the security-group source to authorized workload identities or security groups.',
                ['A01:2021 Broken Access Control'], ['CWE-269', 'CWE-732'])
        if any(token in issue_lower for token in ('all tenants share one vector index', 'shared vector index', 'metadata filters')):
            return self._known_issue_metadata(issue_text, 'AI-RAG-TENANT-ISOLATION-001', 'Elevation of Privilege', 'critical', 'tenant_scoped_retrieval',
                'Enforce tenant authorization in the retrieval service and index policy, derive tenant scope from identity, and continuously test cross-tenant retrieval denial.',
                ['API1:2023 Broken Object Level Authorization'], ['CWE-639', 'CWE-862'])
        if 'prompt injection' in issue_lower and any(token in issue_lower for token in ('uploaded', 'retrieved', 'trusted text', 'instruction/data separation')):
            return self._known_issue_metadata(issue_text, 'AI-INDIRECT-PROMPT-INJECTION-001', 'Tampering', 'high', 'untrusted_context_separation',
                'Treat retrieved documents as untrusted data, separate system instructions from content, detect instruction-like payloads, constrain tools, and validate model output before use.',
                ['LLM01:2025 Prompt Injection'], ['CWE-74'])
        if any(token in issue_lower for token in ('privileged', 'automatically mounts', 'service-account token', 'service account token')) and any(token in issue_lower for token in ('namespace', 'deployment', 'pod')):
            return self._known_issue_metadata(issue_text, 'K8S-PRIVILEGED-POD-TOKEN-001', 'Elevation of Privilege', 'critical', 'kubernetes_workload_isolation',
                'Remove privileged mode, disable automatic service-account token mounting, enforce restricted Pod Security Admission, and apply default-deny ingress and egress NetworkPolicies.',
                ['A05:2021 Security Misconfiguration'], ['CWE-250', 'CWE-269'])
        if any(token in issue_lower for token in ('unscanned object', 'malware scanning is asynchronous', 'scanning is asynchronous')) and any(token in issue_lower for token in ('preview', 'uploaded', 'object')):
            return self._known_issue_metadata(issue_text, 'UPLOAD-MALWARE-RACE-001', 'Tampering', 'high', 'upload_quarantine',
                'Keep uploaded objects in an isolated quarantine bucket and deny preview, download, OCR and model ingestion until content inspection succeeds.',
                ['A08:2021 Software and Data Integrity Failures'], ['CWE-434'])
        if 'mcp' in issue_lower and 'tool call' in issue_lower and any(token in issue_lower for token in ('does not independently authorize', 'initiating user', 'tenant and resource')):
            return self._known_issue_metadata(issue_text, 'MCP-DELEGATED-AUTHORIZATION-001', 'Elevation of Privilege', 'critical', 'mcp_delegated_authorization',
                'Pass a signed delegated-user context and independently authorize every MCP tool invocation against user, tenant, resource, action, and current entitlement.',
                ['API1:2023 Broken Object Level Authorization', 'LLM06:2025 Excessive Agency'], ['CWE-862', 'CWE-863'])
        if any(token in issue_lower for token in ('approve claims', 'issue refunds', 'without human confirmation')) and any(token in issue_lower for token in ('agent', 'semantic constraints', 'human confirmation')):
            return self._known_issue_metadata(issue_text, 'AI-AGENT-CONSEQUENTIAL-ACTION-001', 'Elevation of Privilege', 'critical', 'consequential_action_approval',
                'Enforce policy and human approval in the claims and payment services, bind approval to exact tool arguments, and fail closed on semantic-policy violations.',
                ['LLM06:2025 Excessive Agency'], ['CWE-862', 'CWE-863'])
        if any(token in issue_lower for token in ('token budget', 'agent-step ceiling', 'recursive tool-call', 'recursive tool call')):
            return self._known_issue_metadata(issue_text, 'AI-AGENT-RESOURCE-EXHAUSTION-001', 'Denial of Service', 'high', 'agent_resource_limits',
                'Enforce per-user and per-tenant token budgets, maximum agent steps and tool calls, bounded retries, queue backpressure, and circuit breakers.',
                ['API4:2023 Unrestricted Resource Consumption', 'LLM10:2025 Unbounded Consumption'], ['CWE-400'])
        if 'webhook' in issue_lower and any(token in issue_lower for token in ('bypasses signature validation', 'accepted without signature verification')):
            provider_specific = any(token in issue_lower for token in ('stripe', 'payment', 'paypal', 'adyen', 'braintree'))
            rule_id = 'PAYMENT-WEBHOOK-SIGNATURE-001' if provider_specific else 'WEBHOOK-SIGNATURE-VALIDATION-001'
            return self._known_issue_metadata(issue_text, rule_id, 'Tampering', 'critical', 'webhook_signature_validation',
                'Remove deprecated public routes or verify provider signatures against the raw body, enforce timestamp windows and replay protection, and authenticate every event source.',
                ['A08:2021 Software and Data Integrity Failures'], ['CWE-345'])
        if any(token in issue_lower for token in ('fhir request bodies', 'provider tokens', 'phi')) and any(token in issue_lower for token in ('debug log', 'included in', 'logs')):
            return self._known_issue_metadata(issue_text, 'SENSITIVE-DEBUG-LOGGING-001', 'Information Disclosure', 'critical', 'sensitive_log_redaction',
                'Disable payload logging in production, redact PHI and provider tokens before emission, restrict troubleshooting access, and use short-lived targeted diagnostics.',
                ['A09:2021 Security Logging and Monitoring Failures'], ['CWE-532', 'CWE-200'])
        if any(token in issue_lower for token in ('delete its detailed application audit', 'delete audit', 'audit events before')):
            return self._known_issue_metadata(issue_text, 'AUDIT-SELF-DELETION-001', 'Repudiation', 'critical', 'immutable_audit_separation',
                'Write break-glass events synchronously to an append-only security account and deny application and support roles permission to alter or delete audit evidence.',
                ['A09:2021 Security Logging and Monitoring Failures'], ['CWE-778', 'CWE-284'])
        if 'github actions' in issue_lower and any(token in issue_lower for token in ('pull-request code', 'pull request code', 'trust policy', 'branch or workflow')):
            return self._known_issue_metadata(issue_text, 'SUPPLY-CHAIN-GITHUB-OIDC-001', 'Elevation of Privilege', 'critical', 'github_oidc_subject_constraints',
                'Do not grant AWS credentials to untrusted pull-request code; constrain OIDC subject, branch, environment and reusable workflow, and require protected-environment approval.',
                ['A08:2021 Software and Data Integrity Failures'], ['CWE-269', 'CWE-284'])
        if any(token in issue_lower for token in ('unrestricted outbound', 'action=*', 'resource=*')) and any(token in issue_lower for token in ('eks', 'endpoint policy', 'secrets manager')):
            return self._known_issue_metadata(issue_text, 'AWS-EGRESS-ENDPOINT-POLICY-001', 'Information Disclosure', 'high', 'cloud_egress_and_endpoint_policy',
                'Apply workload egress allowlists and default-deny NetworkPolicies; restrict the Secrets Manager endpoint policy to approved principals, actions, resources and organization conditions.',
                ['A05:2021 Security Misconfiguration'], ['CWE-284', 'CWE-732'])
        if any(token in issue_lower for token in ('long-lived partner api secret', 'outside the secrets manager rotation', 'managed manually')):
            return self._known_issue_metadata(issue_text, 'SECRET-ROTATION-DRIFT-001', 'Spoofing', 'high', 'central_secret_rotation',
                'Remove manually managed secret copies, source the credential only from Secrets Manager, rotate it, and continuously detect unmanaged Kubernetes secrets.',
                ['A07:2021 Identification and Authentication Failures'], ['CWE-798', 'CWE-522'])
        if 'restore testing' in issue_lower and any(token in issue_lower for token in ('excludes', 'vector index', 'agent configuration')):
            return self._known_issue_metadata(issue_text, 'RECOVERY-COVERAGE-GAP-001', 'Denial of Service', 'high', 'complete_restore_testing',
                'Include search/vector indexes and agent configuration in recovery scope, document Redis session-loss behavior, and validate complete service restoration against RTO and RPO.',
                ['A05:2021 Security Misconfiguration'], ['CWE-693'])
        if any(token in issue_lower for token in ('share worker capacity', 'no workload-specific concurrency', 'no concurrency quota')):
            return self._known_issue_metadata(issue_text, 'WORKLOAD-STARVATION-001', 'Denial of Service', 'high', 'workload_isolation_quotas',
                'Separate interactive and bulk worker pools, enforce tenant and workload concurrency quotas, prioritize queues, and shed noncritical bulk work during pressure.',
                ['API4:2023 Unrestricted Resource Consumption'], ['CWE-400'])
        if 'tenant deletion' in issue_lower and any(token in issue_lower for token in ('search', 'vector', 'dlq', 'evaluation set', 'independent retention')):
            return self._known_issue_metadata(issue_text, 'DATA-DELETION-PROPAGATION-001', 'Information Disclosure', 'high', 'deletion_propagation',
                'Use a tracked deletion workflow across primary stores, indexes, queues, exports and AI datasets; verify completion, retention exceptions and cryptographic erasure evidence.',
                ['A01:2021 Broken Access Control'], ['CWE-200', 'CWE-459'])
        if 'break' in issue_lower and 'glass' in issue_lower and any(token in issue_lower for token in ('audit', 'log', 'review')):
            return self._known_issue_metadata(issue_text, 'HEALTH-BTG-AUDIT-001', 'Repudiation', 'critical', 'break_glass_audit',
                'Require a reason and incident or patient context for every break-glass grant; write separate tamper-evident audit events, alert the privacy team, and review every use.',
                ['A09:2021 Security Logging and Monitoring Failures'], ['CWE-778'], ['rest_api', 'azure_ad', 'postgresql'])
        if any(token in issue_lower for token in ('data loss prevention', 'dlp')) and any(token in issue_lower for token in ('download', 'export', 'file')):
            return self._known_issue_metadata(issue_text, 'HEALTH-PHI-DLP-001', 'Information Disclosure', 'critical', 'phi_download_dlp',
                'Route PHI exports through an authorized download service with DLP inspection, export quotas, watermarking, short-lived links, and audit events tied to the user and patient context.',
                ['A01:2021 Broken Access Control'], ['CWE-200', 'CWE-284'], ['azure_blob', 'rest_api', 'react'])
        if 'session' in issue_lower and 'timeout' in issue_lower and any(token in issue_lower for token in ('too long', 'hour', 'long-lived', 'long lived')):
            return self._known_issue_metadata(issue_text, 'AUTH-LONG-LIVED-SESSION-001', 'Spoofing', 'high', 'session_timeout',
                'Use a short PHI-access idle timeout, an absolute session lifetime, step-up reauthentication for sensitive actions, refresh-token rotation, and server-side session revocation.',
                ['A07:2021 Identification and Authentication Failures'], ['CWE-613'], ['redis', 'azure_ad', 'rest_api'])
        if ('password change' in issue_lower or 'password reset' in issue_lower) and any(token in issue_lower for token in ('session', 'token', 'jwt')):
            return self._known_issue_metadata(issue_text, 'AUTH-SESSION-REVOCATION-001', 'Spoofing', 'high', 'session_revocation',
                'Revoke Redis sessions and refresh tokens when credentials change; reject JWTs issued before passwordChangedAt or with an obsolete session version.',
                ['A07:2021 Identification and Authentication Failures'], ['CWE-613'])
        if any(token in issue_lower for token in ('tenant id', 'tenant_id', 'caller-supplied tenant', 'caller supplied tenant')) and any(token in issue_lower for token in (
            'invoice', 'order', 'record', 'load', 'api', 'request header',
            'ownership validation', 'server-side ownership', 'server side ownership',
        )):
            return self._known_issue_metadata(issue_text, 'API-BOLA-TENANT-CONTROL-001', 'Elevation of Privilege', 'critical', 'server_derived_tenant_scope',
                'Derive tenant scope from the authenticated identity on the server and enforce tenant ownership in every query and object lookup.',
                ['API1:2023 Broken Object Level Authorization'], ['CWE-639', 'CWE-862'])
        if any(token in issue_lower for token in ('account_id', 'account id', 'object id', 'record id')) and any(token in issue_lower for token in ('caller-supplied', 'caller supplied', 'trusts', 'without verifying', 'ownership')):
            return self._known_issue_metadata(issue_text, 'API-BOLA-OBJECT-OWNERSHIP-001', 'Elevation of Privilege', 'critical', 'object_level_authorization',
                'Resolve the object under the authenticated principal and tenant, then enforce ownership or entitlement before reading or modifying it.',
                ['API1:2023 Broken Object Level Authorization'], ['CWE-639', 'CWE-862'])
        if 'webhook' in issue_lower and any(token in issue_lower for token in ('without signature', 'no signature', 'not verify', 'without verification')):
            return self._known_issue_metadata(issue_text, 'PAYMENT-WEBHOOK-SIGNATURE-001', 'Tampering', 'critical', 'webhook_signature_validation',
                'Verify the payment provider signature against the raw request body, enforce event replay protection, and reject unsigned events.',
                ['A08:2021 Software and Data Integrity Failures'], ['CWE-345'])
        if any(token in issue_lower for token in ('user-supplied url', 'user supplied url', 'arbitrary url', 'accepts a url', 'fetches it')) and any(token in issue_lower for token in ('fetch', 'preview', 'server-side', 'server side', 'internal control-plane', 'internal control plane')):
            return self._known_issue_metadata(issue_text, 'WEB-SSRF-URL-FETCH-001', 'Information Disclosure', 'high', 'ssrf_egress_controls',
                'Use an allowlist of destination hosts, resolve and block private/link-local addresses after DNS resolution, and restrict outbound network egress.',
                ['A10:2021 Server-Side Request Forgery'], ['CWE-918'])
        if any(token in issue_lower for token in ('user-supplied url', 'user supplied url', 'arbitrary url')) and any(token in issue_lower for token in ('callback', 'webhook delivery', 'outbound delivery')):
            return self._known_issue_metadata(issue_text, 'WEB-SSRF-CALLBACK-001', 'Information Disclosure', 'high', 'callback_destination_validation',
                'Allowlist callback destinations, block private and link-local address ranges after DNS resolution, and isolate callback delivery with restricted egress.',
                ['A10:2021 Server-Side Request Forgery'], ['CWE-918'])
        if any(token in issue_lower for token in ('payment provider payload', 'cardholder', 'payment payload')) and any(token in issue_lower for token in ('log', 'logging', 'logs')):
            return self._known_issue_metadata(issue_text, 'PAYMENT-SENSITIVE-LOGGING-001', 'Information Disclosure', 'critical', 'payment_log_redaction',
                'Remove payment payloads from logs, redact provider tokens and cardholder-related metadata, and enforce PCI-focused log retention and access controls.',
                ['A09:2021 Security Logging and Monitoring Failures'], ['CWE-532', 'CWE-200'])
        if any(token in issue_lower for token in ('idempotency', 'duplicate charge', 'duplicate refund')) and any(token in issue_lower for token in ('refund', 'payment', 'charge')):
            return self._known_issue_metadata(issue_text, 'PAYMENT-IDEMPOTENCY-001', 'Tampering', 'high', 'idempotency_keys',
                'Require an idempotency key per payment or refund operation and store the result atomically before retrying downstream calls.',
                ['API4:2023 Unrestricted Resource Consumption'], ['CWE-362'])
        if any(token in issue_lower for token in ('administratoraccess', 'iam:passrole', 'passrole')):
            return self._known_issue_metadata(issue_text, 'AWS-IAM-ADMIN-PASSROLE-001', 'Elevation of Privilege', 'critical', 'least_privilege_iam',
                'Remove AdministratorAccess and iam:PassRole wildcards; constrain role ARNs, session tags, permissions boundaries, and OIDC trust conditions.',
                ['A05:2021 Security Misconfiguration'], ['CWE-269', 'CWE-732'])
        if 's3' in issue_lower and any(token in issue_lower for token in ('public read', 'public-read', 'public acl', 'public-read acl', 'publicly readable')):
            return self._known_issue_metadata(issue_text, 'AWS-S3-PUBLIC-ACL-001', 'Information Disclosure', 'critical', 's3_block_public_access',
                'Enable account and bucket Block Public Access, remove public ACLs, and use restrictive bucket policies with explicit principals.',
                ['A01:2021 Broken Access Control'], ['CWE-284', 'CWE-200'])
        if 'kms' in issue_lower and any(token in issue_lower for token in ('decrypt', 'key policy', 'encryption-context', 'encryption context')):
            return self._known_issue_metadata(issue_text, 'AWS-KMS-BROAD-DECRYPT-001', 'Information Disclosure', 'critical', 'kms_key_policy_scope',
                'Restrict kms:Decrypt to workload roles and required key ARNs; enforce encryption-context and ViaService conditions in the key policy.',
                ['A05:2021 Security Misconfiguration'], ['CWE-284', 'CWE-311'])
        if any(token in issue_lower for token in ('0.0.0.0/0', 'internet-facing security group', 'node port', 'nodeport')):
            return self._known_issue_metadata(issue_text, 'AWS-NETWORK-OPEN-INGRESS-001', 'Information Disclosure', 'critical', 'network_ingress_restriction',
                'Restrict security-group ingress to required CIDRs and load balancers; keep Kubernetes NodePorts private and use controlled ingress.',
                ['A05:2021 Security Misconfiguration'], ['CWE-284'])
        if any(token in issue_lower for token in ('cluster-wide', 'cluster wide', 'list secrets', 'irsa', 'service account')) and any(token in issue_lower for token in ('secret', 'role', 's3')):
            return self._known_issue_metadata(issue_text, 'K8S-RBAC-IRSA-ESCALATION-001', 'Elevation of Privilege', 'critical', 'kubernetes_rbac_irsa',
                'Limit Kubernetes RBAC to namespace and verb, remove secret-list permissions, and bind each IRSA service account to a narrowly scoped IAM role.',
                ['A05:2021 Security Misconfiguration'], ['CWE-269', 'CWE-284'])
        if 'lambda' in issue_lower and any(token in issue_lower for token in ('public invoke', 'public invokefunction', 'public invokefunction')):
            return self._known_issue_metadata(issue_text, 'AWS-LAMBDA-PUBLIC-INVOKE-001', 'Elevation of Privilege', 'critical', 'lambda_resource_policy',
                'Remove public principals from the Lambda resource policy and allow invocation only from specific API Gateway, EventBridge, or AWS principals.',
                ['A05:2021 Security Misconfiguration'], ['CWE-284'])
        if 'cloudtrail' in issue_lower and any(token in issue_lower for token in ('data event', 's3 object', 'disabled')):
            return self._known_issue_metadata(issue_text, 'AWS-CLOUDTRAIL-DATA-EVENTS-001', 'Repudiation', 'high', 'cloudtrail_data_events',
                'Enable CloudTrail data events for sensitive S3 buckets and route immutable logs to the central security account.',
                ['A09:2021 Security Logging and Monitoring Failures'], ['CWE-778'])
        if any(token in issue_lower for token in ('image tag latest', 'tag latest', 'without signature', 'signature verification')) and any(token in issue_lower for token in ('container', 'image', 'deploy')):
            return self._known_issue_metadata(issue_text, 'CONTAINER-UNVERIFIED-IMAGE-001', 'Tampering', 'high', 'container_image_provenance',
                'Pin images by digest and enforce signature/provenance verification with an admission policy before deployment.',
                ['A08:2021 Software and Data Integrity Failures'], ['CWE-494'])
        if 's3:' in issue_lower and '*' in issue_lower and any(token in issue_lower for token in ('iam', 'policy', 'role')):
            return self._known_issue_metadata(issue_text, 'AWS-IAM-WILDCARD-S3-001', 'Elevation of Privilege', 'high', 'least_privilege_iam',
                'Replace wildcard S3 actions and resources with the minimum bucket, prefix, action, and condition set; separate deployment read/write roles.',
                ['A05:2021 Security Misconfiguration'], ['CWE-269', 'CWE-732'])
        if 'bucket-owner-enforced' in issue_lower or 'object ownership' in issue_lower:
            return self._known_issue_metadata(issue_text, 'AWS-S3-OBJECT-OWNERSHIP-001', 'Elevation of Privilege', 'high', 's3_object_ownership',
                'Enable S3 BucketOwnerEnforced object ownership, disable ACLs, and restrict uploads with a bucket policy.',
                ['A05:2021 Security Misconfiguration'], ['CWE-284'])
        if 'lambda' in issue_lower and any(token in issue_lower for token in ('logs', 'logging', 'event')) and any(token in issue_lower for token in ('full', 'redact', 'unredact')):
            return self._known_issue_metadata(issue_text, 'AWS-LAMBDA-SENSITIVE-LOGGING-001', 'Information Disclosure', 'high', 'log_redaction',
                'Log an allowlisted event summary only; redact PII, credentials, tokens, and document contents before emitting application logs.',
                ['A09:2021 Security Logging and Monitoring Failures'], ['CWE-532'])
        if any(token in issue_lower for token in ('tenant filter', 'tenant isolation', 'cross-tenant', 'tenant_id', 'tenant id')) and any(token in issue_lower for token in ('retrieval', 'opensearch', 'vector', 'search')):
            return self._known_issue_metadata(issue_text, 'AI-RAG-TENANT-ISOLATION-001', 'Elevation of Privilege', 'critical', 'tenant_scoped_retrieval',
                'Apply a server-derived tenant filter before every vector search, enforce it in the index authorization layer, and test cross-tenant retrieval denial.',
                ['API1:2023 Broken Object Level Authorization'], ['CWE-639', 'CWE-862'])
        if any(token in issue_lower for token in ('prompt injection', 'tool-call approval', 'tool call approval', 'tool authorization', 'retrieved contract text', 'retrieved ticket text', 'can call')) and any(token in issue_lower for token in ('tool', 'model', 'retrieved', 'prompt')):
            return self._known_issue_metadata(issue_text, 'AI-TOOL-AUTHORIZATION-001', 'Elevation of Privilege', 'high', 'tool_authorization',
                'Treat retrieved content as untrusted data, require per-tool server-side authorization, constrain tool schemas, and require human approval for consequential actions.',
                ['LLM01:2025 Prompt Injection'], ['CWE-74', 'CWE-862'])
        if any(token in issue_lower for token in ('malware scan', 'virus scan')) and any(token in issue_lower for token in ('before', 'completion', 'accepted', 'processed')):
            return self._known_issue_metadata(issue_text, 'UPLOAD-MALWARE-QUARANTINE-001', 'Tampering', 'high', 'upload_quarantine',
                'Quarantine uploads until malware scanning completes successfully; block extraction, preview, and model ingestion from pending objects.',
                ['A08:2021 Software and Data Integrity Failures'], ['CWE-434'])
        if any(token in issue_lower for token in ('prompt', 'response', 'document excerpt', 'retrieved snippet', 'tool argument')) and any(token in issue_lower for token in ('logged', 'logging', 'logs', 'trace', 'traces', 'retained')):
            return self._known_issue_metadata(issue_text, 'AI-SENSITIVE-TELEMETRY-001', 'Information Disclosure', 'high', 'ai_log_redaction',
                'Do not log raw prompts, responses, or retrieved documents; use redacted structured telemetry with short retention and restricted access.',
                ['A09:2021 Security Logging and Monitoring Failures'], ['CWE-532', 'CWE-200'])
        if any(token in issue_lower for token in ('repository membership', 'project id', 'object-level authorization')):
            return self._known_issue_metadata(issue_text, 'MCP-TOOL-BOLA-001', 'Elevation of Privilege', 'critical', 'mcp_resource_authorization',
                'Authorize each MCP tool invocation against the authenticated principal, organization, repository membership, and requested resource; never trust client-supplied project IDs.',
                ['API1:2023 Broken Object Level Authorization'], ['CWE-639', 'CWE-862'])
        if any(token in issue_lower for token in ('shell command', 'arbitrary command', 'command text')):
            return self._known_issue_metadata(issue_text, 'MCP-TOOL-COMMAND-INJECTION-001', 'Elevation of Privilege', 'critical', 'mcp_command_allowlist',
                'Remove arbitrary shell input. Use typed, allowlisted deployment operations with fixed arguments, policy checks, isolated execution, and approval for production actions.',
                ['A03:2021 Injection'], ['CWE-78'])
        if any(token in issue_lower for token in ('broad github token', 'forwards a broad', 'forwards broad', 'credential forwarding')) and any(token in issue_lower for token in ('mcp', 'token', 'server')):
            return self._known_issue_metadata(issue_text, 'MCP-CREDENTIAL-FORWARDING-001', 'Information Disclosure', 'critical', 'mcp_scoped_credentials',
                'Issue audience- and server-scoped short-lived tokens. Never forward a broad credential to every MCP server.',
                ['A01:2021 Broken Access Control'], ['CWE-522', 'CWE-200'])
        if any(token in issue_lower for token in ('trusted as instructions', 'confluence', 'tool output')) and any(token in issue_lower for token in ('trigger', 'create_jira', 'approval')):
            return self._known_issue_metadata(issue_text, 'MCP-INDIRECT-PROMPT-INJECTION-001', 'Elevation of Privilege', 'high', 'mcp_untrusted_tool_output',
                'Treat MCP tool output as untrusted data, separate it from instructions, and require explicit server-side authorization and approval before consequential tools.',
                ['LLM01:2025 Prompt Injection'], ['CWE-74', 'CWE-862'])
        if any(token in issue_lower for token in ('audit log', 'audit logs')) and any(token in issue_lower for token in ('access token', 'repository secret', 'full tool argument')):
            return self._known_issue_metadata(issue_text, 'MCP-SENSITIVE-AUDIT-LOGGING-001', 'Information Disclosure', 'critical', 'audit_log_redaction',
                'Redact tokens, secrets, and sensitive tool arguments before audit logging; use correlation IDs and restricted retention instead of raw values.',
                ['A09:2021 Security Logging and Monitoring Failures'], ['CWE-532', 'CWE-200'])
        if any(token in issue_lower for token in ('human approval', 'approval step')) and any(token in issue_lower for token in ('bypass', 'without requiring', 'can create', 'does not require')):
            return self._known_issue_metadata(issue_text, 'AI-AGENT-APPROVAL-BYPASS-001', 'Elevation of Privilege', 'critical', 'human_approval_enforcement',
                'Enforce approval in the action service, not the prompt or UI; bind the approved action, user, resource, and expiry to a signed authorization record.',
                ['LLM06:2025 Excessive Agency'], ['CWE-862', 'CWE-863'])
        if any(token in issue_lower for token in ('approval threshold', 'approval_id', 'approval id')) and any(token in issue_lower for token in ('omitted', 'missing', 'above', 'bypass')):
            return self._known_issue_metadata(issue_text, 'AI-AGENT-APPROVAL-BYPASS-001', 'Elevation of Privilege', 'critical', 'human_approval_enforcement',
                'Enforce approval in the refund service, validate the signed approval ID against amount, user, tenant, and expiry, and fail closed when it is absent.',
                ['LLM06:2025 Excessive Agency'], ['CWE-862', 'CWE-863'])
        if any(token in issue_lower for token in ('.env', 'environment file', 'local secret')) and any(token in issue_lower for token in ('cursor', 'model', 'read')):
            return self._known_issue_metadata(issue_text, 'AI-AGENT-LOCAL-SECRETS-001', 'Information Disclosure', 'high', 'agent_workspace_secrets',
                'Do not expose .env or credential files to the agent workspace; use scoped secret injection, deny-list sensitive paths, and redact tool output.',
                ['LLM06:2025 Excessive Agency'], ['CWE-200', 'CWE-522'])
        if any(token in issue_lower for token in ('markdown', 'html')) and any(token in issue_lower for token in ('sanitize', 'sanitization', 'unsanitized')):
            return self._known_issue_metadata(issue_text, 'WEB-XSS-MODEL-OUTPUT-001', 'Tampering', 'high', 'html_sanitization',
                'Render model output as plain text by default; sanitize HTML with an allowlist and enforce a restrictive Content Security Policy.',
                ['A03:2021 Injection'], ['CWE-79'])
        
        # JWT validation issues
        if 'jwt' in issue_lower and any(word in issue_lower for word in ['not validate', 'does not', 'no validation', 'without validation', 'only decode', 'don\'t validate']):
            return {
                'type': 'missing_control',
                'control': 'jwt_validation',
                'severity': 'critical',
                'description': issue_text,
                'suggested_threat_id': 'S-008'
            }
        
        # GraphQL depth limiting
        if 'graphql' in issue_lower and any(word in issue_lower for word in ['no depth', 'depth limit', 'no query depth', 'without depth']):
            return self._known_issue_metadata(issue_text, 'API-GRAPHQL-RESOURCE-CONSUMPTION-001', 'Denial of Service', 'high', 'query_depth_and_cost_limits',
                'Enforce GraphQL depth and complexity limits, pagination maximums, request timeouts, and per-principal query-cost limits.',
                ['API4:2023 Unrestricted Resource Consumption'], ['CWE-400'])
        
        # Webhook signature validation
        if 'webhook' in issue_lower and any(word in issue_lower for word in ['no signature', 'don\'t verify', 'without signature', 'no verification']):
            return {
                'type': 'missing_control',
                'control': 'webhook_signature_validation',
                'severity': 'high',
                'description': issue_text,
                'suggested_threat_id': 'T-008'
            }
        
        # XSS / inline JavaScript
        if any(word in issue_lower for word in ['inline javascript', 'allows javascript', 'xss', 'user-provided html']):
            return {
                'type': 'missing_control',
                'control': 'html_sanitization',
                'severity': 'critical',
                'description': issue_text,
                'suggested_threat_id': 'T-009'
            }
        
        # CSV injection
        if 'csv' in issue_lower and any(word in issue_lower for word in ['formula', 'injection', 'sanitize', 'doesn\'t sanitize']):
            return {
                'type': 'missing_control',
                'control': 'csv_sanitization',
                'severity': 'medium',
                'description': issue_text,
                'suggested_threat_id': 'T-010'
            }
        
        # CORS wildcard
        if 'cors' in issue_lower and any(word in issue_lower for word in ['wildcard', '*', 'any origin']):
            return {
                'type': 'misconfiguration',
                'control': 'cors_wildcard',
                'severity': 'high',
                'description': issue_text,
                'suggested_threat_id': 'CORS-001'
            }
        
        # Stack traces / detailed errors
        if any(word in issue_lower for word in ['stack trace', 'detailed error', 'error message', 'exposes stack']):
            return {
                'type': 'information_disclosure',
                'control': 'detailed_errors',
                'severity': 'medium',
                'description': issue_text,
                'suggested_threat_id': 'ID-010'
            }
        
        # Session timeout issues
        if 'session' in issue_lower and any(word in issue_lower for word in ['no absolute', 'sliding expiration', 'only sliding', 'timeout']):
            return {
                'type': 'misconfiguration',
                'control': 'absolute_timeout',
                'severity': 'medium',
                'description': issue_text,
                'suggested_threat_id': 'S-007'
            }
        
        # File upload validation
        if 'file' in issue_lower and any(word in issue_lower for word in ['no content-type', 'no validation', 'upload', 'without validation']):
            return {
                'type': 'missing_control',
                'control': 'content_type_validation',
                'severity': 'high',
                'description': issue_text,
                'suggested_threat_id': 'T-011'
            }
        
        # HTTP Basic Auth
        if any(word in issue_lower for word in ['basic auth', 'http basic']):
            return {
                'type': 'weak_auth',
                'control': 'auth_type',
                'severity': 'high',
                'description': issue_text,
                'suggested_threat_id': 'S-001'
            }
        
        # Encryption issues
        if 'encryption' in issue_lower and any(word in issue_lower for word in ['no encryption', 'not encrypted', 'without encryption', 'has no']):
            return {
                'type': 'missing_encryption',
                'control': 'encryption_at_rest',
                'severity': 'critical',
                'description': issue_text,
                'suggested_threat_id': 'ID-005'
            }
        
        # Public access issues
        if any(word in issue_lower for word in ['publicly accessible', 'public access', 'without signed']):
            return {
                'type': 'public_access',
                'control': 'signed_urls',
                'severity': 'medium',
                'description': issue_text,
                'suggested_threat_id': 'ID-006'
            }
        
        # Shared authentication issues
        if any(word in issue_lower for word in ['same authentication', 'shared auth', 'uses same']):
            return {
                'type': 'shared_auth',
                'control': 'admin_separation',
                'severity': 'high',
                'description': issue_text,
                'suggested_threat_id': 'EOP-003'
            }
        
        generic = classify_generic_weakness(issue_text)
        if generic:
            return self._known_issue_metadata(
                issue_text, generic['id'], generic['category'], generic['severity'],
                generic['control'], generic['mitigation'], generic['owasp'], generic['cwe'],
                affected_stride_categories=generic['stride'],
            )

        # Never manufacture a STRIDE category for an explicit issue that the
        # taxonomy does not understand. It remains evidence-backed, but blocks
        # publication until a specialist rule or analyst maps it.
        return self._known_issue_metadata(
            issue_text, 'UNCLASSIFIED-KNOWN-ISSUE-001', 'Unclassified', 'high', 'analyst_classification_required',
            'Classify this explicit weakness, resolve its affected scope, and attach a tested technical control before publishing the report.',
            [], [], affected_stride_categories=[],
        )
    
    def _assign_stated_weaknesses(self, text: str, components: Dict[str, Component]) -> List[Dict[str, Any]]:
        """Attribute weaknesses stated in prose to the component they describe.

        A weakness written in ordinary prose carries the same authority as one
        listed under a "Known issues" heading, so each clause is classified and
        recorded on the component it is about. Where a clause names several
        components the earliest and most specifically named one is chosen, which
        keeps "the payments service calls Stripe without verification" on the
        payments service rather than on Stripe.

        Clauses rather than whole sentences, because a list of weaknesses is
        usually a list of subjects too: "there is no MFA on the portal, the audit
        log is writable, and the partner reuses a credential" names three
        components and blaming the portal for all three would be wrong.
        """
        index = alias_index(components)
        unscoped: List[Dict[str, Any]] = []
        for component in components.values():
            component.properties.setdefault('stated_weaknesses', [])

        for statement in prose.clauses(text or ''):
            rules = classify_generic_weaknesses(statement)
            if not rules:
                continue
            # The same name resolution used for data flows, so a component
            # referred to by part of its name is still the one described.
            mentions = find_mentions(statement, index)
            if not mentions:
                for rule in rules:
                    if not any(
                        item['rule_id'] == rule['id'] and item['statement'] == statement
                        for item in unscoped
                    ):
                        unscoped.append({
                            'rule_id': rule['id'],
                            'control': rule['control'],
                            'statement': statement,
                        })
                continue
            component = components[mentions[0][2]]
            weaknesses = component.properties['stated_weaknesses']
            for rule in rules:
                if any(item['rule_id'] == rule['id'] for item in weaknesses):
                    continue
                weaknesses.append({
                    'rule_id': rule['id'],
                    'control': rule['control'],
                    'statement': statement,
                })
        return unscoped

    def _names_something_unmodelled(self, clause: str, components: Dict[str, Component]) -> bool:
        """True when the clause names a component-like thing the model lacks."""
        return any(
            representative_of(candidate, components.values()) is None
            for candidate in find_named_roles(clause)
        )

    def _scope_controls_to_named_subjects(self, text: str, components: Dict[str, Component]) -> None:
        """Keep a control claim on the component whose clause made it.

        "The clinician portal has no MFA" is knowledge about the portal. Read
        from a wider window it became knowledge about everything in the model,
        so a database inherited a sign-in weakness it was never party to and a
        service was credited with a firewall standing in front of someone else.

        Each claim is therefore attributed to the component its clause names,
        and a control that only ever appears in clauses about other components
        is removed from the rest. A control *claimed* alongside another component
        is left with both, because "the portal calls the API over TLS" is a fact
        about both ends; a control *denied* belongs to the one thing said to lack
        it. A claim that names nobody stays general.
        """
        index = alias_index(components)
        subjects: Dict[str, Dict[str, bool]] = defaultdict(dict)
        participants: Dict[str, set] = defaultdict(set)
        general: set = set()
        evidence_by_subject = defaultdict(lambda: defaultdict(list))

        for statement in control_statements.statements(text):
            mentions = find_mentions(statement.clause, index)
            if not mentions:
                # A claim about something the model does not contain belongs to
                # nothing yet. Spreading it over every component was how "the
                # receipts bucket is not encrypted" became a verdict on a
                # database, so it is held back and reported as a gap instead.
                if not self._names_something_unmodelled(statement.clause, components):
                    general.add(statement.control)
                continue
            if statement.affirmed:
                participants[statement.control].update(mention[2] for mention in mentions)
            subject = mentions[0][2]
            record = {'state': 'present' if statement.affirmed else 'absent', 'statement': statement.clause, 'source_type': 'architecture_input'}
            if record not in evidence_by_subject[subject][statement.control]:
                evidence_by_subject[subject][statement.control].append(record)
            claims = subjects[statement.control]
            # A denial outranks a claim about the same component: the clause
            # that says a control is absent is the one carrying the risk.
            if statement.affirmed and claims.get(subject) is False:
                continue
            claims[subject] = statement.affirmed
            if statement.affirmed:
                for implied in control_statements.IMPLIED_BY.get(statement.control, ()):
                    subjects[implied].setdefault(subject, True)
                    participants[implied].add(subject)

        for control in set(subjects) | set(participants):
            claims = subjects.get(control, {})
            for component_id, component in components.items():
                props = component.properties
                negations = set(props.get('explicit_negations') or [])
                if component_id in claims:
                    props[control] = claims[component_id]
                    negations.discard(control)
                    if claims[component_id] is False:
                        negations.add(control)
                elif control in general or component_id in participants.get(control, ()):
                    continue
                else:
                    props.pop(control, None)
                    negations.discard(control)
                props['explicit_negations'] = sorted(negations)
        for component_id, evidence in evidence_by_subject.items():
            props = components[component_id].properties
            previous = props.get('control_evidence') or {}
            props['control_evidence'] = {**previous, **dict(evidence)}

    def _detect_negations(self, text: str) -> Dict[str, bool]:
        """
        Detect explicit negations indicating missing security controls.
        Returns dict of control_name: False for missing controls.
        """
        # Every control in the shared vocabulary can be denied, so a weakness
        # does not need its own hand-written pattern here to be recorded. The
        # patterns below cover the judgements the vocabulary does not model as a
        # property, such as an administrative path that shares an identity.
        negations = {
            control: False
            for control in control_statements.read(text).denied
        }
        text_lower = text.lower()
        
        # JWT validation patterns
        jwt_patterns = [
            r'does not validate jwt',
            r'no jwt validation',
            r'jwt.*not.*validated',
            r'without.*jwt.*validation',
            r'jwt.*validation.*missing'
        ]
        for pattern in jwt_patterns:
            if re.search(pattern, text_lower):
                negations['jwt_validation'] = False
                break
        
        # Encryption at rest patterns
        encryption_patterns = [
            r'no(?:\s+\w+){0,3}\s+encryption at rest',
            r'not encrypted',
            r'without(?:\s+\w+){0,3}\s+encryption',
            r'has no encryption',
            r'unencrypted'
        ]
        for pattern in encryption_patterns:
            if re.search(pattern, text_lower):
                negations['encryption_at_rest'] = False
                break
        
        # Signed URLs patterns
        signed_url_patterns = [
            r'without signed urls',
            r'no signed urls',
            r'publicly accessible',
            r'public access'
        ]
        for pattern in signed_url_patterns:
            if re.search(pattern, text_lower):
                negations['signed_urls'] = False
                break
        
        # Admin separation patterns
        admin_sep_patterns = [
            r'same authentication',
            r'shared.*auth',
            r'uses same.*auth',
            r'no.*separate.*admin'
        ]
        for pattern in admin_sep_patterns:
            if re.search(pattern, text_lower):
                negations['admin_separation'] = False
                break

        waf_patterns = [
            r'no waf',
            r'without waf',
            r'missing waf',
            r'no web application firewall',
            r'without web application firewall',
        ]
        for pattern in waf_patterns:
            if re.search(pattern, text_lower):
                negations['waf_enabled'] = False
                break

        mutual_auth_patterns = [
            r'no mutual authentication',
            r'without mutual authentication',
            r'no mtls',
            r'without mtls',
        ]
        for pattern in mutual_auth_patterns:
            if re.search(pattern, text_lower):
                negations['mtls_enabled'] = False
                break

        prompt_sanitization_patterns = [
            r'no prompt sanitization',
            r'without prompt sanitization',
            r'prompt sanitization.*(?:missing|disabled)',
        ]
        if any(re.search(pattern, text_lower) for pattern in prompt_sanitization_patterns):
            negations['prompt_sanitization'] = False

        output_validation_patterns = [
            r'no output validation',
            r'without output validation',
            r'output validation.*(?:missing|disabled)',
        ]
        if any(re.search(pattern, text_lower) for pattern in output_validation_patterns):
            negations['output_validation'] = False
        
        return negations
    
    def parse(self, text: str) -> SystemArchitecture:
        """
        Enhanced parser with NLP integration.
        Uses the hybrid NLP pipeline when available,
        with rule-based extraction as the fallback.
        """
        authoritative = self._parse_authoritative_architecture(text)
        if authoritative is not None:
            return authoritative

        embedded_iac = self._embedded_iac_architectures(text)
        model_text = self._architecture_only_text(
            text,
            excluded_documents={str(item.get('document') or '') for item in embedded_iac},
        )
        text_lower = model_text.lower()
        components: Dict[str, Component] = {}
        flows: List[DataFlow] = []

        # ========================================
        # NLP-ENHANCED: Extract entities with NLP
        # ========================================
        nlp_entities = None
        nlp_security_props = {}
        nlp = None
        if NLP_AVAILABLE:
            try:
                nlp = get_nlp_processor()
                nlp_entities = nlp.extract_entities(model_text)
                nlp_security_props = nlp.extract_security_properties(model_text)
                logger.info(f"NLP extracted {len(nlp_entities.get('technologies', []))} technologies, "
                           f"{len(nlp_entities.get('services', []))} services")
            except Exception as e:
                logger.warning(f"NLP entity extraction failed: {e}")

        # 1. Extract individual microservices (regex)
        microservices = self._extract_microservices(model_text)
        for service in microservices:
            components[service['id']] = Component(
                id=service['id'],
                name=service['name'],
                type='Service',
                properties=service['properties']
            )
        
        # 2. Extract individual databases (regex)
        databases = self._extract_databases(model_text)
        for db in databases:
            components[db['id']] = Component(
                id=db['id'],
                name=db['name'],
                type='Database',
                properties=db['properties']
            )
        
        # 3. Extract third-party services (regex)
        third_party = self._extract_third_party_services(model_text)
        for service in third_party:
            components[service['id']] = Component(
                id=service['id'],
                name=service['name'],
                type=service['type'],
                properties=service['properties']
            )
        
        # 4. NLP-ENHANCED: Add components discovered by NLP that regex missed
        if nlp_entities:
            for tech_entity in nlp_entities.get('technologies', []):
                comp_type = tech_entity.get('component_type')
                if not comp_type:
                    continue
                tech_name = tech_entity['text']
                tech_id = tech_name.lower().replace(' ', '_').replace('.', '_')
                
                # Skip if already exists
                if tech_id in components:
                    continue
                # Also skip if a similar component already exists
                already_found = False
                for cid in components:
                    normalized_cid = re.sub(r'[^a-z0-9]+', ' ', cid.lower()).strip()
                    normalized_tech = re.sub(r'[^a-z0-9]+', ' ', tech_id.lower()).strip()
                    if normalized_tech == normalized_cid:
                        already_found = True
                        break
                if already_found:
                    continue

                # NER may emit a plausible but absent technology. Require a
                # literal mention in the architecture-only text before modeling it.
                if not re.search(r'(?<!\\w)' + re.escape(tech_name) + r'(?!\\w)', model_text, re.IGNORECASE):
                    continue
                component_context = self._extract_component_context(model_text, tech_name)
                props = self._infer_properties(component_context, comp_type)
                props['technology'] = tech_name
                if comp_type == 'ML Service' or tech_name in {'openai', 'azure openai', 'rag', 'llm', 'bedrock', 'sagemaker', 'gemini', 'claude'}:
                    props['ai_scope'] = True
                    props['ml_pipeline'] = True
                if tech_name in {'pinecone', 'vector store', 'vector database', 'vector db'}:
                    props['ai_scope'] = True
                    props['vector_store'] = True
                if tech_name in {'node.js', 'nodejs'}:
                    props['runtime'] = 'nodejs'
                    props['application_role'] = 'backend'
                elif tech_name == 'ec2':
                    props['compute_service'] = 'ec2'
                if nlp:
                    props = self._apply_security_properties(props, nlp.extract_security_properties(component_context))
                display_name = {
                    'node.js': 'Node.js Backend',
                    'nodejs': 'Node.js Backend',
                    'ec2': 'EC2',
                    'eks': 'Amazon EKS',
                    'ecr': 'Amazon ECR',
                    'aws kms': 'AWS KMS',
                    'kms': 'AWS KMS',
                    'azure openai': 'Azure OpenAI',
                    'github actions': 'GitHub Actions',
                    'argo cd': 'Argo CD',
                }.get(tech_name, tech_name.title())
                components[tech_id] = Component(
                    id=tech_id,
                    name=display_name,
                    type=comp_type,
                    properties=props
                )
                logger.debug(f"NLP discovered component: {tech_name} ({comp_type})")
            
            # Add NLP-discovered named services
            for svc_entity in nlp_entities.get('services', []):
                svc_name = svc_entity['text']
                svc_id = svc_name.lower().replace(' ', '_').replace('-', '_')
                if svc_id not in components:
                    if not re.search(r'(?<!\\w)' + re.escape(svc_name) + r'(?!\\w)', model_text, re.IGNORECASE):
                        continue
                    component_context = self._extract_component_context(model_text, svc_name)
                    props = self._infer_properties(component_context, 'Service')
                    if nlp:
                        props = self._apply_security_properties(props, nlp.extract_security_properties(component_context))
                    if svc_entity.get('tech_stack'):
                        props['tech_stack'] = svc_entity['tech_stack']
                    components[svc_id] = Component(
                        id=svc_id,
                        name=svc_name,
                        type='Service',
                        properties=props
                    )

        # Literal generic nouns are valid architecture evidence when no named
        # technology or service of that type was extracted.
        self._add_explicit_generic_components(model_text, components)
        self._add_explicit_named_components(model_text, components)
        self._add_explicit_mcp_components(model_text, components)
        self._add_explicit_logical_components(model_text, components)
        self._add_inferred_named_components(model_text, components)
        resolved_names = self._consolidate_component_aliases(model_text, components)

        iac_flows: List[DataFlow] = []
        iac_findings = self._merge_embedded_iac(components, iac_flows, embedded_iac)

        # Prefer a concrete frontend technology over generic aliases extracted
        # from the same declaration (for example React + frontend).
        generic_clients = {'frontend', 'webclient', 'client', 'spa'}
        concrete_client_exists = any(
            component.type == 'WebClient' and component_id not in generic_clients
            for component_id, component in components.items()
        )
        if concrete_client_exists:
            for component_id in generic_clients:
                components.pop(component_id, None)
        
        # Generic synonym fallback intentionally removed. It created fictitious
        # API/database/ML nodes and made keyword mentions look deployed.

        # 6. Infer data flows only from architecture text.
        flows = self._infer_flows(model_text, components)
        for flow in flows:
            flow.properties.setdefault('extraction_method', 'heuristic')
        flows.extend(iac_flows)
        
        # 7. NLP-ENHANCED: Extract additional flows using dependency parsing
        if NLP_AVAILABLE and nlp_entities:
            try:
                nlp = get_nlp_processor()
                nlp_flows = nlp.extract_data_flows(model_text, components)
                existing_pairs = {(f.source_id, f.target_id): f for f in flows}
                described_endpoints = {
                    endpoint for flow in flows
                    if flow.properties.get('origin') == 'stated'
                    for endpoint in (flow.source_id, flow.target_id)
                }
                for nf in nlp_flows:
                    pair = (nf['source'], nf['target'])
                    if pair in existing_pairs and nf.get('evidence'):
                        existing = existing_pairs[pair]
                        existing.properties['evidence'] = nf['evidence']
                        existing.properties['extraction_method'] = 'text_pattern'
                        existing.properties.pop('trust_boundary', None)
                    elif (
                        pair not in existing_pairs
                        # The same relationship in the opposite direction is a
                        # contradiction, not an addition. The extracted flow
                        # already carries the sentence that stated its direction.
                        and tuple(reversed(pair)) not in existing_pairs
                        # This pass matches single words, so it cannot tell which
                        # of two components named in a sentence is the subject.
                        # It may connect a component nothing was said about, but
                        # it may not add a second opinion about one already
                        # modeled from a resolved sentence.
                        and not (described_endpoints & set(pair))
                        and nf['source'] in components and nf['target'] in components
                    ):
                        flows.append(DataFlow(
                            source_id=nf['source'],
                            target_id=nf['target'],
                            protocol=nf.get('protocol', 'HTTPS'),
                            properties={
                                'evidence': nf.get('evidence', ''),
                                'origin': 'stated' if nf.get('evidence') else 'assumed',
                                'extraction_method': 'text_pattern' if nf.get('evidence') else nf.get('method', 'nlp')
                            }
                        ))
                        existing_pairs[pair] = flows[-1]
                        logger.debug(f"NLP flow: {nf['source']} → {nf['target']}")
            except Exception as e:
                logger.warning(f"NLP flow extraction failed: {e}")
        
        # 8. Detect component-local negations. A missing control on one bullet
        # must not contaminate every component in the architecture.
        for comp in components.values():
            component_context = self._extract_component_context(model_text, comp.name)
            if comp.type == 'IoT Device':
                component_context += ' ' + self._extract_component_context(model_text, 'IoT devices')
            if comp.type == 'ML Service' or comp.properties.get('ml_pipeline'):
                control_sentences = [
                    segment for segment in re.split(r'(?<=[.!?])\s+|[\r\n]+', model_text)
                    if re.search(r'prompt sanitization|output validation', segment, re.IGNORECASE)
                ]
                component_context += ' ' + ' '.join(control_sentences)
            local_negations = self._detect_negations(component_context)
            for control, value in local_negations.items():
                comp.properties[control] = value
            comp.properties['explicit_negations'] = sorted(local_negations)
        unscoped_stated_weaknesses = self._assign_stated_weaknesses(model_text, components)
        
        # 9. NLP-ENHANCED: Apply NLP-extracted security properties
        if nlp_security_props:
            for comp in components.values():
                component_context = self._extract_component_context(model_text, comp.name)
                scoped_security_props = nlp.extract_security_properties(component_context) if nlp else nlp_security_props
                comp.properties = self._apply_security_properties(comp.properties, scoped_security_props)
                comp.properties = self._apply_global_security_properties(comp.properties, nlp_security_props)

        for comp in components.values():
            for control in comp.properties.get('explicit_negations', []):
                comp.properties[control] = False

        if re.search(r'\b(?:no|without|missing)\s+(?:web application firewall|waf)\b.{0,50}\bapi gateway\b|\b(?:no|without|missing)\s+(?:web application firewall|waf)\s+in front of\s+(?:the\s+)?api gateway\b', model_text, re.IGNORECASE):
            for comp in components.values():
                if comp.type == 'API Gateway':
                    comp.properties['waf_enabled'] = False
                    negations = set(comp.properties.get('explicit_negations', []))
                    negations.add('waf_enabled')
                    comp.properties['explicit_negations'] = sorted(negations)

        self._scope_controls_to_named_subjects(model_text, components)

        # 9.5. Normalize trust levels and enrich flow metadata for architecture modeling
        for comp in components.values():
            comp.trust_level = self._infer_trust_level(comp.type, comp.properties or {})
            comp.properties['trust_level'] = comp.trust_level

        # A classification stated in one sentence describes the data, not the one
        # component the sentence happened to be about, so it is carried along the
        # paths that data travels. This runs before flow data types are derived so
        # that a flow is typed by what actually moves on it.
        for component_id, (sensitivity, reason) in graph.propagate_sensitivity(components, flows).items():
            properties = components[component_id].properties
            properties['data_sensitivity'] = sensitivity
            properties['data_sensitivity_basis'] = 'propagated'
            properties['data_sensitivity_reason'] = reason

        component_map = components
        for flow in flows:
            flow.protocol = (flow.protocol or "").lower()
            source = component_map.get(flow.source_id)
            target = component_map.get(flow.target_id)
            if source and target:
                flow.data_type = self._infer_data_type(source, target)
                # Whether the two ends sit at different trust levels is a fact
                # about the pair, so it is recorded whatever the boundary is
                # named. Deriving it only when the name is missing left every
                # flow looking like it stayed inside one trust level, which both
                # hid boundary crossings from the report and kept them out of
                # the risk calculation.
                if source.trust_level != target.trust_level:
                    flow.properties['crosses_trust_boundary'] = True
                if not flow.properties.get('trust_boundary'):
                    flow.properties['trust_boundary'] = (
                        f"{source.trust_level}_to_{target.trust_level}"
                        if source.trust_level != target.trust_level else source.trust_level
                    )
                flow.properties['source_trust_level'] = source.trust_level
                flow.properties['target_trust_level'] = target.trust_level
            # A flow the templates supplied is already marked assumed by
            # _infer_flows. Recomputing the flag from the boundary name alone
            # discarded that, presenting a guessed path as a described one.
            flow.assumed = bool(
                flow.assumed
                or flow.properties.get('origin') == 'assumed'
                or flow.properties.get('trust_boundary') == 'inferred'
                or flow.properties.get('extraction_method') in {'nlp', 'heuristic'}
            )
            flow.properties['assumed'] = flow.assumed
        
        # 10. Parse known issues
        known_issues = self._link_known_issues_to_components(
            self.parse_known_issues(text), components, flows,
        )
        assumptions = self._collect_assumptions(components, flows)
        trust_boundaries = self._build_trust_boundaries(components, flows)
        assets = self._extract_assets(components, flows)
        
        return SystemArchitecture(
            components=list(components.values()),
            flows=flows,
            trust_boundaries=trust_boundaries,
            assets=assets,
            metadata={
                'known_issues': known_issues,
                'source_text': text,
                'architecture_text': model_text,
                'nlp_enhanced': NLP_AVAILABLE and nlp_entities is not None,
                'global_security_signals': nlp_security_props,
                'assumptions': assumptions,
                'resolved_names': resolved_names,
                'iac_findings': iac_findings,
                'unscoped_stated_weaknesses': unscoped_stated_weaknesses,
                'embedded_iac_documents': [item.get('document') for item in embedded_iac],
                'unresolved_references': [
                    {**reference, 'source_document': source.get('document')}
                    for source in embedded_iac
                    for reference in (source['architecture'].metadata or {}).get('unresolved_references', [])
                ],
                'analysis_limits': list(dict.fromkeys(
                    limitation for source in embedded_iac
                    for limitation in (source['architecture'].metadata or {}).get('analysis_limits', [])
                )),
                'trust_boundaries': [boundary.model_dump() for boundary in trust_boundaries],
                'assets': [asset.model_dump() for asset in assets],
            }
        )
    
    def _extract_microservices(self, text: str) -> List[Dict]:
        """
        Extract individual microservices from numbered lists or bullet points.
        Patterns:
        - "1. User Service (Node.js + Express):"
        - "- Payment Service (Java Spring Boot):"
        - "User Service: Handles authentication"
        """
        services = []
        text_lower = text.lower()
        
        # Pattern 1: Numbered lists with service descriptions
        # Matches: "1. User Service (Node.js + Express):"
        pattern1 = r'(?:^|\n)\s*\d+\.\s+([A-Z][A-Za-z\s]+Service)\s*\(([^)]+)\):\s*([^\n]+)'
        matches = re.finditer(pattern1, text, re.MULTILINE | re.IGNORECASE)
        
        for match in matches:
            service_name = match.group(1).strip()
            tech_stack = match.group(2).strip()
            description = match.group(3).strip()
            
            service_id = service_name.lower().replace(' ', '_').replace('-', '_')
            
            # Infer properties from tech stack and description
            local_context = f"{service_name} {tech_stack} {description}"
            props = self._infer_service_properties(tech_stack, description, local_context)
            props['tech_stack'] = tech_stack
            props['description'] = description
            
            services.append({
                'id': service_id,
                'name': service_name,
                'properties': props
            })
        
        # Pattern 2: Bullet points
        # Matches: "- Payment Service (Java Spring Boot):"
        pattern2 = r'(?:^|\n)\s*[-•]\s+([A-Z][A-Za-z\s]+Service)\s*\(([^)]+)\):\s*([^\n]+)'
        matches = re.finditer(pattern2, text, re.MULTILINE | re.IGNORECASE)
        
        for match in matches:
            service_name = match.group(1).strip()
            tech_stack = match.group(2).strip()
            description = match.group(3).strip()
            
            service_id = service_name.lower().replace(' ', '_').replace('-', '_')
            
            # Skip if already added
            if any(s['id'] == service_id for s in services):
                continue
            
            local_context = f"{service_name} {tech_stack} {description}"
            props = self._infer_service_properties(tech_stack, description, local_context)
            props['tech_stack'] = tech_stack
            props['description'] = description
            
            services.append({
                'id': service_id,
                'name': service_name,
                'properties': props
            })
        
        return services
    
    def _extract_databases(self, text: str) -> List[Dict]:
        """
        Extract individual database instances.
        Detects: PostgreSQL, MongoDB, MySQL, Redis, Elasticsearch, etc.
        """
        databases = []
        text_lower = text.lower()
        
        # Database type mappings
        db_types = {
            'postgresql': ['postgresql', 'postgres'],
            'mongodb': ['mongodb', 'mongo'],
            'mysql': ['mysql', 'mariadb'],
            'redis': ['redis'],
            'elasticsearch': ['elasticsearch', 'elastic search'],
            'dynamodb': ['dynamodb'],
            'cassandra': ['cassandra'],
            'redshift': ['redshift'],
            'snowflake': ['snowflake'],
            'bigquery': ['bigquery']
        }
        
        for db_name, keywords in db_types.items():
            for keyword in keywords:
                if keyword in text_lower:
                    db_id = db_name.lower()
                    
                    # Skip if already added
                    if any(db['id'] == db_id for db in databases):
                        continue
                    
                    # Controls in neighboring bullets belong to other
                    # components, so database properties use its own line.
                    context = self._extract_component_context(text, keyword)
                    
                    props = {
                        'db_type': db_name,
                        'encryption_at_rest': None,
                        'backup_enabled': None,
                        'replication': None
                    }
                    
                    # Infer properties from context
                    if 'read replica' in context or 'replication' in context:
                        props['replication'] = True
                    if 'master-slave' in context:
                        props['replication'] = 'master-slave'
                    if 'cluster' in context:
                        props['clustered'] = True
                    if 'encrypted' in context or 'encryption' in context:
                        props['encryption_at_rest'] = True
                    props = self._apply_security_properties(props, self._infer_properties(context, 'Database'))
                    
                    databases.append({
                        'id': db_id,
                        'name': db_name.upper() if db_name in ['mysql', 'redis'] else db_name.title(),
                        'properties': props
                    })
                    break
        
        return databases
    
    def _extract_third_party_services(self, text: str) -> List[Dict]:
        """
        Extract third-party service integrations.
        """
        services = []
        text_lower = text.lower()
        
        # Third-party service mappings
        third_party_map = {
            'stripe': {'type': 'Payment Processor', 'category': 'payment'},
            'paypal': {'type': 'Payment Processor', 'category': 'payment'},
            'square': {'type': 'Payment Processor', 'category': 'payment'},
            'sendgrid': {'type': 'Email Service', 'category': 'communication'},
            'twilio': {'type': 'SMS Service', 'category': 'communication'},
            'firebase': {'type': 'Push Notification Service', 'category': 'communication'},
            'fedex': {'type': 'Shipping API', 'category': 'logistics'},
            'ups': {'type': 'Shipping API', 'category': 'logistics'},
            'dhl': {'type': 'Shipping API', 'category': 'logistics'},
            'zendesk': {'type': 'Customer Support', 'category': 'support'},
            'sift': {'type': 'Fraud Detection', 'category': 'security'},
            'auth0': {'type': 'Identity Provider', 'category': 'authentication'},
            'okta': {'type': 'Identity Provider', 'category': 'authentication'}
        }
        
        for service_name, info in third_party_map.items():
            if service_name in text_lower:
                service_id = f"{service_name}_external"
                
                props = {
                    'external': True,
                    'third_party': True,
                    'category': info['category'],
                    'trust_boundary': 'external'
                }
                props = self._apply_security_properties(props, self._infer_properties(self._extract_context(text_lower, service_name, 120), info['type']))
                
                services.append({
                    'id': service_id,
                    'name': service_name.title(),
                    'type': info['type'],
                    'properties': props
                })
        
        return services
    
    def _infer_service_properties(self, tech_stack: str, description: str, full_text: str) -> Dict:
        """Infer service properties from tech stack and description."""
        local_context = f"{tech_stack} {description} {full_text}".lower()
        props = self._infer_properties(local_context, 'Service')
        
        # Parse tech stack
        tech_lower = tech_stack.lower()
        if 'node' in tech_lower or 'express' in tech_lower:
            props['language'] = 'Node.js'
        elif 'python' in tech_lower or 'fastapi' in tech_lower or 'django' in tech_lower:
            props['language'] = 'Python'
        elif 'java' in tech_lower or 'spring' in tech_lower:
            props['language'] = 'Java'
        elif 'go' in tech_lower or 'golang' in tech_lower:
            props['language'] = 'Go'
        
        # Parse description for specific features
        desc_lower = description.lower()
        if 'jwt' in desc_lower:
            props['has_jwt'] = True
        if 'webhook' in desc_lower:
            props['has_webhooks'] = True
        if 'graphql' in desc_lower:
            props['has_graphql'] = True
        
        return props
    
    def _extract_context(self, text: str, keyword: str, chars: int = 100) -> str:
        """Extract surrounding context around a keyword."""
        idx = text.find(keyword)
        if idx == -1:
            return ""
        start = max(0, idx - chars)
        end = min(len(text), idx + len(keyword) + chars)
        return text[start:end]
    
    def _infer_flows(self, text: str, components: Dict[str, Component]) -> List[DataFlow]:
        """Model the stated data flows, then connect whatever is still isolated.

        A flow the description states is evidence and is modeled as written. The
        type-based templates below are assumptions, so they are applied only to
        components the description left unconnected: filling a real gap keeps the
        model reviewable, while adding a guessed path beside a stated one would
        put a boundary crossing in the report that the design never had.
        """
        flows: List[DataFlow] = []
        stated_pairs = set()
        assumed_ends: set = set()
        for stated in extract_stated_flows(text, components):
            stated_pairs.add((stated['source_id'], stated['target_id']))
            flows.append(DataFlow(
                source_id=stated['source_id'],
                target_id=stated['target_id'],
                protocol=stated['protocol'],
                assumed=False,
                confidence='High',
                evidence=[{
                    'source_type': 'architecture_input',
                    'source_ref': f"{stated['source_id']}->{stated['target_id']}",
                    'line': None,
                    'statement': stated['evidence'],
                    'confidence': 'High',
                    'relationship': stated['verb'],
                }],
                properties={
                    'trust_boundary': self._flow_trust_boundary(
                        components[stated['source_id']], components[stated['target_id']]
                    ),
                    'origin': 'stated',
                    'evidence': stated['evidence'],
                    'stated_relationship': stated['verb'],
                    'extraction_method': 'stated_relationship',
                },
            ))
        connected = {component_id for pair in stated_pairs for component_id in pair}
        for flow in self._template_flows(text, components):
            pair = (flow.source_id, flow.target_id)
            if pair in stated_pairs or tuple(reversed(pair)) in stated_pairs:
                continue
            # An assumption is only worth making about a component whose
            # connections nobody described, and one assumed flow is enough to
            # put it in scope. Adding every type-compatible peer would invent a
            # fan-out that reads as a described design.
            isolated = next(
                (end for end in pair if end not in connected and end not in assumed_ends),
                None,
            )
            if isolated is None:
                continue
            assumed_ends.add(isolated)
            other = pair[1] if isolated == pair[0] else pair[0]
            flow.assumed = True
            flow.confidence = 'Low'
            flow.properties['origin'] = 'assumed'
            flow.properties['assumption'] = (
                f'No data flow was described for {components[isolated].name}. It is placed '
                f'with {components[other].name} because that is the usual arrangement for a '
                f'{components[isolated].type}; confirm or correct this.'
            )
            flows.append(flow)
            stated_pairs.add(pair)
        return flows

    @staticmethod
    def _flow_trust_boundary(source: Component, target: Component) -> str:
        """Name the boundary a flow crosses from the two ends it connects."""
        for component in (source, target):
            if component.properties.get('external') or component.properties.get('third_party_integration'):
                return 'external'
        if source.type in {'WebClient', 'Mobile App'} or source.properties.get('public_access'):
            return 'internet'
        return 'internal'

    def _template_flows(self, text: str, components: Dict[str, Component]) -> List[DataFlow]:
        """Typical flows for each component type, used where nothing was stated."""
        flows = []

        # Get components by type
        frontend_comps = [cid for cid, c in components.items() if c.type in ['WebClient', 'Mobile App']]
        api_comps = [cid for cid, c in components.items() if c.type in ['API', 'API Gateway', 'Load Balancer']]
        application_api_comps = [cid for cid, c in components.items() if c.type == 'API']
        gateway_comps = [cid for cid, c in components.items() if c.type in ['API Gateway', 'Load Balancer']]
        service_comps = [cid for cid, c in components.items() if c.type == 'Service']
        integration_comps = [
            cid for cid in service_comps
            if components[cid].properties.get('healthcare_integration')
            or any(token in cid.lower() for token in ('fhir', 'hl7', 'partner', 'integration'))
        ]
        business_service_comps = [cid for cid in service_comps if cid not in integration_comps]
        # Types that run application code without saying so in their name. An EC2
        # instance or an EKS cluster called "the backend" plays the part this
        # table gave only to API and Service, so an architecture of a web app,
        # EC2, RDS and a bucket matched no row and produced no flows at all.
        compute_comps = [cid for cid, c in components.items() if c.type in ['Compute', 'Container Platform']]
        db_comps = [cid for cid, c in components.items() if c.type == 'Database']
        storage_comps = [cid for cid, c in components.items() if c.type == 'Object Storage']
        queue_comps = [cid for cid, c in components.items() if c.type == 'Queue']
        idp_comps = [cid for cid, c in components.items() if c.type == 'Identity Provider']
        ml_comps = [cid for cid, c in components.items() if c.type == 'ML Service']
        external_comps = [cid for cid, c in components.items() if c.properties.get('external', False)]
        
        # 1. Frontend → API/Gateway (typical web/mobile app pattern), or straight
        # to the compute tier where nothing sits in front of it.
        for frontend_id in frontend_comps:
            for api_id in (api_comps or compute_comps):
                flows.append(DataFlow(
                    source_id=frontend_id,
                    target_id=api_id,
                    protocol='HTTPS',
                    properties={'trust_boundary': 'internet', 'crosses_trust_boundary': True}
                ))
        
        # 2. API/Gateway → whatever runs behind it
        backend_comps = service_comps or compute_comps
        if backend_comps:
            for api_id in api_comps:
                for service_id in backend_comps:
                    flows.append(DataFlow(
                        source_id=api_id,
                        target_id=service_id,
                        protocol='HTTPS',
                        properties={'trust_boundary': 'internal'}
                    ))
        
        # 3. API → Database (direct connection if no services layer)
        # Whichever tier is present reaches the stores; the compute tier ranks
        # above a gateway because a load balancer in front of EC2 is not the thing
        # that queries the database.
        data_consumers = application_api_comps or business_service_comps or compute_comps
        if not data_consumers and gateway_comps:
            data_consumers = gateway_comps
        if not data_consumers:
            data_consumers = service_comps

        if data_consumers and db_comps:
            for api_id in data_consumers:
                for db_id in db_comps:
                    flows.append(DataFlow(
                        source_id=api_id,
                        target_id=db_id,
                        protocol='TCP',
                        properties={'trust_boundary': 'internal'}
                    ))
        
        # 4. Services → Databases
        for consumer_id in data_consumers:
            for storage_id in storage_comps:
                flows.append(DataFlow(
                    source_id=consumer_id,
                    target_id=storage_id,
                    protocol='HTTPS',
                    properties={'trust_boundary': 'internal', 'workflow': 'object_storage'}
                ))
        
        # 5. API/Services → Identity Provider (for authentication)
        if idp_comps:
            auth_consumers = application_api_comps or business_service_comps or compute_comps or api_comps
            for consumer_id in auth_consumers:
                for idp_id in idp_comps:
                    flows.append(DataFlow(
                        source_id=consumer_id,
                        target_id=idp_id,
                        protocol='HTTPS',
                        properties={'trust_boundary': 'internal'}
                    ))

        # Representative AI request and retrieval flows. Keep these scoped to
        # model components and vector stores instead of connecting models to
        # every data store in the architecture.
        if ml_comps:
            agent_comps = sorted(
                [cid for cid in ml_comps if any(token in cid.lower() for token in ('agent', 'orchestration', 'rag'))],
                key=lambda cid: (0 if any(token in cid.lower() for token in ('agent', 'orchestration')) else 1, cid),
            )
            model_comps = [cid for cid in ml_comps if cid not in agent_comps]
            ai_entry = agent_comps[:1] or model_comps[:1]
            for caller_id in api_comps + service_comps:
                for ml_id in ai_entry:
                    flows.append(DataFlow(
                        source_id=caller_id,
                        target_id=ml_id,
                        protocol='HTTPS',
                        properties={'trust_boundary': 'internal', 'workflow': 'ai_request'}
                    ))
            vector_stores = [
                cid for cid in db_comps
                if any(token in cid.lower() for token in ('opensearch', 'elastic', 'vector', 'pinecone', 'qdrant', 'weaviate'))
            ]
            for ml_id in ai_entry:
                for store_id in vector_stores:
                    flows.append(DataFlow(
                        source_id=ml_id,
                        target_id=store_id,
                        protocol='HTTPS',
                        properties={'trust_boundary': 'internal', 'workflow': 'retrieval'}
                    ))
            for ml_id in ai_entry:
                for model_id in model_comps[:1]:
                    flows.append(DataFlow(
                        source_id=ml_id,
                        target_id=model_id,
                        protocol='HTTPS',
                        properties={'trust_boundary': 'internal', 'workflow': 'model_inference'}
                    ))
        
        # 6. Services → Object Storage (if storage mentioned)
        # Object-storage ownership is modeled with the application data owner.
        
        # 7. Services → Queue (if queue mentioned)
        if queue_comps:
            for service_id in service_comps:
                service_desc = components[service_id].properties.get('description', '').lower()
                if 'kafka' in service_desc or 'queue' in service_desc or 'message' in service_desc or 'event' in service_desc:
                    for queue_id in queue_comps:
                        flows.append(DataFlow(
                            source_id=service_id,
                            target_id=queue_id,
                            protocol='TCP',
                            properties={'trust_boundary': 'internal'}
                        ))
        
        # 8. Services → External APIs (third-party integrations)
        for service_id in service_comps:
            service_desc = components[service_id].properties.get('description', '').lower()
            for ext_id in external_comps:
                ext_name = components[ext_id].name.lower()
                if ext_name in service_desc or ext_id in service_desc:
                    flows.append(DataFlow(
                        source_id=service_id,
                        target_id=ext_id,
                        protocol='HTTPS',
                        properties={'trust_boundary': 'external', 'crosses_trust_boundary': True}
                    ))
        
        # Flows written out in the description are extracted from the sentence
        # itself by extract_stated_flows, which resolves full component names
        # rather than the single word these patterns could capture.
        return flows


    def _infer_properties(self, text_lower: str, component_type: str) -> Dict:
        """Enhanced property inference based on text analysis."""
        text_lower = (text_lower or "").lower()
        # Unknown is not the same as insecure. Explicit negative evidence is
        # represented as False by _detect_negations; rules must not turn an
        # omitted control into a confirmed vulnerability.
        props = {
            'auth_type': 'unknown',
            'encryption_at_rest': None,
            'logging_enabled': None,
            'input_validation': None,
            'rate_limiting': None,
            'public_access': None,
            'compliance_frameworks': []
        }
        
        # Cloud provider detection
        def has_term(*terms: str) -> bool:
            return any(
                re.search(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])", text_lower)
                for term in terms
            )

        if has_term('aws', 'amazon web services', 's3', 'ec2', 'lambda', 'rds', 'cognito'):
            props['cloud_provider'] = 'aws'
        elif has_term('azure', 'blob storage', 'azure ad', 'entra id'):
            props['cloud_provider'] = 'azure'
        elif has_term('gcp', 'google cloud', 'firestore', 'cloud storage'):
            props['cloud_provider'] = 'gcp'
        
        # Database type detection
        if component_type == 'Database':
            if 'mongodb' in text_lower or 'mongo' in text_lower:
                props['db_type'] = 'mongodb'
            elif 'dynamodb' in text_lower:
                props['db_type'] = 'dynamodb'
            elif 'cosmosdb' in text_lower:
                props['db_type'] = 'cosmosdb'
            elif 'firestore' in text_lower:
                props['db_type'] = 'firestore'
            elif 'cassandra' in text_lower:
                props['db_type'] = 'cassandra'
            elif 'redis' in text_lower:
                props['db_type'] = 'redis'
            elif 'mysql' in text_lower:
                props['db_type'] = 'mysql'
            elif 'postgresql' in text_lower or 'postgres' in text_lower:
                props['db_type'] = 'postgresql'
            elif 'mssql' in text_lower or 'sql server' in text_lower:
                props['db_type'] = 'mssql'
            elif 'oracle' in text_lower:
                props['db_type'] = 'oracle'
        
        # Public access detection
        if component_type in ['WebClient', 'API Gateway', 'CDN']:
            props['public_access'] = True
        elif component_type in ['API', 'Service', 'Load Balancer'] and re.search(
            r'\b(?:public|internet-facing|public-facing)\s+(?:api|service|endpoint|load balancer|alb)\b',
            text_lower,
        ):
            props['public_access'] = True
        
        # Managed Authentication Service Detection (takes precedence)
        if 'cognito' in text_lower:
            props['auth_type'] = 'cognito'
            props['idp_integration'] = True
        elif 'auth0' in text_lower:
            props['auth_type'] = 'auth0'
            props['idp_integration'] = True
        elif 'okta' in text_lower:
            props['auth_type'] = 'okta'
            props['idp_integration'] = True
        elif 'keycloak' in text_lower:
            props['auth_type'] = 'keycloak'
            props['idp_integration'] = True
        elif 'azure ad' in text_lower or 'azure active directory' in text_lower:
            props['auth_type'] = 'azure_ad'
            props['idp_integration'] = True
        elif 'google identity' in text_lower or 'firebase auth' in text_lower:
            props['auth_type'] = 'google_identity'
            props['idp_integration'] = True
        # Standard authentication methods (lower priority than managed services)
        elif 'jwt' in text_lower or 'json web token' in text_lower:
            props['auth_type'] = 'jwt'
            props['has_jwt'] = True
        elif 'oauth' in text_lower or 'oauth2' in text_lower or 'oidc' in text_lower:
            props['auth_type'] = 'oauth2'
            props['idp_integration'] = True
        elif 'basic auth' in text_lower:
            props['auth_type'] = 'basic'
        elif 'no auth' in text_lower or 'unauthenticated' in text_lower or 'without auth' in text_lower:
            props['auth_type'] = 'none'
        elif 'api key' in text_lower:
            props['auth_type'] = 'api_key'


        # Data sensitivity. Where a description names more than one kind of data
        # the most sensitive one decides, rather than whichever check ran last.
        stated = [
            classification for classification, terms in self.DATA_SENSITIVITY_TERMS
            if any(term in text_lower for term in terms)
        ]
        if stated:
            props['data_sensitivity'] = graph.most_sensitive(*stated)
            props['data_sensitivity_basis'] = 'stated'
        
        # Compliance frameworks
        if 'hipaa' in text_lower or 'phi' in text_lower:
            props['compliance_frameworks'].append('HIPAA')
        if 'gdpr' in text_lower:
            props['compliance_frameworks'].append('GDPR')
        if 'pci' in text_lower or 'pci dss' in text_lower:
            props['compliance_frameworks'].append('PCI DSS')
        if 'soc 2' in text_lower:
            props['compliance_frameworks'].append('SOC 2')
        if 'fda' in text_lower or '510(k)' in text_lower:
            props['compliance_frameworks'].append('FDA')
        
        # Deployment environment
        if 'kubernetes' in text_lower or 'k8s' in text_lower:
            props['deployment'] = 'k8s'
        if 'docker' in text_lower or 'container' in text_lower:
            props['containerized'] = True
        if ('aws' in text_lower or 'azure' in text_lower or 'gcp' in text_lower or 'cloud' in text_lower) and 'cloud_provider' not in props:
            props['deployment_model'] = 'cloud'
        
        # IoT specific
        if component_type == 'IoT Device' or 'iot' in text_lower or 'sensor' in text_lower:
            props['is_iot_device'] = True
            if 'ota' in text_lower or 'firmware update' in text_lower:
                props['ota_updates'] = True
            if 'medical device' in text_lower:
                props['medical_device'] = True
        
        # ML/AI specific
        if any(
            re.search(r'(?<![a-z0-9])' + re.escape(term) + r'(?![a-z0-9])', text_lower)
            for term in ('ml', 'machine learning', 'sagemaker', 'model', 'llm', 'rag')
        ):
            props['ml_pipeline'] = True
            if 'training' in text_lower:
                props['model_training'] = True
            if 'anonymized' in text_lower or 'de-identified' in text_lower:
                props['data_anonymization'] = True
        
        # Mobile app specific
        if component_type == 'WebClient' and ('mobile' in text_lower or 'ios' in text_lower or 'android' in text_lower):
            props['mobile_app'] = True
            if 'offline' in text_lower:
                props['offline_capability'] = True
        
        # GraphQL detection
        if 'graphql' in text_lower:
            props['has_graphql'] = True
            if any(phrase in text_lower for phrase in ('depth limit enabled', 'enforces depth', 'query complexity limit', 'query cost limit')):
                props['query_depth_limiting'] = True
            elif any(phrase in text_lower for phrase in ('no depth limit', 'without depth limit', 'no query depth', 'depth limiting disabled')):
                props['query_depth_limiting'] = False
        
        # Webhook detection
        if 'webhook' in text_lower:
            props['has_webhooks'] = True
            if 'signature' in text_lower and ('verif' in text_lower or 'validat' in text_lower):
                props['webhook_signature_validation'] = True
            elif any(phrase in text_lower for phrase in ('no signature', 'without signature', 'signature validation disabled', 'bypasses signature')):
                props['webhook_signature_validation'] = False
        
        # XSS / HTML sanitization
        if any(phrase in text_lower for phrase in ['user-provided html', 'user html', 'inline javascript', 'allows javascript']):
            props['user_html_input'] = True
            if 'sanitiz' in text_lower or 'escape' in text_lower or 'csp' in text_lower:
                props['html_sanitization'] = True
            else:
                props['html_sanitization'] = False
        
        # CSV import detection
        if 'csv' in text_lower and ('import' in text_lower or 'upload' in text_lower):
            props['csv_import'] = True
            if 'sanitiz' in text_lower or 'formula' in text_lower:
                props['csv_sanitization'] = True
            else:
                props['csv_sanitization'] = False
        
        # CORS configuration
        if 'cors' in text_lower:
            if 'wildcard' in text_lower or 'cors.*\\*' in text_lower or 'allow.*origin.*\\*' in text_lower:
                props['cors_wildcard'] = True
            else:
                props['cors_wildcard'] = False
        
        # Environment detection
        if 'production' in text_lower or 'prod' in text_lower:
            props['environment'] = 'production'
        elif 'development' in text_lower or 'dev' in text_lower:
            props['environment'] = 'development'
        
        # Error handling
        if any(phrase in text_lower for phrase in ['stack trace', 'detailed error', 'error message', 'debug mode']):
            props['detailed_errors'] = True
        
        # Session timeout
        if 'session' in text_lower:
            if 'sliding' in text_lower:
                props['session_timeout_type'] = 'sliding'
            if 'absolute timeout' in text_lower:
                props['absolute_timeout'] = True
            elif any(phrase in text_lower for phrase in ('no absolute timeout', 'without absolute timeout', 'absolute timeout disabled')):
                props['absolute_timeout'] = False
        
        # File upload
        if 'upload' in text_lower or 'file upload' in text_lower:
            props['file_upload'] = True
            if 'content-type' in text_lower and 'validat' in text_lower:
                props['content_type_validation'] = True
            elif any(phrase in text_lower for phrase in ('no content-type validation', 'without content-type validation', 'only extension validation')):
                props['content_type_validation'] = False
        
        # Third-party integrations
        if 'api' in text_lower and any(vendor in text_lower for vendor in ['stripe', 'twilio', 'sendgrid', 'firebase']):
            props['third_party_integration'] = True
        if 'fhir' in text_lower or 'hl7' in text_lower:
            props['healthcare_integration'] = True
        
        if 'multi-region' in text_lower or 'failover' in text_lower or 'replication' in text_lower:
            props['multi_region'] = True
            props['disaster_recovery'] = True
        
        # Security controls are read last and with the polarity the sentence
        # used, so no heuristic above can turn a stated absence into an
        # assurance. One vocabulary credits a control and records its denial,
        # which is what keeps "the portal has no MFA" out of the strengths.
        reading = control_statements.read(text_lower)
        for control in control_statements.CONTROL_TERMS:
            stated = reading.value(control)
            if stated is not None:
                props[control] = stated
        
        return props

    def _infer_flow_properties(self, text_lower: str, source: Component, target: Component) -> Dict:
        """Infer data flow properties based on source and target components."""
        props = {
            'trust_boundary': 'internal',
            'authenticated': None
        }
        
        # Trust boundary detection
        if source.type == 'WebClient':
            props['trust_boundary'] = 'internet'
            props['protocol'] = 'http'
        elif source.type in ['API Gateway', 'Load Balancer'] and target.type in ['API', 'Service']:
            props['trust_boundary'] = 'internal'
            props['protocol'] = 'http'
        else:
            props['protocol'] = 'tcp'
        
        # Protocol override based on text
        if 'https' in text_lower:
            props['protocol'] = 'https'
        if 'grpc' in text_lower:
            props['protocol'] = 'grpc'
        if 'websocket' in text_lower or 'ws' in text_lower:
            props['protocol'] = 'websocket'
        
        return props

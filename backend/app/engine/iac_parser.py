import yaml
import logging
import re
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    import hcl2
except Exception:  # pragma: no cover - dependency is optional for source installs
    hcl2 = None

from app.models import Component, SystemArchitecture, DataFlow
from .iac_security import IaCSecurityAnalyzer
from .terraform_plan import parse_plan

logger = logging.getLogger(__name__)


class _CloudFormationLoader(yaml.SafeLoader):
    """Safe YAML loader that preserves CloudFormation intrinsic functions."""


def _cloudformation_tag(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    key = "Ref" if tag_suffix == "Ref" else f"Fn::{tag_suffix}"
    return {key: value}


_CloudFormationLoader.add_multi_constructor("!", _cloudformation_tag)


def _flatten_kubernetes_documents(documents: List[Any]) -> List[Dict[str, Any]]:
    flattened: List[Dict[str, Any]] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        if document.get("kind") == "List" and isinstance(document.get("items"), list):
            flattened.extend(item for item in document["items"] if isinstance(item, dict))
        else:
            flattened.append(document)
    return flattened

class IaCParser:
    """
    Parses Infrastructure-as-Code (IaC) files like Docker Compose and Kubernetes manifests.
    Extracts components, properties, and relationships to feed into the ThreatAnalyzer.
    """
    
    def __init__(self):
        self.security_analyzer = IaCSecurityAnalyzer()
        
    def parse(self, iac_content: str, format_hint: str = 'auto', filename: str = '') -> SystemArchitecture:
        """
        Parse an IaC file and return a SystemArchitecture object.
        """
        if not iac_content or not iac_content.strip():
            raise ValueError("Empty IaC content provided")

        try:
            detected_format = self.detect_format(iac_content, filename, format_hint)
            if detected_format == 'terraform-plan':
                return parse_plan(json.loads(iac_content), self.security_analyzer)
            if detected_format == 'terraform':
                architecture = self._parse_terraform(iac_content)
                return self._attach_security_findings(architecture, iac_content, 'terraform')

            if detected_format == 'arm':
                document = json.loads(iac_content)
                architecture = self._parse_arm(document)
                return self._attach_security_findings(architecture, iac_content, 'arm', [document])

            if detected_format in {'bicep', 'pulumi', 'ci', 'kustomize', 'helm-values'}:
                architecture = self._parse_source_iac(iac_content, detected_format, filename)
                return self._attach_security_findings(architecture, iac_content, detected_format)

            yaml_content = self._render_helm_placeholders(iac_content) if detected_format == 'helm' else iac_content

            # Safely parse YAML (handles multi-document streams like K8s)
            documents = list(yaml.load_all(yaml_content, Loader=_CloudFormationLoader))
            
            # Determine format
            is_compose = False
            is_k8s = False
            is_cloudformation = False
            
            if detected_format == 'docker-compose':
                is_compose = True
            elif detected_format in {'kubernetes', 'helm'}:
                is_k8s = True
            elif detected_format == 'cloudformation':
                is_cloudformation = True
            else:
                # Auto-detect
                if not documents or not documents[0]:
                    raise ValueError("Invalid YAML content")
                    
                doc = documents[0]
                if isinstance(doc, dict):
                    if 'apiVersion' in doc and 'kind' in doc:
                        is_k8s = True
                    elif 'services' in doc or 'version' in doc:
                        is_compose = True
                    elif 'Resources' in doc or 'AWSTemplateFormatVersion' in doc:
                        is_cloudformation = True
            
            if is_compose:
                architecture = self._parse_docker_compose(documents[0] if documents else {})
            elif is_k8s:
                documents = _flatten_kubernetes_documents(documents)
                architecture = self._parse_kubernetes(documents)
            elif is_cloudformation:
                architecture = self._parse_cloudformation(documents[0] if documents else {})
            else:
                raise ValueError("Could not determine the IaC format. Supported formats are Compose, Kubernetes/Helm, Terraform, CloudFormation, ARM, Bicep, Pulumi, and CI pipelines.")

            return self._attach_security_findings(architecture, iac_content, detected_format, documents)
                
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}")
            raise ValueError(f"Invalid YAML format: {str(e)}")
        except Exception as e:
            logger.error(f"IaC parsing error: {e}")
            raise ValueError(f"Failed to parse IaC: {str(e)}")

    @staticmethod
    def _looks_like_terraform(iac_content: str) -> bool:
        return bool(re.search(r'^\s*(?:resource|module|provider|terraform)\s+"', iac_content, re.MULTILINE))

    @classmethod
    def detect_format(cls, content: str, filename: str = '', format_hint: str = 'auto') -> str:
        hint = (format_hint or 'auto').lower().strip()
        aliases = {
            'docker_compose': 'docker-compose', 'compose': 'docker-compose',
            'k8s': 'kubernetes', 'cfn': 'cloudformation', 'arm-template': 'arm',
            'github-actions': 'ci', 'gitlab-ci': 'ci', 'jenkins': 'ci',
        }
        hint = aliases.get(hint, hint)
        if hint != 'auto':
            return hint

        path = Path(filename.lower()) if filename else None
        name = path.name if path else ''
        suffix = path.suffix if path else ''
        if suffix in {'.tf', '.hcl', '.tfvars'} or cls._looks_like_terraform(content):
            return 'terraform'
        if suffix == '.bicep':
            return 'bicep'
        if name in {'kustomization.yml', 'kustomization.yaml'}:
            return 'kustomize'
        if name in {'values.yml', 'values.yaml'} or name.endswith(('.values.yml', '.values.yaml')):
            return 'helm-values'
        if name in {'jenkinsfile', '.gitlab-ci.yml', '.gitlab-ci.yaml'} or '.github/workflows' in filename.replace('\\', '/').lower():
            return 'ci'
        if suffix in {'.ts', '.js', '.py', '.go', '.cs'} and re.search(
            r'(?:@pulumi/|pulumi\.|new\s+(?:aws|azure|gcp)\.|pulumi\.Run)', content, re.I
        ):
            return 'pulumi'
        if '{{' in content and re.search(r'\b(?:apiVersion|kind):', content):
            return 'helm'

        if suffix == '.json' or content.lstrip().startswith('{'):
            try:
                parsed = json.loads(content)
                if isinstance(parsed, dict) and 'planned_values' in parsed:
                    return 'terraform-plan'
                if isinstance(parsed, dict) and (
                    'Microsoft.Resources/deployments' in str(parsed.get('resources', ''))
                    or str(parsed.get('$schema', '')).lower().find('deploymenttemplate') >= 0
                ):
                    return 'arm'
                if isinstance(parsed, dict) and ('Resources' in parsed or 'AWSTemplateFormatVersion' in parsed):
                    return 'cloudformation'
            except (TypeError, ValueError):
                pass

        try:
            first = next((item for item in yaml.safe_load_all(content) if isinstance(item, dict)), {})
        except yaml.YAMLError:
            first = {}
        if 'apiVersion' in first and 'kind' in first:
            if str(first.get('kind')).lower() == 'kustomization':
                return 'kustomize'
            return 'kubernetes'
        if 'Resources' in first or 'AWSTemplateFormatVersion' in first:
            return 'cloudformation'
        if 'services' in first:
            return 'docker-compose'
        if name.endswith(('.yml', '.yaml')) and any(key in first for key in ('jobs', 'stages', 'workflow')):
            return 'ci'
        return 'auto'

    def parse_project(self, files: List[Dict[str, str]]) -> SystemArchitecture:
        """Parse a related IaC file set and retain resource-to-file provenance."""
        normalized = [
            {'filename': str(item.get('filename') or f'input-{index}'), 'content': str(item.get('content') or ''),
             'format_hint': str(item.get('format_hint') or 'auto')}
            for index, item in enumerate(files, start=1)
            if str(item.get('content') or '').strip()
        ]
        if not normalized:
            raise ValueError('No non-empty IaC files were provided.')

        groups: Dict[str, List[Dict[str, str]]] = defaultdict(list)
        for item in normalized:
            groups[self.detect_format(item['content'], item['filename'], item['format_hint'])].append(item)

        architectures: List[SystemArchitecture] = []
        terraform_files = groups.pop('terraform', [])
        if terraform_files:
            sections = []
            line_ranges = []
            line_cursor = 1
            for item in terraform_files:
                marker = f'# AEGIS_SOURCE_FILE: {item["filename"]}\n'
                section = marker + item['content'].rstrip() + '\n'
                section_lines = section.count('\n')
                line_ranges.append((line_cursor, line_cursor + section_lines - 1, item['filename']))
                sections.append(section)
                line_cursor += section_lines
            architecture = self.parse(''.join(sections), 'terraform')
            self._annotate_source_files(architecture, line_ranges)
            architectures.append(architecture)

        for detected_format, items in groups.items():
            if detected_format == 'auto':
                raise ValueError(f'Could not determine IaC format for {items[0]["filename"]}.')
            for item in items:
                architecture = self.parse(item['content'], detected_format, item['filename'])
                self._annotate_single_source(architecture, item['filename'])
                architectures.append(architecture)

        return self._merge_project_architectures(architectures, [item['filename'] for item in normalized])

    @staticmethod
    def _render_helm_placeholders(content: str) -> str:
        rendered = re.sub(r'(?m)^\s*\{\{[-]?[\s\S]*?\}\}\s*$', '', content)
        rendered = re.sub(r'\{\{[-]?[\s\S]*?[-]?\}\}', 'AEGIS_TEMPLATE_VALUE', rendered)
        return rendered

    @staticmethod
    def _annotate_source_files(architecture: SystemArchitecture, ranges: List[tuple]) -> None:
        def source_for_line(line: Any) -> str:
            try:
                value = int(line)
            except (TypeError, ValueError):
                value = 0
            return next((name for start, end, name in ranges if start <= value <= end), ranges[0][2])

        for component in architecture.components:
            component.properties['source_file'] = source_for_line(component.properties.get('source_line'))
        for finding in (architecture.metadata or {}).get('iac_findings') or []:
            finding['source_file'] = source_for_line(finding.get('line'))

    @staticmethod
    def _annotate_single_source(architecture: SystemArchitecture, filename: str) -> None:
        for component in architecture.components:
            component.properties['source_file'] = filename
        for finding in (architecture.metadata or {}).get('iac_findings') or []:
            finding['source_file'] = filename

    @staticmethod
    def _merge_project_architectures(architectures: List[SystemArchitecture], filenames: List[str]) -> SystemArchitecture:
        components: List[Component] = []
        flows: List[DataFlow] = []
        findings: List[Dict[str, Any]] = []
        seen_components = set()
        seen_flows = set()
        sources = []
        finding_keys = set()
        unresolved_references = []
        analysis_limits = []
        for architecture in architectures:
            metadata = architecture.metadata or {}
            sources.append(metadata.get('source', 'iac'))
            id_map: Dict[str, str] = {}
            for component in architecture.components:
                original_id = component.id
                component_id = original_id
                if component_id in seen_components:
                    component_id = f'{component.properties.get("source_file", "iac")}::{component_id}'
                    component = component.model_copy(update={'id': component_id})
                id_map[original_id] = component_id
                seen_components.add(component_id)
                components.append(component)
            for source_finding in metadata.get('iac_findings') or []:
                finding = dict(source_finding)
                finding['resource_id'] = id_map.get(finding.get('resource_id'), finding.get('resource_id'))
                key = (finding.get('id'), finding.get('source_file'))
                if key in finding_keys:
                    continue
                finding_keys.add(key)
                if any(item.get('id') == finding.get('id') for item in findings):
                    finding['id'] = f"{finding.get('id')}@{finding.get('source_file', 'source')}"
                findings.append(finding)
            for reference in metadata.get('unresolved_references') or []:
                reference = dict(reference) if isinstance(reference, dict) else {'reason': str(reference)}
                if reference.get('resource_id') in id_map:
                    reference['resource_id'] = id_map[reference['resource_id']]
                unresolved_references.append(reference)
            for limit in metadata.get('analysis_limits') or []:
                if limit not in analysis_limits:
                    analysis_limits.append(limit)
            for flow in architecture.flows:
                flow = flow.model_copy(update={
                    'source_id': id_map.get(flow.source_id, flow.source_id),
                    'target_id': id_map.get(flow.target_id, flow.target_id),
                })
                key = (flow.source_id, flow.target_id, flow.protocol)
                if key not in seen_flows:
                    seen_flows.add(key)
                    flows.append(flow)
        return SystemArchitecture(
            components=components,
            flows=flows,
            metadata={
                'source': 'iac-project',
                'iac_formats': sorted(set(sources)),
                'source_files': filenames,
                'iac_findings': findings,
                'iac_findings_count': len(findings),
                'unresolved_references': unresolved_references,
                'analysis_limits': analysis_limits,
                'original_text': f'IaC project containing {len(filenames)} related files.',
            },
        )

    def _attach_security_findings(
        self,
        architecture: SystemArchitecture,
        iac_content: str,
        format_hint: str,
        documents: Optional[List[Dict[str, Any]]] = None,
    ) -> SystemArchitecture:
        metadata = architecture.metadata or {}
        metadata['iac_findings'] = self.security_analyzer.analyze(iac_content, format_hint, documents)
        metadata['iac_findings_count'] = len(metadata['iac_findings'])
        architecture.metadata = metadata
        return architecture

    def _parse_terraform(self, content: str) -> SystemArchitecture:
        """Create architecture components from Terraform resources for report context."""
        ast_summary = self._terraform_ast_summary(content)
        type_map = {
            'aws_s3_bucket': 'Object Storage',
            'aws_db_instance': 'Database',
            'aws_lambda_function': 'Serverless',
            'aws_api_gateway_rest_api': 'API Gateway',
            'aws_instance': 'Service',
            'aws_eks_cluster': 'Container',
            'aws_dynamodb_table': 'Database',
            'aws_iam_role': 'IAM',
            'aws_iam_policy': 'IAM',
            'aws_kms_key': 'KMS',
            'azurerm_storage_account': 'Object Storage',
            'azurerm_key_vault': 'KMS',
            'azurerm_mssql_server': 'Database',
            'azurerm_postgresql_flexible_server': 'Database',
            'azurerm_kubernetes_cluster': 'Container',
            'azurerm_container_registry': 'Container Registry',
            'google_storage_bucket': 'Object Storage',
            'google_sql_database_instance': 'Database',
            'google_container_cluster': 'Container',
            'google_compute_instance': 'Service',
            'google_kms_crypto_key': 'KMS',
        }
        resources = list(self.security_analyzer._terraform_blocks(content))
        components = [Component(
            id='terraform.configuration',
            name='Terraform Configuration',
            type='CI/CD',
            properties={
                'iac_resource_type': 'terraform_configuration',
                'deployment': 'terraform',
                'authoritative': True,
            },
        )]
        blocks: Dict[str, tuple] = {}
        for resource_type, name, block, line in resources:
            resource_id = f'{resource_type}.{name}'
            blocks[resource_id] = (resource_type, block, line)
            component_type = type_map.get(resource_type) or self._terraform_component_type(resource_type)
            provider = resource_type.split('_', 1)[0]
            provider = {'aws': 'aws', 'azurerm': 'azure', 'google': 'gcp'}.get(provider, provider)
            components.append(Component(
                id=resource_id,
                name=name.replace('-', ' ').replace('_', ' ').title(),
                type=component_type,
                properties={
                    'iac_resource_type': resource_type,
                    'cloud_provider': provider,
                    'deployment': 'terraform',
                    'source_line': line,
                },
            ))
        for name, _, _ in self.security_analyzer._terraform_modules(content):
            components.append(Component(
                id=f'module.{name}',
                name=name.replace('-', ' ').replace('_', ' ').title(),
                type='Cloud',
                properties={
                    'iac_resource_type': 'terraform_module',
                    'cloud_provider': 'multi-cloud',
                    'deployment': 'terraform',
                },
            ))
        component_map = {component.id: component for component in components}
        reference_edges: List[Dict[str, Any]] = []
        flows: List[DataFlow] = []
        flow_pairs = set()
        for source_id, (source_type, block, line) in blocks.items():
            references = sorted({
                match.group(0) for match in re.finditer(
                    r'(?<![A-Za-z0-9_])(?:aws|azurerm|google)_[a-z0-9_]+\.[A-Za-z0-9_-]+', block,
                    re.IGNORECASE,
                )
                if match.group(0) in blocks and match.group(0) != source_id
            })
            component_map[source_id].properties['references'] = references
            for target_id in references:
                target_type = blocks[target_id][0]
                relationship = self._terraform_relationship(source_type, target_type)
                reference_edges.append({
                    'source': source_id,
                    'target': target_id,
                    'relationship': relationship,
                    'line': line,
                    'evidence': f'{source_id} references {target_id}.',
                })
                protocol = self._terraform_flow_protocol(source_type, target_type, relationship)
                if protocol and (source_id, target_id) not in flow_pairs:
                    flows.append(DataFlow(
                        source_id=source_id,
                        target_id=target_id,
                        protocol=protocol,
                        assumed=False,
                        properties={
                            'origin': 'iac_reference',
                            'authoritative': True,
                            'relationship': relationship,
                            'evidence': f'Terraform expression in {source_id} references {target_id}.',
                        },
                        confidence='High',
                    ))
                    flow_pairs.add((source_id, target_id))

        return SystemArchitecture(
            components=components,
            flows=flows,
            metadata={
                'source': 'terraform',
                'original_text': 'Terraform infrastructure configuration',
                'iac_resource_graph': {
                    'nodes': sorted(blocks),
                    'edges': reference_edges,
                },
                'terraform_parser': ast_summary,
            },
        )

    @staticmethod
    def _terraform_ast_summary(content: str) -> Dict[str, Any]:
        """Parse HCL into an AST summary while keeping raw blocks for evidence lines."""
        if hcl2 is None:
            return {
                'mode': 'balanced_block_fallback',
                'available': False,
                'warning': 'python-hcl2 is not installed; nested HCL is analyzed with the fallback parser.',
            }
        try:
            parsed = hcl2.loads(content)
        except Exception as exc:
            return {
                'mode': 'balanced_block_fallback',
                'available': True,
                'warning': f'python-hcl2 could not parse this file: {exc}',
            }

        def names(section: str) -> List[str]:
            values = parsed.get(section) or []
            if isinstance(values, dict):
                values = [values]
            output = []
            for value in values:
                if isinstance(value, dict):
                    output.extend(str(key) for key in value)
            return sorted(set(output))

        resources = parsed.get('resource') or []
        resource_count = sum(
            len(resource_names)
            for group in resources if isinstance(group, dict)
            for resource_names in group.values() if isinstance(resource_names, dict)
        )
        return {
            'mode': 'python-hcl2',
            'available': True,
            'resource_count': resource_count,
            'modules': names('module'),
            'providers': names('provider'),
            'variables': names('variable'),
            'outputs': names('output'),
        }

    @staticmethod
    def _terraform_relationship(source_type: str, target_type: str) -> str:
        if 'permission' in source_type or 'policy' in source_type or 'role' in source_type:
            return 'permission_reference'
        if any(token in source_type for token in ('security_group', 'subnet', 'route', 'firewall')):
            return 'network_reference'
        if any(token in target_type for token in ('iam_', 'role', 'policy', 'kms_', 'key_vault')):
            return 'identity_or_key_reference'
        return 'resource_reference'

    @staticmethod
    def _terraform_flow_protocol(source_type: str, target_type: str, relationship: str) -> Optional[str]:
        if relationship != 'resource_reference':
            return None
        if 'api_gateway' in source_type and 'lambda' in target_type:
            return 'aws-invoke'
        if 'function_url' in source_type and 'lambda' in target_type:
            return 'https'
        if 'lambda_function' in source_type and any(
            token in target_type for token in ('s3_', 'db_', 'dynamodb', 'sql_', 'storage_', 'secret')
        ):
            return 'aws-sdk'
        return None

    def _parse_cloudformation(self, template: Dict[str, Any]) -> SystemArchitecture:
        """Create architecture components from CloudFormation resources."""
        type_map = {
            'AWS::S3::Bucket': 'Object Storage',
            'AWS::RDS::DBInstance': 'Database',
            'AWS::Lambda::Function': 'Serverless',
            'AWS::ApiGateway::RestApi': 'API Gateway',
            'AWS::EC2::Instance': 'Service',
            'AWS::EKS::Cluster': 'Container',
            'AWS::DynamoDB::Table': 'Database',
            'AWS::IAM::Role': 'IAM',
            'AWS::IAM::ManagedPolicy': 'IAM',
            'AWS::KMS::Key': 'KMS',
        }
        components = []
        for logical_id, resource in (template.get('Resources') or {}).items():
            if not isinstance(resource, dict):
                continue
            resource_type = resource.get('Type', '')
            component_type = type_map.get(resource_type) or self._cloudformation_component_type(resource_type)
            components.append(Component(
                id=logical_id,
                name=logical_id.replace('-', ' ').replace('_', ' '),
                type=component_type,
                properties={
                    'iac_resource_type': resource_type,
                    'cloud_provider': 'aws',
                    'deployment': 'cloudformation',
                },
            ))
        return SystemArchitecture(
            components=components,
            flows=[],
            metadata={'source': 'cloudformation', 'original_text': 'CloudFormation infrastructure configuration'},
        )

    def _parse_arm(self, template: Dict[str, Any]) -> SystemArchitecture:
        """Create a technical model from Azure Resource Manager JSON."""
        components: List[Component] = []
        flows: List[DataFlow] = []
        resources = template.get('resources') or []
        by_name: Dict[str, str] = {}
        for index, resource in enumerate(resources):
            if not isinstance(resource, dict):
                continue
            resource_type = str(resource.get('type') or 'Microsoft.Resources/deployments')
            name = str(resource.get('name') or f'resource-{index + 1}')
            resource_id = name.strip("[]'")
            by_name[name.lower()] = resource_id
            components.append(Component(
                id=resource_id,
                name=name,
                type=self._arm_component_type(resource_type),
                properties={
                    'iac_resource_type': resource_type,
                    'cloud_provider': 'azure',
                    'deployment': 'arm',
                    'public_access': self._arm_public_access(resource),
                },
            ))
        component_ids = {component.id for component in components}
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            source = str(resource.get('name') or '').strip("[]'")
            for dependency in resource.get('dependsOn') or []:
                dependency_text = str(dependency).lower()
                target = next((value for key, value in by_name.items() if key in dependency_text), None)
                if source in component_ids and target in component_ids:
                    flows.append(DataFlow(
                        source_id=source,
                        target_id=target,
                        protocol='azure-resource-reference',
                        assumed=False,
                        confidence='High',
                        properties={'origin': 'iac_reference', 'authoritative': True},
                    ))
        return SystemArchitecture(
            components=components,
            flows=flows,
            metadata={'source': 'arm', 'original_text': 'Azure Resource Manager infrastructure configuration'},
        )

    def _parse_source_iac(self, content: str, format_name: str, filename: str) -> SystemArchitecture:
        """Build a conservative model for source-oriented IaC and CI definitions."""
        components: List[Component] = []
        if format_name == 'bicep':
            pattern = re.compile(
                r'(?m)^\s*resource\s+(?P<name>[A-Za-z_][\w]*)\s+[\'\"](?P<type>[^\'\"]+)[\'\"]\s*=\s*\{'
            )
            for match in pattern.finditer(content):
                resource_type = match.group('type').split('@', 1)[0]
                components.append(Component(
                    id=match.group('name'),
                    name=match.group('name'),
                    type=self._arm_component_type(resource_type),
                    properties={
                        'iac_resource_type': resource_type,
                        'cloud_provider': 'azure',
                        'deployment': 'bicep',
                        'source_line': content[:match.start()].count('\n') + 1,
                    },
                ))
        elif format_name == 'pulumi':
            pattern = re.compile(
                r'(?m)(?:new\s+)?(?P<type>(?:aws|azure|gcp|google|kubernetes)[.\w]+)\s*\(\s*[\'\"](?P<name>[^\'\"]+)',
                re.I,
            )
            for match in pattern.finditer(content):
                resource_type = match.group('type')
                prefix = resource_type.split('.')[0].lower()
                provider = {'google': 'gcp', 'kubernetes': 'kubernetes'}.get(prefix, prefix)
                components.append(Component(
                    id=f'{resource_type}.{match.group("name")}',
                    name=match.group('name'),
                    type=self._terraform_component_type(resource_type.replace('.', '_')),
                    properties={
                        'iac_resource_type': resource_type,
                        'cloud_provider': provider,
                        'deployment': 'pulumi',
                        'source_line': content[:match.start()].count('\n') + 1,
                    },
                ))
        else:
            components.append(Component(
                id=f'pipeline.{Path(filename or "pipeline").stem}',
                name=Path(filename or 'Pipeline').name,
                type='CI/CD',
                properties={
                    'deployment': 'ci',
                    'iac_resource_type': 'ci_pipeline',
                    'authoritative': True,
                },
            ))
        if not components:
            components.append(Component(
                id=f'{format_name}.configuration',
                name=f'{format_name.title()} Configuration',
                type='CI/CD',
                properties={
                    'deployment': format_name,
                    'iac_resource_type': f'{format_name}_configuration',
                },
            ))
        return SystemArchitecture(
            components=components,
            flows=[],
            metadata={'source': format_name, 'original_text': f'{format_name.title()} infrastructure configuration'},
        )

    @staticmethod
    def _arm_component_type(resource_type: str) -> str:
        lowered = resource_type.lower()
        if any(token in lowered for token in ('storageaccounts', 'blobservices', '/containers')):
            return 'Object Storage'
        if any(token in lowered for token in ('databases', '/servers', 'redis', 'cosmosdb')):
            return 'Database'
        if any(token in lowered for token in ('managedidentity', 'roleassignments')):
            return 'IAM'
        if 'vaults' in lowered:
            return 'KMS'
        if any(token in lowered for token in ('web/sites', 'containerapps', 'function')):
            return 'Serverless'
        if any(token in lowered for token in ('network', 'firewall', 'publicip')):
            return 'Network'
        if 'managedclusters' in lowered:
            return 'Container'
        return 'Cloud'

    @staticmethod
    def _arm_public_access(resource: Dict[str, Any]) -> bool:
        properties = resource.get('properties') or {}
        rendered = json.dumps(resource, sort_keys=True)
        return bool(
            properties.get('allowBlobPublicAccess') is True
            or re.search(r'0\.0\.0\.0/0', rendered)
            or (
                properties.get('publicNetworkAccess') in (True, 'Enabled', 'enabled')
                and (properties.get('networkAcls') or {}).get('defaultAction') in ('Allow', 'allow')
                and not (properties.get('networkAcls') or {}).get('ipRules')
            )
        )
            
    def _parse_docker_compose(self, compose_data: Dict) -> SystemArchitecture:
        """Parse Docker Compose YAML into a SystemArchitecture"""
        components = []
        
        services = compose_data.get('services', {})
        if not services:
            logger.warning("No services found in Docker Compose file")
            return SystemArchitecture(components=[])
            
        # First pass: Create components
        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue
                
            # Try to infer component type
            image = service_config.get('image', '').lower()
            comp_type = self._infer_component_type(service_name, image)
            
            # Extract properties
            properties = {}
            if 'image' in service_config:
                properties['image'] = service_config['image']
            
            if 'ports' in service_config:
                properties['public_access'] = True
            else:
                properties['public_access'] = False
                
            if 'environment' in service_config:
                env = service_config['environment']
                if isinstance(env, dict):
                    # Check for secrets passing in env
                    if any('password' in k.lower() or 'secret' in k.lower() or 'key' in k.lower() for k in env.keys()):
                        properties['secrets_in_env'] = True
                elif isinstance(env, list):
                    if any('password' in str(v).lower() or 'secret' in str(v).lower() or 'key' in str(v).lower() for v in env):
                        properties['secrets_in_env'] = True
            
            if service_config.get('privileged') is True:
                properties['privileged_container'] = True
                
            properties['containerized'] = True

            comp = Component(
                id=service_name,
                name=service_name.replace('-', ' ').title(),
                type=comp_type,
                properties=properties
            )
            components.append(comp)
            
        # Second pass: establish connections (networks and depends_on)
        flows = []
        for comp in components:
            service_config = services.get(comp.id, {})
            targets = set()
            
            # 1. depends_on 
            if 'depends_on' in service_config:
                deps = service_config['depends_on']
                if isinstance(deps, list):
                    for dep in deps:
                        targets.add(dep)
                elif isinstance(deps, dict):
                    for dep in deps.keys():
                        targets.add(dep)
            
            # 2. Extract potential database connections from environment variables
            env = service_config.get('environment', {})
            if isinstance(env, dict):
                for val in env.values():
                    val_str = str(val).lower()
                    for other_comp in components:
                        if other_comp.id != comp.id and other_comp.id.lower() in val_str:
                             targets.add(other_comp.id)
            elif isinstance(env, list):
                for val in env:
                    val_str = str(val).lower()
                    for other_comp in components:
                        if other_comp.id != comp.id and other_comp.id.lower() in val_str:
                             targets.add(other_comp.id)

            for target in targets:
                flows.append(DataFlow(source_id=comp.id, target_id=target, protocol="tcp"))
            
        # Generate a textual summary for the NLP pipeline to process
        summary = self._generate_summary_text("Docker Compose", components, flows)
        metadata = {'source': 'docker-compose', 'original_text': summary}
        
        return SystemArchitecture(components=components, flows=flows, metadata=metadata)
        
    def _parse_kubernetes(self, documents: List[Dict]) -> SystemArchitecture:
        """Parse Kubernetes YAML manifests into a SystemArchitecture"""
        components = []
        services_map = {} # map service name to selector
        deployments = []
        workload_labels: Dict[str, Dict[str, str]] = {}
        
        # First gather all resources
        for doc in documents:
            if not doc or not isinstance(doc, dict):
                continue
                
            kind = doc.get('kind', '')
            metadata = doc.get('metadata', {})
            name = metadata.get('name', 'unknown')
            
            if kind in ('Deployment', 'StatefulSet', 'DaemonSet', 'Pod', 'Job', 'CronJob'):
                deployments.append(doc)
            elif kind == 'Service':
                spec = doc.get('spec', {})
                selector = spec.get('selector', {})
                ports = spec.get('ports', [])
                services_map[name] = {
                    'selector': selector,
                    'type': spec.get('type', 'ClusterIP'),
                    'ports': ports
                }
        
        # Process deployments/pods into components
        for dep in deployments:
            name = dep.get('metadata', {}).get('name', 'unknown')
            kind = dep.get('kind', '')
            
            spec = dep.get('spec', {})
            if kind == 'CronJob':
                template = spec.get('jobTemplate', {}).get('spec', {}).get('template', {})
            else:
                template = spec.get('template', {}) if kind != 'Pod' else dep
            pod_spec = template.get('spec', {})
            pod_labels = template.get('metadata', {}).get('labels', {})
            
            containers = pod_spec.get('containers', [])
            if not containers:
                continue
                
            # Typically taking the primary container
            primary_container = containers[0]
            image = primary_container.get('image', '')
            
            comp_type = self._infer_component_type(name, image)
            
            properties = {
                'image': image,
                'containerized': True,
                'deployment': 'k8s',
                'iac_kind': kind,
                'namespace': dep.get('metadata', {}).get('namespace', 'default'),
            }
            
            # Security Context
            sec_context = primary_container.get('securityContext', {})
            pod_sec_context = pod_spec.get('securityContext', {})
            
            if sec_context.get('privileged'):
                properties['privileged_container'] = True
            
            if sec_context.get('allowPrivilegeEscalation') is False:
                properties['privilege_escalation_disabled'] = True
                
            if pod_sec_context.get('runAsNonRoot') or sec_context.get('runAsNonRoot'):
                properties['runs_as_non_root'] = True
            
            # Check Services exposure
            is_exposed = False
            for svc_name, svc_info in services_map.items():
                selector = svc_info.get('selector', {})
                # If pod labels match service selector
                if selector and all(pod_labels.get(k) == v for k, v in selector.items()):
                    if svc_info.get('type') in ('LoadBalancer', 'NodePort'):
                        is_exposed = True
                        properties['public_access'] = True
                    break
                    
            if not is_exposed:
                properties['public_access'] = False
                
            comp = Component(
                id=name,
                name=name.replace('-', ' ').title(),
                type=comp_type,
                properties=properties
            )
            components.append(comp)
            workload_labels[name] = pod_labels

        flows = []

        for service_name, service_info in services_map.items():
            service_id = f'service.{service_name}'
            public = service_info.get('type') in ('LoadBalancer', 'NodePort')
            components.append(Component(
                id=service_id,
                name=service_name.replace('-', ' ').title(),
                type='API Gateway' if public else 'Service',
                properties={
                    'deployment': 'k8s',
                    'iac_kind': 'Service',
                    'public_access': public,
                    'service_type': service_info.get('type'),
                },
            ))
            selector = service_info.get('selector') or {}
            for workload_name, labels in workload_labels.items():
                if selector and all(labels.get(key) == value for key, value in selector.items()):
                    protocol = 'tcp'
                    ports = service_info.get('ports') or []
                    if any(str(item.get('name', '')).lower() in {'https', 'tls'} or item.get('port') == 443 for item in ports if isinstance(item, dict)):
                        protocol = 'https'
                    flows.append(DataFlow(source_id=service_id, target_id=workload_name, protocol=protocol))

        supplemental_types = {
            'Ingress': 'API Gateway',
            'Role': 'IAM',
            'ClusterRole': 'IAM',
            'RoleBinding': 'IAM',
            'ClusterRoleBinding': 'IAM',
            'ServiceAccount': 'IAM',
            'Secret': 'KMS',
            'ConfigMap': 'Service',
            'NetworkPolicy': 'Network',
        }
        existing_ids = {component.id for component in components}
        for document in documents:
            kind = document.get('kind', '')
            if kind not in supplemental_types:
                continue
            metadata = document.get('metadata') or {}
            name = metadata.get('name', kind)
            resource_id = f'{kind.lower()}.{name}'
            if resource_id not in existing_ids:
                components.append(Component(
                    id=resource_id,
                    name=name.replace('-', ' ').title(),
                    type=supplemental_types[kind],
                    properties={
                        'deployment': 'k8s',
                        'iac_kind': kind,
                        'namespace': metadata.get('namespace', 'default'),
                        'public_access': kind == 'Ingress',
                    },
                ))
                existing_ids.add(resource_id)
            if kind == 'Ingress':
                ingress_spec = document.get('spec') or {}
                backend_names = []
                default_backend = ingress_spec.get('defaultBackend') or {}
                if isinstance(default_backend.get('service'), dict):
                    backend_names.append(default_backend['service'].get('name'))
                for rule in ingress_spec.get('rules') or []:
                    for path in ((rule.get('http') or {}).get('paths') or []):
                        service = ((path.get('backend') or {}).get('service') or {})
                        backend_names.append(service.get('name'))
                protocol = 'https' if ingress_spec.get('tls') else 'http'
                for backend_name in {item for item in backend_names if item}:
                    target_id = f'service.{backend_name}'
                    if target_id in existing_ids:
                        flows.append(DataFlow(source_id=resource_id, target_id=target_id, protocol=protocol))
        
        summary = self._generate_summary_text("Kubernetes", components, flows)
        metadata = {'source': 'kubernetes', 'original_text': summary, 'deployment': 'k8s'}
        
        return SystemArchitecture(components=components, flows=flows, metadata=metadata)

    @staticmethod
    def _terraform_component_type(resource_type: str) -> str:
        lowered = resource_type.lower()
        if any(token in lowered for token in ('bucket', 'storage', 'blob')):
            return 'Object Storage'
        if any(token in lowered for token in ('database', 'db_', 'sql_', 'dynamodb', 'redis', 'cache')):
            return 'Database'
        if any(token in lowered for token in ('iam', 'role', 'policy', 'service_account')):
            return 'IAM'
        if any(token in lowered for token in ('kms', 'key_vault', 'crypto_key', 'secret')):
            return 'KMS'
        if any(token in lowered for token in ('kubernetes', 'eks_', 'aks_', 'gke_', 'container')):
            return 'Container'
        if any(token in lowered for token in ('api_gateway', 'apigateway', 'application_gateway')):
            return 'API Gateway'
        if any(token in lowered for token in ('lambda', 'function', 'cloud_run')):
            return 'Serverless'
        if any(token in lowered for token in ('security_group', 'firewall', 'network', 'subnet', 'vpc')):
            return 'Network'
        return 'Cloud'

    @staticmethod
    def _cloudformation_component_type(resource_type: str) -> str:
        lowered = resource_type.lower()
        if 'bucket' in lowered:
            return 'Object Storage'
        if any(token in lowered for token in ('database', 'dbinstance', 'table', 'cache')):
            return 'Database'
        if any(token in lowered for token in ('iam::', 'role', 'policy')):
            return 'IAM'
        if any(token in lowered for token in ('kms::', 'secretsmanager')):
            return 'KMS'
        if any(token in lowered for token in ('lambda', 'function')):
            return 'Serverless'
        if any(token in lowered for token in ('securitygroup', 'vpc', 'subnet', 'route')):
            return 'Network'
        return 'Cloud'
        
    def _infer_component_type(self, name: str, image: str) -> str:
        """Infer type based on container image and name"""
        name_lower = name.lower()
        image_lower = image.lower()
        
        db_keywords = ['postgres', 'mysql', 'mongo', 'redis', 'db', 'mariadb', 'cassandra']
        for kw in db_keywords:
            if kw in image_lower or kw in name_lower:
                return 'Database'
                
        api_keywords = ['api', 'backend', 'server', 'node', 'python', 'java', 'go']
        for kw in api_keywords:
            if kw in image_lower or kw in name_lower:
                return 'API'
                
        web_keywords = ['ui', 'frontend', 'web', 'react', 'nginx', 'apache']
        for kw in web_keywords:
            if kw in image_lower or kw in name_lower:
                return 'WebClient'
                
        queue_keywords = ['kafka', 'rabbit', 'celery', 'worker']
        for kw in queue_keywords:
            if kw in image_lower or kw in name_lower:
                return 'Queue'
                
        return 'Service'
        
    def _generate_summary_text(self, env_type: str, components: List[Component], flows: List[DataFlow]) -> str:
        """Generate a natural language summary that the NLP engine can process for semantic matching"""
        lines = [f"This is a {env_type} architecture."]
        
        for comp in components:
            lines.append(f"{comp.name} is a {comp.type} component.")
            if comp.properties.get('image'):
                lines.append(f"It runs the {comp.properties['image']} image.")
            
            targets = [f.target_id for f in flows if f.source_id == comp.id]
            if targets:
                targets_str = ", ".join(targets)
                lines.append(f"It connects to {targets_str}.")
                
        return " ".join(lines)

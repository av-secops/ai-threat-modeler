"""Machine-readable boundaries of static IaC analysis, not deployment assurance."""


SUPPORT = {
    'terraform': ('partial', 'HCL resources, literal settings and local references', 'Module expansion, provider defaults and computed expressions require a resolved plan.'),
    'terraform-plan': ('partial', 'Submitted planned resource values and explicit after_unknown paths', 'Only registered plan checks execute; missing policy layers and runtime reachability remain unknown.'),
    'cloudformation': ('partial', 'Resources, literal properties and preserved intrinsic functions', 'Unresolved intrinsic functions, transforms and external stacks require resolved input.'),
    'kubernetes': ('partial', 'Multi-document objects, workload settings and local selectors', 'Admission mutations, external policies and live network reachability are not verified.'),
    'docker-compose': ('partial', 'Services, ports, networks and explicit container settings', 'External overrides, environment interpolation and image configuration require resolved evidence.'),
    'helm': ('partial', 'Recognizable manifest structure with placeholders', 'Templates are never executed; use rendered manifests for authoritative checks.'),
    'arm': ('partial', 'Literal resource properties', 'Deployment expressions and external resources are not fully resolved.'),
    'bicep': ('partial', 'Explicit source settings', 'Source pattern checks only; upload compiled ARM for structural checks.'),
    'pulumi': ('partial', 'Explicit source settings', 'Uploaded programs are never executed; dynamic configuration remains unresolved.'),
    'ci': ('partial', 'Supported pipeline triggers and explicit permission/checkout settings', 'Reusable workflows and runtime inputs may require additional evidence.'),
    'kustomize': ('partial', 'Source references', 'Overlays are not executed; provide rendered manifests.'),
    'helm-values': ('partial', 'Explicit value assignments', 'Values alone do not establish the resulting workload configuration.'),
    'dockerfile': ('partial', 'Stage structure, explicit final USER and local stage inheritance', 'No image builds, base-image configuration, RUN effects, alternate build targets or deployment overrides are evaluated. Heredocs require resolved image configuration. EXPOSE does not establish public access.'),
}


def coverage(architecture, format_name):
    state, evaluated, limit = SUPPORT.get(format_name, ('unsupported', '', 'Unrecognized static IaC format.'))
    metadata = architecture.metadata or {}
    return {'version': 'iac-support-1', 'format': format_name, 'status': state,
        'evaluated': evaluated, 'limits': [limit, *(metadata.get('analysis_limits') or [])],
        'resources_modeled': len(architecture.components),
        'unresolved_references': metadata.get('unresolved_references') or [],
        'runtime_verified': False, 'executes_uploaded_code': False}

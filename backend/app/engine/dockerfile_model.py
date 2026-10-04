"""Read Dockerfile stages without building images or executing instructions."""

from io import BytesIO
import shlex

from dockerfile_parse import DockerfileParser


def read_stages(content):
    parser = DockerfileParser(fileobj=BytesIO(content.encode('utf-8')), env_replace=False)
    stages, aliases = [], {}
    for item in parser.structure:
        instruction, value = item['instruction'].upper(), item['value'].strip()
        line = item['startline'] + 1
        if instruction in {'RUN', 'COPY', 'ADD'} and '<<' in value:
            raise ValueError('Dockerfile heredoc syntax is not supported by this static parser. Provide the resolved image configuration or a manifest; no clean-security result can be inferred.')
        if instruction == 'FROM':
            tokens = shlex.split(value)
            tokens = [token for token in tokens if not token.startswith('--')]
            if not tokens:
                raise ValueError('Dockerfile FROM requires an image.')
            if len(tokens) != 1 and not (len(tokens) == 3 and tokens[1].upper() == 'AS'):
                raise ValueError('Unsupported Dockerfile FROM syntax.')
            base = tokens[0]
            parent = aliases.get(base.lower())
            name = tokens[2] if len(tokens) == 3 and tokens[1].upper() == 'AS' else f'stage-{len(stages) + 1}'
            stage = {'id': f'dockerfile.stage-{len(stages) + 1}', 'name': name,
                'base_image': base, 'line': line, 'user': parent['user'] if parent and not parent['has_onbuild'] else None,
                'user_line': parent['user_line'] if parent else None,
                'exposed_ports': list(parent['exposed_ports']) if parent else [],
                'has_onbuild': bool(parent and parent['has_onbuild'])}
            stages.append(stage)
            aliases[name.lower()] = stage
        elif stages and instruction == 'USER':
            stages[-1].update(user=value, user_line=line)
        elif stages and instruction == 'EXPOSE':
            stages[-1]['exposed_ports'].extend(value.split())
        elif stages and instruction == 'ONBUILD':
            stages[-1]['has_onbuild'] = True
    if not stages:
        raise ValueError('Dockerfile must contain at least one FROM instruction.')
    return stages


def literal_root_user(stage):
    user = stage['user']
    if user is None or any(marker in user for marker in ('$', '{', '}')):
        return None
    # Numeric nonzero IDs are known non-root; named users require image /etc/passwd.
    name = user.split(':', 1)[0].strip()
    if name.lower() == 'root' or (name.isdecimal() and int(name) == 0):
        return True
    return False if name.isdecimal() else None

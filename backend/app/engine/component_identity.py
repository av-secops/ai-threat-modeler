"""Resolve several extracted names that denote one architecture component.

Independent extraction passes each recognize what they know: a catalog matches
"Auth0", a third-party pass matches the same word as an external dependency, and
a role pass matches "iOS mobile app". Left alone the model then carries one node
twice, which splits its data flows, doubles its findings and makes the diagram
disagree with the design it describes.

The rules here are stated in terms of how names relate to each other rather than
per vendor, so a name the catalogs have never seen is resolved the same way.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .component_roles import find_named_roles, tokens_of
from .technology_catalog import (
    CLASSIFYING_SUFFIXES,
    PLATFORM_DISPLAY_NAMES,
    PLATFORM_TECHNOLOGIES,
)


def consolidate(components: Dict[str, Any], text: str = '') -> List[Dict[str, str]]:
    """Merge duplicate nodes in place and return what was merged.

    Each returned record states the surviving id, the id that was removed and
    the reason, so the merge is reviewable rather than silent.
    """
    merges: List[Dict[str, str]] = []
    merges.extend(_merge_classifying_suffixes(components))
    merges.extend(_merge_platform_names(components, text))
    merges.extend(_merge_identical_names(components))
    merges.extend(_merge_contained_names(components))
    merges.extend(_drop_system_name(components, text))
    return merges


# "The Aurora payments platform serves retail customers" names the system under
# review. A catalog that also sells a database called Aurora would otherwise put
# a data store in the model that the design never had.
# The head noun has to name a whole system. "Application" is left out because a
# React single page application is a component, not the system under review.
_SYSTEM_NAME_RE = re.compile(
    r'\b(?:the\s+)?(?P<name>[A-Z][\w.-]*)(?:\s+[a-z][\w-]*){0,3}\s+'
    r'(?:platform|system|solution|suite|product|estate|programme)\b'
)


def _drop_system_name(components: Dict[str, Any], text: str) -> List[Dict[str, str]]:
    # Only the opening statement introduces the system by name.
    opening = re.split(r'(?<=[.!?])\s', ' '.join((text or '').split()))[0][:240]
    dropped: List[Dict[str, str]] = []
    for match in _SYSTEM_NAME_RE.finditer(opening):
        name = match.group('name')
        component = components.get(re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_'))
        if component is None:
            continue
        # Only where the name is used nowhere else. A component that takes part
        # in the design is mentioned again; a product name is not.
        mentions = len(re.findall(rf'\b{re.escape(name)}\b', text or '', re.IGNORECASE))
        if mentions > 1:
            continue
        components.pop(component.id)
        dropped.append({
            'kept': '',
            'removed': component.id,
            'reason': 'the name identifies the system under review, not a component',
        })
    return dropped


def _merge_classifying_suffixes(components: Dict[str, Any]) -> List[Dict[str, str]]:
    """Collapse "auth0_external" into "auth0" whenever both were extracted."""
    merges: List[Dict[str, str]] = []
    for component_id in sorted(components):
        base = next(
            (component_id[: -len(suffix)] for suffix in CLASSIFYING_SUFFIXES
             if component_id.endswith(suffix) and component_id[: -len(suffix)]),
            None,
        )
        if not base or base not in components or base == component_id:
            continue
        survivor, removed = components[base], components[component_id]
        if not _same_role(survivor, removed):
            continue
        _absorb(survivor, removed)
        components.pop(component_id)
        merges.append({
            'kept': base,
            'removed': component_id,
            'reason': 'one dependency was both named and classified',
        })
    return merges


def _merge_identical_names(components: Dict[str, Any]) -> List[Dict[str, str]]:
    """Collapse nodes that ended up with the same name and role.

    Two catalogs can recognize one phrase under different ids, so "AWS KMS"
    arrives as both `aws_kms` and `kms`. They are one key manager, and left
    separate they each collect their own findings and coverage cells.
    """
    merges: List[Dict[str, str]] = []
    by_name: Dict[Tuple[str, str], List[str]] = {}
    for component_id, component in components.items():
        key = (_normalize(str(component.name or '')), str(component.type or ''))
        if key[0]:
            by_name.setdefault(key, []).append(component_id)

    for (normalized_name, _), ids in by_name.items():
        if len(ids) < 2:
            continue
        # The id derived from the shared name is the one other passes will have
        # used; failing that, keep the most specific.
        survivor_id = next(
            (candidate for candidate in ids if candidate == normalized_name),
            max(ids, key=lambda candidate: (len(tokens_of(candidate)), len(candidate))),
        )
        survivor = components[survivor_id]
        for component_id in ids:
            if component_id == survivor_id:
                continue
            _absorb(survivor, components[component_id])
            components.pop(component_id)
            merges.append({
                'kept': survivor_id,
                'removed': component_id,
                'reason': 'two extraction passes named the same component',
            })
    return merges


def _normalize(name: str) -> str:
    return re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_')


def _merge_contained_names(components: Dict[str, Any]) -> List[Dict[str, str]]:
    """Fold a name that is wholly contained in a fuller one for the same role.

    A catalog pass recognizes "Aurora" while a role pass reads the same phrase as
    "Aurora PostgreSQL Database". One database is described twice, and the fuller
    name is the one the design used.

    Containment on its own is not enough. "Redis" inside both a session cache and
    a rate limit store names neither of them in particular, so a name that fits
    into more than one fuller name is left alone: the evidence does not say which
    node it belongs to, and picking one is how a wrong attribution gets made.
    """
    merges: List[Dict[str, str]] = []
    for component_id in sorted(components, key=lambda item: len(tokens_of(item))):
        component = components.get(component_id)
        if component is None:
            continue
        contained = tokens_of(str(component.name or ''))
        if not contained:
            continue
        hosts = [
            other for other in components.values()
            if other.id != component_id
            and _same_role(other, component)
            and contained < tokens_of(str(other.name or ''))
        ]
        if len(hosts) != 1:
            continue
        survivor = hosts[0]
        _absorb(survivor, component)
        # The fuller name won because it says more, but the shorter one may be
        # the one that carries the role: "Aurora" is known to be a database while
        # the phrase that contains it was only ever a noun.
        if survivor.type == 'unknown' and component.type != 'unknown':
            survivor.type = component.type
        components.pop(component_id)
        merges.append({
            'kept': survivor.id,
            'removed': component_id,
            'reason': 'a fuller name for the same component was also extracted',
        })
    return merges


def _merge_platform_names(components: Dict[str, Any], text: str) -> List[Dict[str, str]]:
    """Fold a platform name into the component it is built with.

    A merge needs positive evidence that the two names describe one thing: the
    host's own description has to mention the platform. Without that check a
    React portal and an unrelated admin portal would be collapsed together.
    """
    merges: List[Dict[str, str]] = []
    # Longest name first, so "Spring Boot" is recognized before "Spring" and the
    # label ends up reading "(Spring Boot)" rather than "(Spring) (Spring Boot)".
    ordered = sorted(
        list(components.values()),
        key=lambda component: (-len(_platform_key(component)), component.id),
    )
    for platform in ordered:
        platform_id = platform.id
        if platform_id not in components:
            continue
        hosted_types = PLATFORM_TECHNOLOGIES.get(_platform_key(platform))
        if not hosted_types:
            continue
        host = _host_for(platform, hosted_types, components, text)
        if host is None:
            continue
        _absorb(host, platform)
        key = _platform_key(platform)
        host.properties['technology'] = ' '.join(
            part for part in (host.properties.get('technology'), key) if part
        )
        # The platform stays on the label. A reviewer reading the diagram needs to
        # know the portal is a React application, and the merge would otherwise
        # remove that word from the model entirely.
        if not re.search(rf'\b{re.escape(key)}\b', str(host.name or ''), re.IGNORECASE):
            host.name = _with_platform(str(host.name or ''), _platform_display_name(platform, key))
        components.pop(platform_id)
        merges.append({
            'kept': host.id,
            'removed': platform_id,
            'reason': 'a platform name describes how this component is built',
        })
    return merges


def _host_for(platform, hosted_types: Iterable[str], components: Dict[str, Any], text: str = ''):
    key = _platform_key(platform)
    candidates = [
        component for component in components.values()
        if component.id != platform.id
        and component.type in tuple(hosted_types)
        and _states_platform(component, key)
    ]
    if not candidates and text:
        stated = [component for component in components.values()
            if component.id != platform.id and component.type in tuple(hosted_types)
            and re.search(r'\b' + re.escape(component.name) + r'\s+(?:is|is implemented in|is written in|is built with)\s+(?:an?\s+)?' + re.escape(key) + r'\b', text, re.I)]
        # Shared runtimes are not evidence that two separately named services are one.
        return stated[0] if len(stated) == 1 else None
    # The most specifically named host wins, so a platform attaches to "Customer
    # Mobile App" rather than to the bare "Mobile App" placeholder beside it.
    return max(candidates, key=lambda component: len(tokens_of(component.id)), default=None)


def _with_platform(name: str, platform: str) -> str:
    """Add a platform to a label, keeping one stack in one pair of brackets.

    A service written as "User Service (Node.js + Express)" is built with two
    things, and naming it "User Service (Express) (Node.js)" reads as though the
    brackets meant something different each time.
    """
    trailing = re.search(r'\s*\(([^()]*)\)\s*$', name)
    if trailing:
        return f'{name[: trailing.start()]} ({trailing.group(1)}, {platform})'
    return f'{name} ({platform})'


#: What ends a noun phrase. Either side of one of these, two names are listed
#: beside each other rather than one describing the other.
_PHRASE_BREAK = re.compile(r'[,;:.()]|\band\b|\bor\b', re.IGNORECASE)


def _states_platform(component, key: str) -> bool:
    """Whether this component is described as being built with the platform.

    Three things count as saying so, in descending order of deliberateness: the
    name already carries the platform, a stack was declared beside the name as in
    "User Service (Node.js + Express)", or the description puts the two words in
    one phrase, as "React web portal" does.

    Appearing in the same description is not one of them. "React, Azure AD, API
    Gateway, Node.js, HL7 FHIR API, Redis and PostgreSQL support patient records"
    mentions every name in every component's description, and reading that as
    evidence would fold an inventory of ten systems into one.
    """
    pattern = rf'\b{re.escape(key)}\b'
    if re.search(pattern, str(component.name or ''), re.IGNORECASE):
        return True
    if re.search(pattern, str((component.properties or {}).get('tech_stack') or ''), re.IGNORECASE):
        return True

    description = str(component.description or '')
    host_tokens = tokens_of(str(component.name or ''), component.id) - tokens_of(key)
    if not host_tokens:
        return False
    for match in re.finditer(pattern, description, re.IGNORECASE):
        if _same_phrase(description[match.end():match.end() + 60], host_tokens, leading=True):
            return True
        if _same_phrase(description[max(0, match.start() - 60):match.start()], host_tokens, leading=False):
            return True
    return False


def _same_phrase(window: str, host_tokens: frozenset, leading: bool) -> bool:
    """Whether the host is named inside the same noun phrase as the platform."""
    breaks = list(_PHRASE_BREAK.finditer(window))
    if breaks:
        window = window[:breaks[0].start()] if leading else window[breaks[-1].end():]
    return bool(tokens_of(window) & host_tokens)


def _platform_display_name(platform, key: str) -> str:
    """How the platform should read on a label the reviewer sees."""
    if key in PLATFORM_DISPLAY_NAMES:
        return PLATFORM_DISPLAY_NAMES[key]
    name = str(platform.name or key).strip()
    # The label is read by a person, so it needs a capital letter. A pass that
    # produced a name by lowercasing gives none, and the raw key gives none
    # either, which is how a service came to be labelled "(express)".
    return name if any(character.isupper() for character in name) else key.title()


def _platform_key(component) -> str:
    # The technology a pass recorded is the platform's own spelling. An id cannot
    # be: "node.js" survives extraction as `node_js`, which reads as "node js"
    # and matches nothing.
    candidates = (
        str((component.properties or {}).get('technology') or '').lower(),
        component.id.replace('_', ' '),
        str(component.name or '').lower(),
    )
    for candidate in candidates:
        if candidate in PLATFORM_TECHNOLOGIES:
            return candidate
    return component.id.replace('_', ' ')


def _same_role(survivor, removed) -> bool:
    """Two names denote one node only if they play the same architectural role."""
    return survivor.type == removed.type or 'unknown' in {survivor.type, removed.type}


def _absorb(survivor, removed) -> None:
    """Keep what the removed node knew that the survivor does not.

    Security-relevant facts are never downgraded: a node known to be external or
    internet-facing under one name stays that way under the other.
    """
    for key, value in (removed.properties or {}).items():
        if value in (None, '', [], {}) or key == 'technology':
            continue
        current = survivor.properties.get(key)
        if current in (None, '', [], {}, 'unknown'):
            survivor.properties[key] = value
        elif key in {'external', 'public_access', 'third_party_integration', 'internet_facing'}:
            survivor.properties[key] = bool(current) or bool(value)
    aliases = survivor.properties.setdefault('merged_aliases', [])
    for alias in [removed.id, *(removed.properties or {}).get('merged_aliases', [])]:
        if alias not in aliases:
            aliases.append(alias)
    if len(str(removed.description or '')) > len(str(survivor.description or '')):
        survivor.description = removed.description


def richer_name(candidate: Dict[str, Any], existing) -> Optional[str]:
    """Return the fuller name when a candidate names an existing node better.

    "React" and "React web portal" are the same client, and the second name is
    the one the design used. Only the label changes; the id stays stable so that
    findings and flows keep referring to the same node.
    """
    existing_tokens = tokens_of(str(existing.name or ''))
    candidate_tokens = tokens_of(candidate['name'])
    if candidate_tokens > existing_tokens and tokens_of(existing.id) <= candidate_tokens:
        return candidate['name']
    return None


def name_from_description(component) -> Optional[str]:
    """Recover a component's full name from the sentence that introduced it."""
    for candidate in find_named_roles(str(component.description or '')):
        if candidate['type'] != component.type:
            continue
        better = richer_name(candidate, component)
        if better:
            return better
    return None

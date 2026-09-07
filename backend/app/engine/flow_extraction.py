"""Read the data flows a description actually states.

Type-based templates can guess that services talk to databases, but a guess and
a statement are not the same evidence. A described flow tells the reviewer where
data really crosses a boundary; a guessed one can invent a path that does not
exist and hide the one that does. This module extracts the stated flows so the
templates are only needed where the description is silent.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from .component_roles import ROLE_TYPES
from .prose import unwrap

# Verb phrases that place data between two named components. ``reversed`` marks
# a phrase where the grammatical subject receives the data, as in "the worker
# consumes from the queue", so the flow is drawn from the queue.
FLOW_VERBS: Tuple[Tuple[str, str, bool], ...] = (
    (r'calls?(?:\s+(?:out\s+)?to)?', 'HTTPS', False),
    (r'invokes?', 'HTTPS', False),
    (r'requests?\s+(?:data\s+)?from', 'HTTPS', True),
    (r'routes?\s+(?:requests?\s+|traffic\s+)?to', 'HTTPS', False),
    (r'forwards?\s+(?:\w+\s+){0,3}?to', 'HTTPS', False),
    (r'proxies\s+(?:\w+\s+){0,3}?to', 'HTTPS', False),
    (r'sends?\s+(?:\w+\s+){0,3}?to', 'HTTPS', False),
    (r'posts?\s+(?:\w+\s+){0,3}?to', 'HTTPS', False),
    (r'pushes\s+(?:\w+\s+){0,3}?to', 'HTTPS', False),
    (r'uploads?\s+(?:\w+\s+){0,3}?to', 'HTTPS', False),
    (r'publishes\s+(?:\w+\s+){0,3}?(?:to|onto|into)', 'TCP', False),
    (r'writes?\s+(?:\w+\s+){0,3}?(?:to|into)', 'TCP', False),
    (r'stores?\s+(?:\w+\s+){0,3}?(?:in|into|on|to)', 'TCP', False),
    (r'persists?\s+(?:\w+\s+){0,3}?(?:in|into|to)', 'TCP', False),
    (r'caches?\s+(?:\w+\s+){0,3}?(?:in|into)', 'TCP', False),
    (r'queries', 'TCP', False),
    (r'reads?\s+(?:\w+\s+){0,3}?from', 'TCP', True),
    (r'reads?', 'TCP', True),
    (r'loads?\s+(?:\w+\s+){0,3}?from', 'TCP', True),
    (r'fetches\s+(?:\w+\s+){0,3}?from', 'HTTPS', True),
    (r'pulls?\s+(?:\w+\s+){0,3}?from', 'HTTPS', True),
    (r'retrieves?\s+(?:\w+\s+){0,3}?from', 'HTTPS', True),
    (r'consumes?\s+(?:\w+\s+){0,3}?from', 'TCP', True),
    (r'consumes?', 'TCP', True),
    (r'subscribes?\s+to', 'TCP', True),
    (r'authenticates?\s+(?:\w+\s+){0,3}?(?:against|with|via|through|using)', 'HTTPS', False),
    (r'connects?\s+to', 'TCP', False),
    (r'communicates?\s+with', 'HTTPS', False),
    (r'exchanges?\s+(?:\w+\s+){0,3}?with', 'HTTPS', False),
    (r'integrates?\s+with', 'HTTPS', False),
    (r'replicates?\s+(?:\w+\s+){0,3}?to', 'TCP', False),
    (r'streams?\s+(?:\w+\s+){0,3}?to', 'TCP', False),
    (r'ships?\s+(?:\w+\s+){0,3}?to', 'HTTPS', False),
    (r'exports?\s+(?:\w+\s+){0,3}?to', 'HTTPS', False),
)

_VERB_RE = re.compile(
    '|'.join(f'(?P<v{index}>\\b{pattern}\\b)' for index, (pattern, _, _) in enumerate(FLOW_VERBS)),
    re.IGNORECASE,
)

# Words that never identify a component on their own when matching mentions.
_WEAK_TOKENS = frozenset({
    'the', 'a', 'an', 'and', 'or', 'to', 'from', 'in', 'on', 'at', 'of', 'for',
    'with', 'via', 'over', 'app', 'apps', 'data', 'new', 'all', 'both', 'that',
    'this', 'its', 'their', 'our', 'is', 'are', 'it', 'them', 'service',
    'services', 'system', 'systems', 'user', 'users',
})

_PROTOCOL_OVERRIDES: Tuple[Tuple[str, str], ...] = (
    (r'\bmtls\b|\bmutual\s+tls\b', 'MTLS'),
    (r'\bgrpcs\b|\bgrpc\s+(?:over|with)\s+tls\b', 'GRPCS'),
    (r'\bwss\b|\bsecure\s+websockets?\b', 'WSS'),
    (r'\bws\b', 'WS'),
    (r'\btls\b', 'TLS'),
    (r'\bover\s+https\b|\bvia\s+https\b|\bhttps\b', 'HTTPS'),
    (r'\bover\s+http\b(?!s)|\bplain\s+http\b', 'HTTP'),
    (r'\bgrpc\b', 'GRPC'),
    (r'\bwebsockets?\b', 'WS'),
    (r'\bamqp\b', 'AMQP'),
    (r'\bmqtt\b', 'MQTT'),
    (r'\bsftp\b', 'SFTP'),
    (r'\bftp\b(?!s)', 'FTP'),
    (r'\bjdbc\b|\bodbc\b|\bsql\b', 'TCP'),
)


def _clean(name: str) -> str:
    return ' '.join(
        word for word in re.split(r'[^A-Za-z0-9.+#-]+', (name or '').lower())
        if word and word not in _WEAK_TOKENS
    )


def aliases_for(component) -> List[str]:
    """Phrases in a description that refer to this component."""
    names = {
        str(component.name or ''),
        component.id.replace('_', ' '),
        str((component.properties or {}).get('technology') or ''),
    }
    names.update(
        str(alias).replace('_', ' ')
        for alias in (component.properties or {}).get('merged_aliases', [])
    )
    # Two characters is enough for a real component name such as "s3".
    phrases = [cleaned for cleaned in map(_clean, names) if len(cleaned) > 1]
    # The longest phrase is tried first so "payments service" wins over
    # "payments" when both could match at the same position.
    return sorted(set(phrases), key=len, reverse=True)


def _partial_aliases(component) -> List[str]:
    """Shorter ways the same component is referred to later in a description.

    A design introduces the "FastAPI Orchestration Service" once and calls it
    "the orchestration service" from then on. Without those references the
    component appears to take part in nothing.
    """
    partials = []
    for phrase in aliases_for(component):
        words = phrase.split()
        for start in range(1, len(words)):
            tail = ' '.join(words[start:])
            if len(tail) > 4:
                partials.append(tail)
    return partials


def _role_aliases(components: Dict[str, Any]) -> Dict[str, set]:
    """The bare role noun as a reference, where only one component can answer it.

    A description introduces "a Node.js REST API" and then says "the API stores
    records in Postgres". The role noun is stripped from the component's name
    because on its own it identifies nothing - unless the model holds exactly one
    component of that type, when it identifies that one and nothing else. Without
    this the later sentences have no subject, and flows the description states
    are dropped and then guessed.
    """
    by_type: Dict[str, set] = {}
    for component_id, component in components.items():
        by_type.setdefault(str(component.type or '').lower(), set()).add(component_id)
    owners: Dict[str, set] = {}
    for noun, component_type in ROLE_TYPES.items():
        owning = by_type.get(component_type.lower(), set())
        cleaned = _clean(noun)
        if len(owning) == 1 and cleaned and len(cleaned) > 1:
            owners.setdefault(cleaned, set()).update(owning)
    return owners


def alias_index(components: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Phrase to component id, longest phrase first and ambiguity removed.

    A partial name is only usable when it can mean one component. Where two
    components would answer to "payments service" the short form is dropped and
    both keep their full names, because guessing between them would attach data
    flows and findings to the wrong element.
    """
    owners: Dict[str, set] = {}
    for component_id, component in components.items():
        for phrase in aliases_for(component):
            owners.setdefault(phrase, set()).add(component_id)
    for component_id, component in components.items():
        for phrase in _partial_aliases(component):
            if phrase in owners and component_id not in owners[phrase]:
                owners[phrase].add(component_id)
            elif phrase not in owners:
                owners[phrase] = {component_id}
    # A role noun is the weakest reference, so it never displaces a name: it is
    # only added where nothing else claims the phrase.
    for phrase, owning in _role_aliases(components).items():
        owners.setdefault(phrase, set()).update(owning)
    return sorted(
        ((phrase, next(iter(ids))) for phrase, ids in owners.items() if len(ids) == 1),
        key=lambda entry: len(entry[0]),
        reverse=True,
    )


def _mention_pattern(phrase: str) -> str:
    """Match a component name, allowing a plural on words long enough to take one.

    A short name is matched exactly: "s3" must not also match "s3x".
    """
    words = phrase.split()
    tail = r'(?:s|es)?' if len(words[-1]) > 3 else ''
    return r'\b' + r'\s+'.join(re.escape(word) for word in words) + tail + r'\b'


def find_mentions(clause: str, index: List[Tuple[str, str]]) -> List[Tuple[int, int, str]]:
    """Positions in the clause where each component is named.

    Longer phrases claim their span first, so "payments service" is one mention
    rather than a "payments" mention inside a "service" mention.
    """
    found: List[Tuple[int, int, str]] = []
    claimed: List[Tuple[int, int]] = []
    for phrase, component_id in index:
        if any(component_id == existing for _, _, existing in found):
            continue
        for match in re.finditer(_mention_pattern(phrase), clause, re.IGNORECASE):
            if any(match.start() < end and start < match.end() for start, end in claimed):
                continue
            found.append((match.start(), match.end(), component_id))
            claimed.append((match.start(), match.end()))
            break
    return sorted(found)


def _protocol_in(clause: str, default: str) -> str:
    for pattern, protocol in _PROTOCOL_OVERRIDES:
        if re.search(pattern, clause, re.IGNORECASE):
            return protocol
    return default


def _verb_at(match: re.Match) -> Tuple[str, bool]:
    for index, (_, protocol, is_reversed) in enumerate(FLOW_VERBS):
        if match.group(f'v{index}'):
            return protocol, is_reversed
    return 'HTTPS', False


_SENTENCE_SPLIT_RE = re.compile(r'(?<=[.!?;])\s+|[\r\n]+')

# A comma and a conjunction may begin a statement with its own subject, or may
# continue a list of verbs belonging to the subject already named.
_CANDIDATE_BOUNDARY_RE = re.compile(
    r',\s+(?:and|then|while|whereas|before|after)\s+', re.IGNORECASE,
)

# Words that introduce a circumstance rather than an actor, so what follows them
# is not the subject of the coming verb: "and, after validation, stores it in
# Postgres" is still the previous subject storing something.
_NOT_A_SUBJECT_LEAD = re.compile(
    r'^(?:after|before|during|while|when|once|upon|if|since|because|on|in|at|for|'
    r'with|without|via|over|through|by|from|to|as)\b',
    re.IGNORECASE,
)

# Adverbs that may stand between the conjunction and the subject without being
# one, so they are stripped before deciding whether a subject is present.
_LEADING_ADVERB = re.compile(
    r'^(?:then|also|subsequently|finally|immediately|afterwards?|next|later|'
    r'in\s+turn|meanwhile)\b[\s,]*',
    re.IGNORECASE,
)


def _introduces_its_own_subject(fragment: str) -> bool:
    """True when this fragment names the actor of its own verb.

    "a worker consumes from Kafka" does; "uploads documents to S3" does not, and
    detaching the latter from the subject it shares strands the verb. A stranded
    verb has one named component instead of two, so the flow is dropped here and
    guessed by a type template later - which is how a described path became an
    assumption pointing somewhere else.
    """
    stripped = _LEADING_ADVERB.sub('', fragment.lstrip())
    verb = _VERB_RE.search(stripped)
    if verb is None:
        return True
    before = stripped[:verb.start()].strip(' ,')
    return bool(before) and not _NOT_A_SUBJECT_LEAD.match(before)


def _statements(sentence: str) -> List[str]:
    """Split a sentence only where a new subject actually takes over."""
    parts: List[str] = []
    cursor = 0
    for boundary in _CANDIDATE_BOUNDARY_RE.finditer(sentence):
        if not _introduces_its_own_subject(sentence[boundary.end():]):
            continue
        parts.append(sentence[cursor:boundary.start()])
        cursor = boundary.end()
    parts.append(sentence[cursor:])
    return parts


def _clauses(text: str) -> List[str]:
    for sentence in _SENTENCE_SPLIT_RE.split(unwrap(text)):
        for part in _statements(sentence):
            statement = ' '.join((part or '').split())
            if statement:
                yield statement


def extract_stated_flows(text: str, components: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the flows the description states, each with its own evidence.

    A subject is the component named closest before the verb and the object is
    the one named closest after it, which is how these sentences are written:
    "the settlement worker consumes from Kafka and writes files to S3" states two
    flows, both owned by the worker.
    """
    index = alias_index(components)
    stated: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def record(source: str, sink: str, protocol: str, clause: str, verb: str, transport_text: str = None) -> None:
        if source == sink or (source, sink) in stated:
            return
        stated[(source, sink)] = {
            'source_id': source,
            'target_id': sink,
            'protocol': _protocol_in(clause if transport_text is None else transport_text, protocol),
            'evidence': clause,
            'verb': verb,
        }

    for clause in _clauses(text):
        mentions = find_mentions(clause, index)
        if len(mentions) < 2:
            continue
        for source, sink, protocol, verb in _routed(clause, mentions):
            record(source, sink, protocol, clause, verb)

        verbs = list(_VERB_RE.finditer(clause))
        subjects: List[str] = []
        objects: set = set()
        for position, verb in enumerate(verbs):
            protocol, is_reversed = _verb_at(verb)
            next_verb = verbs[position + 1] if position + 1 < len(verbs) else None
            if re.search(r'\b(?:not|never|cannot|can\x27t|don\x27t|doesn\x27t)\s+(?:directly\s+)?$', clause[:verb.start()], re.IGNORECASE):
                continue
            relative = _relative_subject(clause, mentions, verb)
            if relative is not None:
                subjects = [relative]
            else:
                # A component already named as an object cannot become the subject of
                # the next verb: in "stores transactions in Postgres and publishes
                # events to Kafka" the publisher is still the original subject.
                before = [
                    entry for entry in mentions
                    if entry[1] <= verb.start() and entry[2] not in objects
                ]
                if before:
                    subjects = _coordinated(clause, before, components)
            limit = next_verb.start() if next_verb else len(clause)
            targets = _targets_of(clause, mentions, verb, limit, components)
            if not subjects or not targets:
                continue
            for subject in subjects:
                for target in targets:
                    objects.add(target)
                    source, sink = (target, subject) if is_reversed else (subject, target)
                    record(source, sink, protocol, clause, ' '.join(verb.group(0).split()).lower(), clause[0 if position == 0 else verb.start():limit])
    return list(stated.values())


# "Documents are ingested from the connector into the landing bucket" states a
# flow between two components without either being the grammatical subject.
_ROUTED_RE = re.compile(
    r'\b(?:is|are|was|were|gets?|get|being|be)\s+(?:\w+\s+){0,2}?'
    r'(?:ingested|imported|copied|replicated|synced|synchronized|loaded|exported|'
    r'moved|transferred|streamed|forwarded|routed|published|pushed|pulled|sent|'
    r'delivered|written|uploaded|fed)\s+'
    r'(?P<direction>from|to|into)\b',
    re.IGNORECASE,
)


def _routed(clause: str, mentions: List[Tuple[int, int, str]]) -> List[Tuple[str, str, str, str]]:
    """Flows stated without a subject, as "A is copied from B to C"."""
    flows = []
    for match in _ROUTED_RE.finditer(clause):
        after = [entry for entry in mentions if entry[0] >= match.end()]
        if len(after) < 2:
            continue
        if match.group('direction').lower() == 'from':
            source, sink = after[0][2], after[1][2]
        else:
            source, sink = after[1][2], after[0][2]
        flows.append((source, sink, 'HTTPS', ' '.join(match.group(0).split()).lower()))
    return flows


_COORDINATION_RE = re.compile(
    r'[\s,]*(?:and|or|,|&|as well as|along with|together with)[\s,]*'
    r'(?:the|a|an|its|their|our|both)?[\s,]*',
    re.IGNORECASE,
)

# "an API gateway which routes to the payments service": the pronoun stands for
# the noun just named, making it the subject of the verb that follows.
_RELATIVE_RE = re.compile(
    r'^[\s,]*(?:(?:over|via|using)\s+\w+[\s,]+)?(?:which|that|who)\s*$', re.IGNORECASE,
)


def _relative_subject(
    clause: str, mentions: List[Tuple[int, int, str]], verb: re.Match
) -> Any:
    """The component a relative pronoun makes the subject of this verb.

    Needed because such a component usually arrived as the object of the
    previous verb, and objects are otherwise barred from becoming subjects.
    Without this, "a portal calls a gateway which routes to a service" reads as
    the portal calling the service directly, drawing a path past the gateway
    that the design does not have.
    """
    preceding = [entry for entry in mentions if entry[1] <= verb.start()]
    if not preceding:
        return None
    _, end, component_id = preceding[-1]
    return component_id if _RELATIVE_RE.match(clause[end:verb.start()]) else None


# Role nouns that name no component on their own and are therefore dropped from
# aliases. Because they are dropped, a mention spans "accounts" and leaves the
# word "service" trailing it. They have to be ignored here too: otherwise "a
# payments service and an accounts service" has the word "service" sitting
# between the two mentions, hiding the conjunction that joins them. Conjunctions
# and prepositions are deliberately absent, since those are what this is reading.
_TRAILING_ROLE_NOUNS = frozenset({
    'app', 'apps', 'data', 'service', 'services', 'system', 'systems',
    'user', 'users',
})


def _between(
    clause: str, earlier: Tuple[int, int, str], later: Tuple[int, int, str],
    components: Dict[str, Any],
) -> str:
    """The words separating two mentions, less the rest of their own noun phrases.

    A mention spans the name only, so "an iOS mobile app" leaves "mobile app"
    lying between it and its neighbour; those words say nothing about how the
    two relate and would hide the conjunction that does.
    """
    text = clause[earlier[1]:later[0]]
    for component_id in (later[2], earlier[2]):
        for phrase in aliases_for(components[component_id]):
            for word in phrase.split():
                text = re.sub(_mention_pattern(word), ' ', text, flags=re.IGNORECASE)
    for noun in _TRAILING_ROLE_NOUNS:
        text = re.sub(_mention_pattern(noun), ' ', text, flags=re.IGNORECASE)
    return text


def _coordinated(
    clause: str, before: List[Tuple[int, int, str]], components: Dict[str, Any]
) -> List[str]:
    """Return every component sharing the subject position of one verb.

    "A React web portal and an iOS mobile app call an API gateway" states two
    flows. Coordinated subjects are the run of mentions before the verb separated
    only by a conjunction, allowing for the rest of each component's own noun
    phrase: only the word "mobile" is matched in "an iOS mobile app".
    """
    subjects = [before[-1][2]]
    for earlier, later in zip(reversed(before[:-1]), reversed(before[1:])):
        if not _COORDINATION_RE.fullmatch(_between(clause, earlier, later, components)):
            break
        subjects.insert(0, earlier[2])
    return subjects


def _targets_of(
    clause: str, mentions: List[Tuple[int, int, str]], verb: re.Match, limit: int,
    components: Dict[str, Any],
) -> List[str]:
    """The components this verb sends data to.

    Only the run of names joined to the first one by a conjunction receives the
    data. Every mention up to the next verb is too many: in "routes to a
    payments service backed by an Aurora database and an S3 bucket", the
    database and the bucket describe what stands behind the service rather than
    what the gateway routes to, and reading all three as destinations puts two
    paths into the model that nobody described.
    """
    after = [entry for entry in mentions if verb.end() <= entry[0] < limit]
    if not after:
        return []
    targets = [after[0][2]]
    for earlier, later in zip(after, after[1:]):
        if not _COORDINATION_RE.fullmatch(_between(clause, earlier, later, components)):
            break
        targets.append(later[2])
    return targets

"""The shape of written descriptions: where sentences really begin and end.

Architecture descriptions arrive wrapped at a margin, so a newline is not a
sentence boundary. Treating it as one silently truncates statements: "there is
no MFA on the clinician / portal" becomes a claim about "the clinician", which
matches no component, and the weakness is attributed to nothing at all.

Every pass that reads statements out of prose therefore segments text through
here, so they all agree on what one sentence is.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import List, Tuple

# A line that continues the previous one rather than starting a statement.
_CONTINUATION_RE = re.compile(r'^\s*(?:and|or|but|which|that|who|to|into|from|then)\b|^\s*[a-z]')

# Beyond this a line without closing punctuation was wrapped by a margin rather
# than written as an item. It lets a sentence broken before a capitalized name
# be rejoined: "writes the ledger to an Aurora / PostgreSQL database and stores
# receipts in S3" otherwise parses as two statements, the second of which has
# the database as its subject and states that the database writes to the bucket.
_WRAPPED_LINE_LENGTH = 55

_SENTENCE_SPLIT = re.compile(r'(?<=[.!?])\s+|[\r\n]+')

# A comma followed by a new noun phrase begins a claim about something else:
# "there is no MFA on the portal, the audit log is writable, and the partner
# reuses a credential" is three weaknesses on three components, and reading it
# as one sentence attributes all three to the portal.
_NEW_CLAUSE = re.compile(
    r',\s*(?:and\s+|but\s+|while\s+|whereas\s+)?'
    r'(?=(?:the|a|an|its|their|our|this|that|these|those|all|every|each)\s+[a-z])',
    re.IGNORECASE,
)

# A conjunction with no comma before it does the same work: "the portal has no
# MFA and the ingestion bucket is not encrypted at rest" states one weakness
# about each. Read as a single clause, both attach to whichever component the
# sentence named first, and the bucket's finding is filed against the portal.
_JOINED_CLAUSE = re.compile(
    r'\s+(?:and|but|while|whereas)\s+'
    r'(?=(?:the|a|an|its|their|our|this|that|these|those|all|every|each)\s+[a-z])',
    re.IGNORECASE,
)

# Without a comma the conjunction is more often extending the verb's object -
# "sends records to the database and the bucket" names two destinations, not two
# claims - so a second claim has to show a predicate of its own. Third-person
# singular verbs are matched generally because the vocabulary of an architecture
# description is open; a bare noun phrase has no such word.
_HAS_PREDICATE = re.compile(
    r'\b(?:is|are|was|were|be|been|being|has|have|had|does|do|did|can|could|'
    r'may|might|must|should|would|will|shall|lacks?|remains?|stays?|'
    r'\w{3,}(?:es|s))\b\s+(?!of\b|for\b|in\b|to\b)',
    re.IGNORECASE,
)


@lru_cache(maxsize=512)
def unwrap(text: str) -> str:
    """Rejoin lines that a margin broke, leaving deliberate lines alone."""
    joined: List[str] = []
    for line in (text or '').splitlines():
        previous = joined[-1].rstrip() if joined else ''
        if (
            joined
            and line.strip()
            and not previous.endswith(('.', '!', '?', ':', ';'))
            and not line.lstrip().startswith(('-', '*', '#', '|'))
            and (_CONTINUATION_RE.match(line) or len(previous) >= _WRAPPED_LINE_LENGTH)
        ):
            joined[-1] = f'{previous} {line.strip()}'
        else:
            joined.append(line)
    return '\n'.join(joined)


@lru_cache(maxsize=512)
def sentences(text: str) -> Tuple[str, ...]:
    """The sentences of the text, each on one line and wrapping undone."""
    return tuple(
        statement
        for statement in (
            ' '.join(segment.split()) for segment in _SENTENCE_SPLIT.split(unwrap(text))
        )
        if statement
    )


def architecture_assertions(text: str) -> str:
    """Omit explicit non-deployment clauses, not missing-control statements.

    The original input remains the evidence source. This view is for entity
    discovery, where a negated technology mention is not a deployed component.
    """
    # Preserve bullets, wrapping, delimiters and source offsets. Formatting can
    # determine whether the next line is a separate component or a modifier.
    parts = re.split(r'((?<=[.!?])\s+|;\s*|\s+(?:but|whereas)\s+|\r?\n)', text, flags=re.IGNORECASE)
    for index in range(0, len(parts), 2):
        clause = parts[index]
        stripped = clause.strip(' -*')
        # Non-deployment is different from a component not using a control.
        # Leave the latter intact for the control-polarity reader.
        if re.search(
            r'\b(?:authentication|authorization|mfa|2fa|encryption|tls|mtls|'
            r'validation|sanitization|rate limiting|audit logging|rotation)\b',
            clause, re.IGNORECASE,
        ):
            continue
        not_deployed = re.match(
            r'^(?:there\s+(?:is|are)\s+)?no\s+.+?\s+(?:(?:is|are)\s+)?'
            r'(?:used|deployed|present|installed|in\s+scope)\b'
            r'|^.+?\s+(?:is|are)\s+not\s+(?:used|deployed|present|installed|in\s+scope)\b',
            stripped, re.IGNORECASE,
        )
        if not_deployed:
            parts[index] = ' ' * len(clause)
            continue
        unused = re.search(
            r'\b(?:do|does|did)\s+not\s+(?:use|deploy|run|integrate)\b'
            r'|\b(?:don\x27t|doesn\x27t)\s+(?:use|deploy|run|integrate)\b',
            clause, re.IGNORECASE,
        )
        if unused:
            parts[index] = clause[:unused.start()] + ' ' * (len(clause) - unused.start())
    return ''.join(parts)


def divide_on_new_subject(sentence: str) -> List[str]:
    """Split where a conjunction hands the sentence to a new subject."""
    parts: List[str] = []
    cursor = 0
    for boundary in _JOINED_CLAUSE.finditer(sentence):
        if not _HAS_PREDICATE.search(sentence[boundary.end():]):
            continue
        parts.append(sentence[cursor:boundary.start()])
        cursor = boundary.end()
    parts.append(sentence[cursor:])
    return parts


@lru_cache(maxsize=512)
def clauses(text: str) -> Tuple[str, ...]:
    """Sentences, divided again wherever a claim about something else begins."""
    return tuple(
        clause
        for sentence in sentences(text)
        for comma_part in _NEW_CLAUSE.split(sentence)
        for part in divide_on_new_subject(comma_part)
        for clause in (part.strip(' ,;'),)
        if clause
    )

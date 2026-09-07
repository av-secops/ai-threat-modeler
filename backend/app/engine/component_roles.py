"""Shared vocabulary for recognizing explicitly named architecture components.

Registries can enumerate technologies and well-known platforms, but they cannot
enumerate product-specific names such as "Settlement Worker" or "Admin Portal".
This module recognizes those from a qualifier plus a role noun so that the
parser and the extraction challenger agree on what counts as explicitly named.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from . import technology_catalog

# Role noun -> canonical component type. Types are restricted to the vocabulary
# the STRIDE coverage engine already understands so every recognized component
# receives a full applicability assessment.
ROLE_TYPES: Dict[str, str] = {
    "api gateway": "API Gateway",
    "load balancer": "Load Balancer",
    "identity provider": "Identity Provider",
    "data warehouse": "Database",
    "data store": "Database",
    "datastore": "Database",
    "web application": "WebClient",
    "web app": "WebClient",
    "message broker": "Queue",
    "event bus": "Queue",
    "microservice": "Service",
    "portal": "WebClient",
    "dashboard": "WebClient",
    "console": "WebClient",
    "gateway": "API Gateway",
    "api": "API",
    "endpoint": "API",
    "database": "Database",
    "warehouse": "Database",
    "repository": "Database",
    "cache": "Database",
    "search index": "Database",
    "vector store": "Database",
    "vector index": "Database",
    # Stored objects are a first-class target: a bucket carries the exposure and
    # encryption questions of storage, and leaving it unnamed removed both.
    "object storage": "Object Storage",
    "object store": "Object Storage",
    "blob storage": "Object Storage",
    "blob store": "Object Storage",
    "file store": "Object Storage",
    "data lake": "Object Storage",
    "bucket": "Object Storage",
    "secrets store": "Secrets Manager",
    "secret store": "Secrets Manager",
    "key vault": "Secrets Manager",
    "queue": "Queue",
    "topic": "Queue",
    "stream": "Queue",
    "broker": "Queue",
    "service": "Service",
    # An organisation on the other side of an integration is a component of the
    # model: it holds credentials and sends data in. Leaving it unnamed left the
    # weaknesses stated about it with nowhere to be recorded.
    "partner": "Service",
    "partner system": "Service",
    "worker": "Service",
    "processor": "Service",
    "orchestrator": "Service",
    "scheduler": "Service",
    "engine": "Service",
    "handler": "Service",
    "consumer": "Service",
    "producer": "Service",
    "pipeline": "Service",
    "connector": "Service",
    "adapter": "Service",
    "collector": "Service",
    "proxy": "Service",
    "daemon": "Service",
}

# Words that can qualify a role noun without identifying a distinct component.
# "public API gateway" is the same node as "API gateway"; "payments service" is
# not the same node as "service".
NON_IDENTIFYING = frozenset({
    "the", "a", "an", "this", "that", "these", "those", "its", "their", "our",
    "your", "his", "her", "my",
    "same", "other", "another", "each", "every", "any", "all", "some", "both",
    "single", "one", "two", "new", "old", "existing", "following", "above",
    "below", "internal", "external", "public", "private", "upstream",
    "downstream", "main", "primary", "secondary", "shared", "central",
    "common", "generic", "separate", "individual", "additional", "relevant",
    "appropriate", "given", "certain", "specific", "multiple", "several",
    "many", "few", "various", "dedicated", "whole", "entire", "full",
    "complete", "respective", "corresponding", "customer-facing", "message",
    "self-hosted", "managed", "hosted", "third-party", "third", "party",
    "partner", "vendor", "legacy", "modern", "core", "own", "only", "just",
    "and", "or", "of", "to", "from", "via", "over", "with", "without", "into",
    "onto", "through", "by", "for", "in", "on", "at", "as", "is", "are", "was",
    "were", "be", "been", "being", "has", "have", "had", "does", "do", "did",
    "can", "could", "will", "would", "should", "may", "might", "must",
    "calls", "call", "sends", "send", "stores", "store", "reads", "read",
    "writes", "write", "forwards", "forward", "queries", "query", "publishes",
    "publish", "consumes", "consume", "ships", "ship", "uses", "use", "runs",
    "run", "exposes", "expose", "returns", "return", "receives", "receive",
    "accepts", "accept", "provides", "provide", "handles", "handle",
    "connects", "connect", "hosts", "host", "serves", "serve",
    "logs", "log",
    "also", "then", "there", "here", "when", "where", "which", "who", "whose",
    "what", "how", "why", "but", "not", "no",
})

EXTERNAL_MARKERS = frozenset({
    "third-party", "thirdparty", "external", "partner", "vendor", "upstream",
})

# Roles that are outside the trust boundary by definition, however they are
# qualified: a "laboratory partner" is another organisation.
EXTERNAL_ROLES = frozenset({"partner", "partner system"})

_ACRONYMS = frozenset({"api", "siem", "idp", "waf", "cdn", "ui", "iam", "sso", "mcp"})

_ROLE_ALTERNATION = "|".join(
    re.escape(role) for role in sorted(ROLE_TYPES, key=len, reverse=True)
)
# Sentence punctuation is excluded from the qualifier so a name can never be
# assembled across a sentence boundary.
# A trailing role noun is the head of the phrase: "payment processor API" is an
# API, not a service. The optional second role captures that head.
_NAMED_ROLE_RE = re.compile(
    r"\b((?:[A-Za-z][A-Za-z0-9/-]*\s+){1,3})(" + _ROLE_ALTERNATION + r")s?"
    r"(?:\s+(" + _ROLE_ALTERNATION + r")s?)?(?![a-z])",
    re.IGNORECASE,
)


def _slug(value: str) -> str:
    return re.sub(r"_+", "_", re.sub(r"[^a-z0-9]+", "_", value.lower())).strip("_")


def _display(word: str) -> str:
    lowered = word.lower()
    if lowered in _ACRONYMS:
        return lowered.upper()
    if word.isupper() and len(word) <= 5:
        return word
    return "-".join(part[:1].upper() + part[1:] for part in word.split("-"))


def _is_identifying(word: str) -> bool:
    lowered = word.lower().strip(".,;:()[]\"'")
    if lowered in NON_IDENTIFYING or lowered in ROLE_TYPES:
        return False
    # A vendor name is identifying however short it is. Dropping "S3" from "an S3
    # receipts bucket" left the bucket and the storage service looking like two
    # components, because neither name shared a word with the other.
    if len(lowered) < 3 and not technology_catalog.classify(lowered):
        return False
    return bool(re.match(r"^[a-z][a-z0-9-]*$", lowered))


def tokens_of(*values: str) -> frozenset:
    """Token set used to decide whether two component names denote one node."""
    joined = " ".join(value or "" for value in values)
    return frozenset(token for token in re.split(r"[^a-z0-9]+", joined.lower()) if token)


# Placeholders created from a bare architecture noun. A named component is meant
# to supersede these, so they never count as existing representation.
GENERIC_PLACEHOLDER_IDS = frozenset({
    "api", "rest_api", "service", "microservice", "web_application",
    "database", "queue", "frontend", "mobile_app",
})


def representative_of(candidate: Dict[str, Any], components):
    """Return the extracted component that already denotes the candidate's node.

    ``components`` is any iterable of objects exposing ``id``, ``name`` and
    ``type``. ``None`` means the candidate is a node in its own right.
    """
    for component in components:
        if component.id in GENERIC_PLACEHOLDER_IDS:
            continue
        tokens = tokens_of(component.id, component.name)
        # A broader existing name covers the candidate, for example
        # "Payment Processor" against a candidate "Payment API".
        if tokens >= candidate["tokens"]:
            return component
        # Same type and a shared qualifier means one node named two ways, for
        # example "RabbitMQ" against a candidate "RabbitMQ Message Queue".
        if component.type == candidate["type"] and tokens & candidate["tokens"]:
            return component
    return None


def already_represented(candidate: Dict[str, Any], components) -> bool:
    """True when an extracted component already denotes the candidate's node."""
    return representative_of(candidate, components) is not None


def _closest_qualifiers(words: List[str], limit: int = 2) -> List[str]:
    """The qualifiers nearest the role noun, without splitting a name in half.

    A long clause should not become a component name, so only the closest few
    words are kept. Counting words alone cuts "Java Spring Boot payments service"
    down to "Boot payments service", which names a framework's second half. The
    cut is therefore moved left until it no longer falls inside a phrase the
    catalog recognizes as one thing.
    """
    if len(words) <= limit:
        return words
    start = len(words) - limit
    while start > 0 and technology_catalog.names_one_thing(words[start - 1], words[start]):
        start -= 1
    return words[start:]


def find_named_roles(text: str) -> List[Dict[str, Any]]:
    """Return explicitly named components implied by qualifier plus role noun."""
    found: Dict[str, Dict[str, Any]] = {}
    for match in _NAMED_ROLE_RE.finditer(text or ""):
        qualifiers = [word for word in re.split(r"\s+", match.group(1).strip()) if word]
        # Only an unbroken run of qualifiers immediately before the role noun
        # actually modifies it. In "going through the API gateway" the verb is
        # separated from the role by a preposition and a determiner, so it names
        # nothing; in "internal admin portal" the adjacent "admin" does.
        identifying: List[str] = []
        for word in reversed(qualifiers):
            if not _is_identifying(word):
                break
            identifying.insert(0, word)
        if not identifying:
            continue
        modifier_role = match.group(2).lower()
        head_role = (match.group(3) or match.group(2)).lower()
        role_words = modifier_role.split() if head_role == modifier_role else (
            modifier_role.split() + head_role.split()
        )
        # Keep the two closest qualifiers so a long clause does not become a name.
        identifying = _closest_qualifiers([word.strip(".,;:()[]\"'") for word in identifying])
        words = identifying + role_words
        component_id = _slug(" ".join(words))
        if not component_id or component_id in found:
            continue
        found[component_id] = {
            "id": component_id,
            "name": " ".join(_display(word) for word in words),
            "type": ROLE_TYPES[head_role],
            "role": head_role,
            "phrase": re.sub(r"\s+", " ", match.group(0).strip()),
            "tokens": tokens_of(" ".join(identifying)),
            "external": (
                any(word.lower() in EXTERNAL_MARKERS for word in qualifiers)
                or head_role in EXTERNAL_ROLES
            ),
        }
    return list(found.values())

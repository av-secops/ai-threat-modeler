"""Optional local generative SLM with a strict, review-only contract."""

from __future__ import annotations

import json
import re
import os
from typing import Any, Dict, List

from . import model_policy
from .stride_coverage_engine import STRIDE_CATEGORIES, StrideCoverageEngine


class StructuredLocalSLM:
    def __init__(self):
        self.model_name = os.getenv("AEGIS_THREAT_LOCAL_SLM_MODEL", "").strip()
        self.pipeline = None
        self.error = None
        if not self.model_name:
            return
        try:
            from transformers import pipeline

            self.pipeline = pipeline(
                os.getenv("AEGIS_THREAT_LOCAL_SLM_TASK", "text2text-generation"),
                model=self.model_name,
                tokenizer=self.model_name,
                **model_policy.transformers_kwargs(self.model_name),
            )
            model_policy.note_model(self.model_name, "local_slm", loaded=True)
        except Exception as exc:
            self.error = str(exc)
            model_policy.note_model(
                self.model_name, "local_slm", loaded=False, error=str(exc),
                fallback="deterministic_engines_only",
            )

    def review(self, architecture, findings) -> Dict[str, Any]:
        if not self.pipeline:
            return {
                "status": "not_configured" if not self.model_name else "unavailable",
                "model": self.model_name or None,
                "accepted_candidates": [],
                "rejected_candidates": 0,
                "finding_authority": False,
                "error": self.error,
            }
        _, coverage = StrideCoverageEngine().assess(architecture, findings, generate_candidates=False)
        unknown = [item for item in coverage["cells"] if item["status"] in {"unknown", "potential"}][:40]
        source = str((architecture.metadata or {}).get("architecture_text") or "")
        prompt = self._prompt(architecture, source, unknown)
        try:
            generated = self.pipeline(prompt, max_new_tokens=1200, do_sample=False)
            content = generated[0].get("generated_text") or generated[0].get("summary_text") or ""
            payload = _parse_json(content)
            accepted, rejected = self.validate_candidates(payload.get("candidates", []), architecture, source, unknown)
            return {
                "status": "active",
                "model": self.model_name,
                "accepted_candidates": accepted,
                "rejected_candidates": rejected,
                "finding_authority": False,
                "error": None,
            }
        except Exception as exc:
            return {
                "status": "failed",
                "model": self.model_name,
                "accepted_candidates": [],
                "rejected_candidates": 0,
                "finding_authority": False,
                "error": str(exc),
            }

    @staticmethod
    def validate_candidates(candidates, architecture, source: str, unknown_cells: List[Dict[str, Any]]):
        element_ids = {
            item.id for item in architecture.components or []
        } | {
            f"flow:{item.source_id}->{item.target_id}" for item in architecture.flows or []
        } | {
            f"asset:{item.name}" for item in architecture.assets or []
        } | {
            f"boundary:{item.name}" for item in architecture.trust_boundaries or []
        }
        unknown = {(item["element_id"], item["category"]) for item in unknown_cells}
        source_lower = source.lower()
        accepted = []
        rejected = 0
        for item in candidates if isinstance(candidates, list) else []:
            if not isinstance(item, dict) or not isinstance(item.get('evidence'), list):
                rejected += 1
                continue
            element_id = str(item.get("element_id") or "")
            category = str(item.get("stride_category") or "")
            evidence = item['evidence']
            if not all(isinstance(value, str) for value in evidence):
                rejected += 1
                continue
            target = next((c for c in architecture.components if c.id == element_id), None)
            def mentioned(names):
                return any(re.search(r'(?<!\w)' + re.escape(name) + r'(?!\w)', quote, re.I) for name in names if name for quote in evidence)
            if target:
                bound = mentioned((target.id, target.name))
            elif element_id.startswith('flow:'):
                endpoints = element_id[5:].split('->')
                components = {c.id: c for c in architecture.components}
                bound = len(endpoints) == 2 and all(cid in components and mentioned((cid, components[cid].name)) for cid in endpoints)
            else:
                bound = mentioned((element_id.partition(':')[2],))
            valid = (
                element_id in element_ids
                and category in STRIDE_CATEGORIES
                and (element_id, category) in unknown
                and evidence
                and bound
                and len(evidence) <= 10 and all(8 <= len(value) <= 2000 for value in evidence)
                and all(value.lower() in source_lower for value in evidence)
            )
            if not valid:
                rejected += 1
                continue
            accepted.append({
                "element_id": element_id,
                "stride_category": category,
                "title": str(item.get("title") or "Local model review candidate")[:240],
                "evidence": evidence,
                "question": str(item.get("question") or "What control confirms or negates this candidate?")[:2000],
                "status": "information_required",
            })
        return accepted, rejected

    @staticmethod
    def _prompt(architecture, source: str, unknown_cells: List[Dict[str, Any]]) -> str:
        elements = [{
            "id": item.id, "name": item.name, "type": item.type,
        } for item in architecture.components or []]
        return (
            "Return JSON only with shape {\"candidates\": [{\"element_id\": \"\", "
            "\"stride_category\": \"\", \"title\": \"\", \"evidence\": [\"verbatim quote\"], "
            "\"question\": \"\"}]}. Use only listed IDs and unknown STRIDE cells. "
            "Every evidence value must be a verbatim substring of SOURCE. Do not assert a vulnerability; "
            "produce review candidates only.\nELEMENTS\n"
            + json.dumps(elements, ensure_ascii=True)
            + "\nUNKNOWN CELLS\n" + json.dumps(unknown_cells, ensure_ascii=True)
            + "\nSOURCE\n" + source
        )


def _parse_json(content: str) -> Dict[str, Any]:
    normalized = content.strip()
    if "```" in normalized:
        normalized = normalized.split("```", 1)[1].split("```", 1)[0].removeprefix("json").strip()
    start = normalized.find("{")
    end = normalized.rfind("}")
    if start < 0 or end < start:
        raise ValueError("Local SLM did not return JSON.")
    value = json.loads(normalized[start:end + 1])
    if not isinstance(value, dict):
        raise ValueError("Local SLM response must be an object.")
    return value

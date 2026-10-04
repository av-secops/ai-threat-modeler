"""Authenticated offline model interchange and snapshot drift. No cloud calls."""

import json
from typing import Literal

import anyio
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field

from .enterprise_api import editor, invoke
from .model_interchange import MAX_BYTES, import_model, export_model, validate_model
from .cloud_drift import compare_drift, snapshot_to_model

MAX_REQUEST_BYTES = 2 * MAX_BYTES + 65536  # Two bounded documents plus compare envelope.


class ModelToolsRequest(Request):
    async def body(self):
        if not hasattr(self, '_body'):
            if self.headers.get('content-encoding', 'identity') != 'identity':
                raise HTTPException(415, 'Use uncompressed JSON for model tools.')
            declared = self.headers.get('content-length')
            if declared is not None:
                try:
                    length = int(declared)
                except ValueError:
                    raise HTTPException(400, 'Invalid Content-Length.') from None
                if length < 0:
                    raise HTTPException(400, 'Invalid Content-Length.')
                if length > MAX_REQUEST_BYTES:
                    raise HTTPException(413, 'Model tools request exceeds the size limit.')
            chunks, size = [], 0
            try:
                with anyio.fail_after(30):
                    async for chunk in self.stream():
                        size += len(chunk)
                        if size > MAX_REQUEST_BYTES:
                            raise HTTPException(413, 'Model tools request exceeds the size limit.')
                        chunks.append(chunk)
            except TimeoutError:
                raise HTTPException(408, 'Model tools request body timed out.') from None
            self._body = b''.join(chunks)
        return self._body

    async def json(self):
        def unique_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate key')
                result[key] = value
            return result

        def reject_constant(_value):
            raise ValueError('non-finite value')

        if not hasattr(self, '_json'):
            try:
                self._json = json.loads(await self.body(), object_pairs_hook=unique_pairs,
                                        parse_constant=reject_constant)
            except (ValueError, UnicodeError, RecursionError):
                raise HTTPException(400, 'Invalid JSON, duplicate keys, or unsupported nesting.') from None
        return self._json


class ModelToolsRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def bounded_handler(request):
            response = await handler(ModelToolsRequest(request.scope, request.receive))
            response.headers['Cache-Control'] = 'no-store'
            return response

        return bounded_handler


router = APIRouter(prefix='/enterprise/model-tools', tags=['Model tools'], route_class=ModelToolsRoute)


def invoke_tool(work):
    try:
        return invoke(work)
    except (RuntimeError, ImportError):
        raise HTTPException(503, 'Model tool dependency unavailable. Check the backend installation.') from None


class Document(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    document: dict


class ImportDocument(Document):
    format: Literal['aegis', 'otm', 'threat-dragon']
    diagram_id: int | None = Field(default=None, ge=0)


class ExportDocument(Document):
    format: Literal['aegis', 'otm', 'threat-dragon']


class Drift(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    baseline: dict
    observed: dict


@router.post('/validate')
def validate(payload: Document, user=Depends(editor)):
    return invoke_tool(lambda: validate_model(payload.document))


@router.post('/import')
def import_document(payload: ImportDocument, user=Depends(editor)):
    return invoke_tool(lambda: import_model(payload.document, payload.format, diagram_id=payload.diagram_id))


@router.post('/export')
def export_document(payload: ExportDocument, user=Depends(editor)):
    return invoke_tool(lambda: export_model(payload.document, payload.format))


@router.post('/cloud-snapshot/model')
def cloud_model(payload: Document, user=Depends(editor)):
    return invoke_tool(lambda: snapshot_to_model(payload.document))


@router.post('/cloud-snapshot/compare')
def cloud_drift(payload: Drift, user=Depends(editor)):
    return invoke_tool(lambda: compare_drift(payload.baseline, payload.observed))

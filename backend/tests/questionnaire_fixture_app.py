"""Isolated questionnaire browser checks using a disposable workspace database."""
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import Depends, FastAPI, HTTPException, Request

from app.services.assessment_api import router as assessment_router
from app.services.assessment_store import AssessmentStore
from app.services.enterprise_api import router, editor
from app.services.model_review import ModelReviewRequest
from app.services.product_store import ProductStore


@asynccontextmanager
async def lifespan(app):
    os.environ['AEGIS_WORKSPACE_TOKENS'] = json.dumps({'questionnaire-qa': {'name': 'QA Architect', 'role': 'admin'}})
    with TemporaryDirectory(prefix='aegis-questionnaire-qa-') as directory:
        app.state.product_store = ProductStore(Path(directory) / 'qa.sqlite3')
        app.state.assessment_store = AssessmentStore(app.state.product_store)
        yield


app = FastAPI(lifespan=lifespan)
app.include_router(router)
app.include_router(assessment_router)


@app.post('/model-review/prepare')
def prepare(payload: ModelReviewRequest, request: Request, identity=Depends(editor)):
    try:
        return request.app.state.assessment_store.prepare(payload, identity)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get('/health')
def health():
    return {'status': 'qa-only'}

"""FastAPI application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import Engine

from audit_log.api import events, verify
from audit_log.storage.database import create_schema, make_engine


async def _validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
    # Same shape as FastAPI's default 422, minus the rejected "input": echoing it would
    # return oversized or sensitive payloads to the caller, and NaN inputs cannot be
    # encoded as JSON at all.
    errors = [
        {key: value for key, value in error.items() if key != "input"} for error in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": jsonable_encoder(errors)},
    )


def create_app(engine: Engine | None = None) -> FastAPI:
    """Build the FastAPI application.

    ``engine`` defaults to one for ``DATABASE_URL``. The schema is created on startup.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        create_schema(app.state.engine)
        yield

    app = FastAPI(title="Audit Log Service", version="0.1.0", lifespan=lifespan)
    app.state.engine = engine if engine is not None else make_engine()
    app.add_exception_handler(RequestValidationError, _validation_error)  # type: ignore[arg-type]
    app.include_router(events.router)
    app.include_router(verify.router)
    return app


app = create_app()

import sqlite3
from contextlib import asynccontextmanager
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from Backend.config import settings
from Backend.database import initialize_database
from Backend.routes import alerts, dashboard, events, ingestion, system


logger = logging.getLogger(__name__)


def create_app(database_path: Path | str | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        initialize_database(application.state.database_path)
        yield

    application = FastAPI(
        title=settings.app_name,
        description=settings.app_description,
        version=settings.app_version,
        lifespan=lifespan,
    )
    application.state.database_path = (
        Path(database_path) if database_path is not None else settings.database_path
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @application.middleware("http")
    async def limit_request_body(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                request_size = int(content_length)
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header"},
                )
            if request_size < 0:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header"},
                )
            if request_size > settings.max_request_body_bytes:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body is too large"},
                )
        return await call_next(request)

    @application.exception_handler(sqlite3.Error)
    async def handle_database_error(
        request: Request,
        error: sqlite3.Error,
    ) -> JSONResponse:
        logger.error(
            "Database operation failed for %s %s: %s",
            request.method,
            request.url.path,
            error,
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "A database error occurred"},
        )

    application.include_router(system.router)
    application.include_router(events.router)
    application.include_router(ingestion.router)
    application.include_router(alerts.router)
    application.include_router(dashboard.router)

    return application


app = create_app()

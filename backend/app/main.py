import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy import text

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.security import new_request_id
from app.db.session import engine
from app.db.session import SessionLocal
from app.api.v1.router import router as api_router
from app.db.seed import seed_demo
from app.jobs.scheduler import start_scheduler, stop_scheduler

configure_logging()
logger = logging.getLogger(__name__)
settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:8080",
        "https://localhost:8443",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)
app.include_router(api_router)


@app.exception_handler(StarletteHTTPException)
async def http_error(_request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        headers=exc.headers,
        content={
            "error": {
                "code": "request_error",
                "message": str(exc.detail),
                "details": None,
            }
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, exc: RequestValidationError):
    safe_errors = [
        {
            "loc": item.get("loc", []),
            "msg": item.get("msg", "Invalid input"),
            "type": item.get("type", "value_error"),
        }
        for item in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "Request validation failed",
                "details": safe_errors,
            }
        },
    )


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or new_request_id()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("Unhandled request error", extra={"request_id": request_id})
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "Internal server error",
                    "details": None,
                }
            },
        )
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    )
    return response


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return {"status": "ok", "database": "ok"}


@app.on_event("startup")
def seed_empty_database() -> None:
    with SessionLocal() as db:
        seed_demo(db)
    start_scheduler()


@app.on_event("shutdown")
def shutdown_jobs() -> None:
    stop_scheduler()

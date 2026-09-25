"""FastAPI application factory."""

from fastapi import FastAPI


def create_app() -> FastAPI:
    """Build the FastAPI application. Routers are registered here as features land."""
    return FastAPI(title="Audit Log Service", version="0.1.0")


app = create_app()

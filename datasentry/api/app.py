from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time
import uvicorn

from .routes import router
from ..core.config import settings
from ..logging.audit_logger import AuditLogger


def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    
    app = FastAPI(
        title="DataSentry PII Guardrail API",
        description="API for detecting, masking, and preventing PII leakage to AI services",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add request timing middleware
    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response
    
    # Add request logging middleware
    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        audit_logger = AuditLogger()
        
        # Log incoming request
        await audit_logger.log_request_event(
            method=request.method,
            path=str(request.url.path),
            client_ip=request.client.host if request.client else "unknown"
        )
        
        response = await call_next(request)
        
        # Log response
        await audit_logger.log_response_event(
            status_code=response.status_code,
            processing_time_ms=(
                float(response.headers.get("X-Process-Time", 0)) * 1000
            )
        )
        
        return response
    
    # Include API routes
    app.include_router(router)
    
    # Add global exception handler
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """General exception handler"""
        from ..logging.audit_logger import AuditLogger
        from .routes import ErrorResponse
        
        audit_logger = AuditLogger()
        await audit_logger.log_error_event(
            error_type="unhandled_exception",
            error_message=str(exc),
            request_path=str(request.url)
        )
        
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="internal_server_error",
                message="An unexpected error occurred",
                details={"exception": str(exc)}
            ).dict()
        )
    
    @app.get("/")
    async def root():
        return {
            "service": "DataSentry PII Guardrail API",
            "version": "0.1.0",
            "status": "operational",
            "docs": "/docs"
        }
    
    return app


app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "datasentry.api.app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True
    )
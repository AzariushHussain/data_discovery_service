import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from app.api.routes import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

app = FastAPI(title="Data Discovery Service")

app.include_router(router)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    # Validation inputs, context, and custom messages can contain credentials.
    messages = {"missing": "Field required", "json_invalid": "Invalid JSON"}
    return JSONResponse(
        status_code=422,
        content={"detail": [
            {
                "type": error["type"],
                "loc": error["loc"],
                "msg": messages.get(error["type"], "Invalid value"),
            }
            for error in exc.errors()
        ]},
    )


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}

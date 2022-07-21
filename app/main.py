import uvicorn
from fastapi import FastAPI

import auth
import home
from core.config import settings
from core.utils import get_logger

logger = get_logger()


app_params = {}

if settings.disable_swagger_ui:
    app_params["docs_url"] = None

if settings.disable_openapi_json:
    app_params["openapi_url"] = None

logger.debug(app_params)

app = FastAPI(**app_params)


@app.on_event("startup")
async def startup():
    logger.info("on startup")


@app.on_event("shutdown")
async def shutdown():
    logger.info("on shutdown")


app.include_router(auth.routers.router)
app.include_router(home.routers.router)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        reload=settings.uvicorn_reload,
        debug=settings.debug,
        host=settings.host,
        port=settings.port,
    )

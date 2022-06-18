import uvicorn
from fastapi import FastAPI

import auth
import home
from core.config import settings

app = FastAPI()


@app.on_event("startup")
async def startup():
    print("on startup")


@app.on_event("shutdown")
async def shutdown():
    print("on shutdown")


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

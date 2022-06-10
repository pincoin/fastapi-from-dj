from fastapi import APIRouter

from .config import get_settings
from .database import metadata

settings = get_settings()


router = APIRouter(
    prefix="",
    tags=[
        "core",
    ],
)


@router.get("/")
async def home():
    return {"message": f"Hi! {settings.app_name}"}

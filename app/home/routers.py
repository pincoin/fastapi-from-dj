from core.config import get_settings
from fastapi import APIRouter

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

from core.config import settings
from fastapi import APIRouter

router = APIRouter(
    prefix="",
    tags=[
        "core",
    ],
)


@router.get("/")
async def home():
    return {"message": f"Hi! {settings.app_name}"}

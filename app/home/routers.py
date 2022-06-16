from fastapi import APIRouter

from conf.config import get_settings

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

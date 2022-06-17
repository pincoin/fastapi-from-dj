import fastapi


async def list_params(
    q: str | None = None,
    skip: int = fastapi.Query(default=0, ge=0),
    take: int = fastapi.Query(default=10, le=100),
):
    return {"q": q, "skip": skip, "take": take}

import logging

import fastapi

from core.config import settings


async def list_params(
    q: str | None = None,
    skip: int = fastapi.Query(default=0, ge=0),
    take: int = fastapi.Query(default=100, le=100),
) -> dict:
    return {"q": q, "skip": skip, "take": take}


def get_logger():
    logger = logging.getLogger()
    handler = logging.FileHandler(settings.log_file)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s: [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ),
    )
    logger.setLevel(logging.WARNING)
    logger.addHandler(handler)

    return logger

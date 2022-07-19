import logging

import fastapi

from core.config import settings


async def list_params(
    q: str | None = None,
    skip: int = fastapi.Query(default=0, ge=0),
    take: int = fastapi.Query(default=100, le=100),
) -> dict:
    return {"q": q, "skip": skip, "take": take}


def get_logger(name, level=logging.DEBUG):
    handler = logging.FileHandler(settings.log_file)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s: [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ),
    )

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger

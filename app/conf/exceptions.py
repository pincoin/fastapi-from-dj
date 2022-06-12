from fastapi import HTTPException


def item_not_found_exception(item):
    return HTTPException(status_code=404, detail=f"{item} not found")


def bad_request_exception():
    HTTPException(status_code=400, detail="Bad request")

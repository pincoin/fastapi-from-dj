from fastapi import HTTPException


def bad_request_exception():
    return HTTPException(status_code=400, detail="Bad request")


def item_not_found_exception(item):
    return HTTPException(status_code=404, detail=f"{item} not found")


def conflict_exception():
    return HTTPException(status_code=409, detail="Integrity conflict")

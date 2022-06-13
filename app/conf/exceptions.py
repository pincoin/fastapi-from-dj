from fastapi import HTTPException


def bad_request_exception():
    return HTTPException(status_code=400, detail="Bad Request")


def unauthorized_exception():
    return HTTPException(status_code=401, detail="Invalid Authentication")


def forbidden_exception():
    return HTTPException(status_code=403, detail="Forbidden")


def item_not_found_exception(item):
    return HTTPException(status_code=404, detail=f"{item} Not Found")


def conflict_exception():
    return HTTPException(status_code=409, detail="Integrity error")

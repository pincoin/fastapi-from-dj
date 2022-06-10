from fastapi import HTTPException


def user_not_found_exception():
    return HTTPException(status_code=404, detail="User not found")

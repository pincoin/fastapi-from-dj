from fastapi import HTTPException


def user_not_found_exception():
    return HTTPException(status_code=404, detail="User not found")

def content_type_not_found_exception():
    return HTTPException(status_code=404, detail="Content type not found")

def permission_not_found_exception():
    return HTTPException(status_code=404, detail="Permission not found")

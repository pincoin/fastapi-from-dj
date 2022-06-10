# fastapi-from-dj
This is a fastapi boilerplate template for quick start.

This project watches the same database schemes installed by Django.

This project is based on SQLAlchemy 1.4+ in order to utilize async connections.

## Features
* SQLAlchemy Async Core + CRUD on PostgreSQL
* OAuth2 + JWT (Django-compatible)

# Getting started
## Requirements
* fastapi
* SQLAlchemy[asyncio]
* uvicorn
* asyncpg (PostgreSQL)
* alembic
* uvicorn

## app/conf/local.env

# Package structure
```
package/
  __init__.py
  routers.py
  models.py
  schemas.py
  responses.py
  exceptions.py
  utils.py
```

* `routers.py`: API routers for controllers
* `models.py`: Database tables, relations, and views
* `schemas.py`: API schemas, forms includes validators
* `responses.py`: Reusable HTTP responses
* `exceptions.py`: Reusable HTTP exceptions
* `utils.py`: Helpers

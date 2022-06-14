# fastapi-from-dj
This is a FastAPI boilerplate template for quick start.

This project watches the same database schemes installed by Django.

This project is based on Python 3.10+ and SQLAlchemy 1.4+ in order to utilize async connections.

## Features
* SQLAlchemy Async Core + CRUD on PostgreSQL
* OAuth2 + JWT (Django scheme-compatible)

# Getting started
## Requirements
Python 3.10 and above
* fastapi
* SQLAlchemy[asyncio]
* asyncpg
* psycopg2-binary (for alembic)
* pydantic[dotenv]
* pydantic[email]
* uvicorn
* alembic
* uvicorn

## Settings
`app/local.env`

```py
app_name="FastAPI from Django"
debug=True
uvicorn_reload=True
secret_key="Minimum-length-32-secret-key-string"
sqlalchemy_database_uri="postgresql+asyncpg://username:password@host:port/database"
```

You can create the `app/production.env` file for production server, and all `.env` files are hidden by `.gitignore`.

## Run
```
$ python app/main.py
```

SQLAlchemy 2.0 migration must be considered for consistent development, so you may enable all of SQLAlchemy warings as follows:

```
$ SQLALCHEMY_WARN_20=1 python -W always::DeprecationWarning app/main.py
```

# Django or FastAPI
I decided to run Django and FastAPI servers because of the following reasons:

## Django
Pros
* All-in-one framework with a rich of 3rd party libraries in django-ecosystem
* Django ORM and Admin page

Cons
* REST API is supported by DRF(Django Rest Framework)
* WSGI
* Websocket not supported

## FastAPI
Pros
* Async/ASGI - Fast
* Easy to code and fast learning curve.
* Data validation via Pydantic
* Automatic docs(Swagger-UI)
* Websocket

Cons
* Session not supported
* Samll communities with small 3rd party libraries

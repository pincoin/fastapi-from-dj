# fastapi-from-dj
This is a FastAPI boilerplate template for quick start.

This project watches the same database schemes which was installed by Django. You can authenticate users with Django-compatible authentication backend and password hasher. However, you can define your own authentication backend and password hasher.

This project is based on Python 3.10+ and SQLAlchemy 1.4+ in order to utilize async connections and the lastest Python features.

## Features
* SQLAlchemy Async Core + CRUD on PostgreSQL
* Alembic migrations
* OAuth2 + JWT (Django scheme-compatible)

# Getting started
## Requirements
Python 3.10 and above
* fastapi
* SQLAlchemy[asyncio]
* asyncpg
* psycopg2-binary (for alembic)
* alembic
* pydantic[dotenv]
* pydantic[email]
* python-multipart
* python-jose[cryptography]
* uvicorn

## Settings
`app/local.env`

```py
app_name="FastAPI from Django"
debug=True
uvicorn_reload=True
disable_swagger_ui=True
disable_openapi_json=False
jwt_secret_key="Minimum-length-32-secret-key-string-for-HS256"
jwt_expiration_delta=30
jwt_refresh_secret_key="Minimum-length-32-secret-key-string-for-HS256"
jwt_refresh_expiration_delta=20160
jwt_algorithm="HS256"
password_hasher="auth.hashers.Pbkdf2Sha256Hasher"
authentication_backend="auth.backends.AuthenticationBackend"
sqlalchemy_database_uri="postgresql+asyncpg://username:password@host:port/database"
log_file="/path/to/logs/fastapi.log"
```

You may create the `app/production.env` separate file for the production server, and you can run server by setting environment variable `ENV_STATE=production`.

All `*.env` files are hidden for security by `.gitignore`.

You can substitute `authentication_backend` and `password_hasher` with your own algorithms. Please, make sure what methods have to be implemented.

Please don't forget to add `get_superuser` method dynamically into an `authentication` instance of your backend class. Python does not allow `self` parameter is accessed in the parameter list of a method during method declarations. It is not always a good idea to add a method into an instance dynamically, but we have no choice if we want to make authentication dependencies and methods live together.

## Alembic migrations
`psycopg2-binary` is required because Alembic works synchronously.

```
$ mv alembic.ini.sample alembic.ini
```

Please, change the line as shown below:
```
sqlalchemy.url = driver://user:pass@localhost/dbname
```

Now, you can migrate by issuing this command in the parent directory of `alembic/`:
```
$  alembic upgrade head
```

## Run
You can simply run like this:
```
$ cd app/
$ python main.py
```

SQLAlchemy 2.0 migration must be considered for consistent development process, so you may enable all of SQLAlchemy future deprecation warnings as follows:

```
$ cd app/
$ SQLALCHEMY_WARN_20=1 python -W always::DeprecationWarning main.py
```

You can run FastAPI app using `uvicorn`:

```
$ cd app/
$ uvicorn main:app --reload
```

Of course, you can change the service port with `--port` option.

You can specify the `env` file by setting environment variable:

```
$ cd app/
$ ENV=local python main.py
```

## Logging
```py
from core.utils import get_logger

logger = get_logger(__name__)
logger.debug("log message")
```

# Django or FastAPI
I decided to run both Django and FastAPI servers because of the following reasons:

## Django
Pros
* Easy to set up and run
* High-level framework for rapid web development
* Django ORM and Admin page
* Built-in authentication system
* A complete stack of tools
* Cache framework comes with multiple cache mechanisms

Cons
* Monolithic platform.
* High dependence on Django ORM
* High learning curve
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
* Slower MVP development in most cases
* Higher maintenance costs for more complex systems
* Session not supported
* Smaller community compared to Django

# Topics for study
* Pydantic validation
    * Path parameters
    * Query parameters
    * Raw JSON body
    * Form data
    * Masking response
* SQLAlchemy
    * Ready for 2.0
    * Prevent nested transactions
* FastAPI dependencies are cached.
* Simple singleton is implemented by LRU cache.

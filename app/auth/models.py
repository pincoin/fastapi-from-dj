import sqlalchemy
from conf.database import metadata

users = sqlalchemy.Table(
    "auth_user",
    metadata,
    sqlalchemy.Column(
        "id",
        sqlalchemy.BigInteger,
        primary_key=True,
        index=True,
    ),
    sqlalchemy.Column(
        "password",
        sqlalchemy.String(128),
    ),
    sqlalchemy.Column(
        "last_login",
        sqlalchemy.DateTime,
    ),
    sqlalchemy.Column(
        "is_superuser",
        sqlalchemy.Boolean,
    ),
    sqlalchemy.Column(
        "username",
        sqlalchemy.String(150),
        index=True,
        unique=True,
    ),
    sqlalchemy.Column(
        "first_name",
        sqlalchemy.String(150),
    ),
    sqlalchemy.Column(
        "last_name",
        sqlalchemy.String(150),
        nullable=True,
    ),
    sqlalchemy.Column(
        "email",
        sqlalchemy.String(254),
        unique=True,
        index=True,
    ),
    sqlalchemy.Column(
        "is_staff",
        sqlalchemy.Boolean,
    ),
    sqlalchemy.Column(
        "is_active",
        sqlalchemy.Boolean,
    ),
    sqlalchemy.Column(
        "date_joined",
        sqlalchemy.DateTime,
    ),
)

groups = sqlalchemy.Table(
    "auth_group",
    metadata,
    sqlalchemy.Column(
        "id",
        sqlalchemy.BigInteger,
        primary_key=True,
        index=True,
    ),
    sqlalchemy.Column(
        "name",
        sqlalchemy.String(150),
        unique=True,
    ),
)


content_types = sqlalchemy.Table(
    "django_content_type",
    metadata,
    sqlalchemy.Column(
        "id",
        sqlalchemy.BigInteger,
        primary_key=True,
        index=True,
    ),
    sqlalchemy.Column(
        "app_label",
        sqlalchemy.String(100),
    ),
    sqlalchemy.Column(
        "model",
        sqlalchemy.String(100),
    ),
    sqlalchemy.UniqueConstraint("app_label", "model"),
)


permissions = sqlalchemy.Table(
    "auth_permission",
    metadata,
    sqlalchemy.Column(
        "id",
        sqlalchemy.BigInteger,
        primary_key=True,
        index=True,
    ),
    sqlalchemy.Column(
        "name",
        sqlalchemy.String(255),
    ),
    sqlalchemy.Column(
        "content_type_id",
        sqlalchemy.BigInteger,
        sqlalchemy.ForeignKey("django_content_type.id"),
    ),
    sqlalchemy.Column(
        "codename",
        sqlalchemy.String(100),
    ),
    sqlalchemy.UniqueConstraint("content_type_id", "codename"),
)


group_permissions = sqlalchemy.Table(
    "auth_group_permissions",
    metadata,
    sqlalchemy.Column(
        "id",
        sqlalchemy.BigInteger,
        primary_key=True,
        index=True,
    ),
    sqlalchemy.Column(
        "group_id",
        sqlalchemy.BigInteger,
        sqlalchemy.ForeignKey("auth_group.id"),
    ),
    sqlalchemy.Column(
        "permission_id",
        sqlalchemy.BigInteger,
        sqlalchemy.ForeignKey("auth_permission.id"),
    ),
    sqlalchemy.UniqueConstraint("group_id", "permission_id"),
)


user_groups = sqlalchemy.Table(
    "auth_user_groups",
    metadata,
    sqlalchemy.Column(
        "id",
        sqlalchemy.BigInteger,
        primary_key=True,
        index=True,
    ),
    sqlalchemy.Column(
        "user_id",
        sqlalchemy.BigInteger,
        sqlalchemy.ForeignKey("auth_user.id"),
    ),
    sqlalchemy.Column(
        "group_id",
        sqlalchemy.BigInteger,
        sqlalchemy.ForeignKey("auth_group.id"),
    ),
    sqlalchemy.UniqueConstraint("user_id", "group_id"),
)


user_user_permissions = sqlalchemy.Table(
    "auth_user_user_permissions",
    metadata,
    sqlalchemy.Column(
        "id",
        sqlalchemy.BigInteger,
        primary_key=True,
        index=True,
    ),
    sqlalchemy.Column(
        "user_id",
        sqlalchemy.BigInteger,
        sqlalchemy.ForeignKey("auth_user.id"),
    ),
    sqlalchemy.Column(
        "permission_id",
        sqlalchemy.BigInteger,
        sqlalchemy.ForeignKey("auth_permission.id"),
    ),
    sqlalchemy.UniqueConstraint("user_id", "permission_id"),
)

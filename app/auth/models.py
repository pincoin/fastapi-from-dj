import sqlalchemy as sa
from core.database import metadata

users = sa.Table(
    "auth_user",
    metadata,
    sa.Column(
        "id",
        sa.BigInteger,
        primary_key=True,
        index=True,
    ),
    sa.Column(
        "password",
        sa.String(128),
    ),
    sa.Column(
        "last_login",
        sa.types.TIMESTAMP(timezone=True),
        nullable=True,
    ),
    sa.Column(
        "is_superuser",
        sa.Boolean,
    ),
    sa.Column(
        "username",
        sa.String(150),
        index=True,
        unique=True,
    ),
    sa.Column(
        "first_name",
        sa.String(150),
    ),
    sa.Column(
        "last_name",
        sa.String(150),
        nullable=True,
    ),
    sa.Column(
        "email",
        sa.String(254),
        unique=True,
        index=True,
    ),
    sa.Column(
        "is_staff",
        sa.Boolean,
    ),
    sa.Column(
        "is_active",
        sa.Boolean,
    ),
    sa.Column(
        "date_joined",
        sa.types.TIMESTAMP(timezone=True),
    ),
)


groups = sa.Table(
    "auth_group",
    metadata,
    sa.Column(
        "id",
        sa.BigInteger,
        primary_key=True,
        index=True,
    ),
    sa.Column(
        "name",
        sa.String(150),
        unique=True,
        index=True,
    ),
)


content_types = sa.Table(
    "django_content_type",
    metadata,
    sa.Column(
        "id",
        sa.BigInteger,
        primary_key=True,
        index=True,
    ),
    sa.Column(
        "app_label",
        sa.String(100),
    ),
    sa.Column(
        "model",
        sa.String(100),
    ),
    sa.UniqueConstraint("app_label", "model"),
)


permissions = sa.Table(
    "auth_permission",
    metadata,
    sa.Column(
        "id",
        sa.BigInteger,
        primary_key=True,
        index=True,
    ),
    sa.Column(
        "name",
        sa.String(255),
    ),
    sa.Column(
        "content_type_id",
        sa.BigInteger,
        sa.ForeignKey(
            "django_content_type.id",
            onupdate="CASCADE",
            ondelete="CASCADE",
            deferrable=True,
            initially="IMMEDIATE",
        ),
        index=True,
    ),
    sa.Column(
        "codename",
        sa.String(100),
    ),
    sa.UniqueConstraint("content_type_id", "codename"),
)


group_permissions = sa.Table(
    "auth_group_permissions",
    metadata,
    sa.Column(
        "id",
        sa.BigInteger,
        primary_key=True,
        index=True,
    ),
    sa.Column(
        "group_id",
        sa.BigInteger,
        sa.ForeignKey(
            "auth_group.id",
            onupdate="CASCADE",
            ondelete="CASCADE",
            deferrable=True,
            initially="IMMEDIATE",
        ),
        index=True,
    ),
    sa.Column(
        "permission_id",
        sa.BigInteger,
        sa.ForeignKey(
            "auth_permission.id",
            onupdate="CASCADE",
            ondelete="CASCADE",
            deferrable=True,
            initially="IMMEDIATE",
        ),
        index=True,
    ),
    sa.UniqueConstraint("group_id", "permission_id"),
)


user_groups = sa.Table(
    "auth_user_groups",
    metadata,
    sa.Column(
        "id",
        sa.BigInteger,
        primary_key=True,
        index=True,
    ),
    sa.Column(
        "user_id",
        sa.BigInteger,
        sa.ForeignKey(
            "auth_user.id",
            onupdate="CASCADE",
            ondelete="CASCADE",
            deferrable=True,
            initially="IMMEDIATE",
        ),
        index=True,
    ),
    sa.Column(
        "group_id",
        sa.BigInteger,
        sa.ForeignKey(
            "auth_group.id",
            onupdate="CASCADE",
            ondelete="CASCADE",
            deferrable=True,
            initially="IMMEDIATE",
        ),
        index=True,
    ),
    sa.UniqueConstraint("user_id", "group_id"),
)


user_permissions = sa.Table(
    # Django table name does not match the model name.
    "auth_user_user_permissions",
    metadata,
    sa.Column(
        "id",
        sa.BigInteger,
        primary_key=True,
        index=True,
    ),
    sa.Column(
        "user_id",
        sa.BigInteger,
        sa.ForeignKey(
            "auth_user.id",
            onupdate="CASCADE",
            ondelete="CASCADE",
            deferrable=True,
            initially="IMMEDIATE",
        ),
        index=True,
    ),
    sa.Column(
        "permission_id",
        sa.BigInteger,
        sa.ForeignKey(
            "auth_permission.id",
            onupdate="CASCADE",
            ondelete="CASCADE",
            deferrable=True,
            initially="IMMEDIATE",
        ),
        index=True,
    ),
    sa.UniqueConstraint("user_id", "permission_id"),
)


admin_logs = sa.Table(
    "django_admin_log",
    metadata,
    sa.Column(
        "id",
        sa.BigInteger,
        primary_key=True,
        index=True,
    ),
    sa.Column(
        "action_time",
        sa.types.TIMESTAMP(timezone=True),
    ),
    sa.Column(
        "object_id",
        sa.String,
        nullable=True,
    ),
    sa.Column(
        "object_repr",
        sa.String(200),
    ),
    sa.Column(
        "action_flag",
        sa.SmallInteger,
        sa.CheckConstraint("action_flag>0"),
    ),
    sa.Column(
        "change_message",
        sa.String,
    ),
    sa.Column(
        "content_type_id",
        sa.BigInteger,
        sa.ForeignKey(
            "django_content_type.id",
            onupdate="CASCADE",
            ondelete="CASCADE",
            deferrable=True,
            initially="IMMEDIATE",
        ),
        index=True,
    ),
    sa.Column(
        "user_id",
        sa.BigInteger,
        sa.ForeignKey(
            "auth_user.id",
            onupdate="CASCADE",
            ondelete="CASCADE",
            deferrable=True,
            initially="IMMEDIATE",
        ),
        index=True,
    ),
)


sessions = sa.Table(
    "django_session",
    metadata,
    sa.Column(
        "session_key",
        sa.String(40),
        primary_key=True,
        index=True,
    ),
    sa.Column(
        "session_data",
        sa.String,
    ),
    sa.Column(
        "expire_date",
        sa.types.TIMESTAMP(timezone=True),
        index=True,
    ),
)


django_migrations = sa.Table(
    "django_migrations",
    metadata,
    sa.Column(
        "id",
        sa.BigInteger,
        primary_key=True,
        index=True,
    ),
    sa.Column(
        "app",
        sa.String(255),
    ),
    sa.Column(
        "name",
        sa.String(255),
    ),
    sa.Column(
        "applied",
        sa.types.TIMESTAMP(timezone=True),
    ),
)


tokens = sa.Table(
    "auth_token",
    metadata,
    sa.Column(
        "id",
        sa.BigInteger,
        primary_key=True,
        index=True,
    ),
    sa.Column(
        "user_id",
        sa.BigInteger,
        sa.ForeignKey(
            "auth_user.id",
            onupdate="CASCADE",
            ondelete="CASCADE",
            deferrable=True,
            initially="IMMEDIATE",
        ),
        index=True,
    ),
    sa.Column(
        "token",
        sa.String(255),
        index=True,
    ),
    sa.Column(
        "expiration_time_delta",
        sa.Interval,
    ),
    sa.Column(
        "created",
        sa.types.TIMESTAMP(timezone=True),
    ),
)

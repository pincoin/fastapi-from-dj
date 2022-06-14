"""init

Revision ID: ef6fbe3476c9
Revises: 
Create Date: 2022-06-14 23:49:40.028003

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "ef6fbe3476c9"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_user",
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

    op.create_table(
        "auth_group",
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

    op.create_table(
        "django_content_type",
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

    op.create_table(
        "auth_permission",
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
                deferrable=False,
            ),
        ),
        sa.Column(
            "codename",
            sa.String(100),
        ),
        sa.UniqueConstraint("content_type_id", "codename"),
    )

    op.create_table(
        "auth_group_permissions",
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
                deferrable=False,
            ),
        ),
        sa.Column(
            "permission_id",
            sa.BigInteger,
            sa.ForeignKey(
                "auth_permission.id",
                onupdate="CASCADE",
                ondelete="CASCADE",
                deferrable=False,
            ),
        ),
        sa.UniqueConstraint("group_id", "permission_id"),
    )

    op.create_table(
        "auth_user_groups",
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
                deferrable=False,
            ),
        ),
        sa.Column(
            "group_id",
            sa.BigInteger,
            sa.ForeignKey(
                "auth_group.id",
                onupdate="CASCADE",
                ondelete="CASCADE",
                deferrable=False,
            ),
        ),
        sa.UniqueConstraint("user_id", "group_id"),
    )

    op.create_table(
        "auth_user_user_permissions",
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
                deferrable=False,
            ),
        ),
        sa.Column(
            "permission_id",
            sa.BigInteger,
            sa.ForeignKey(
                "auth_permission.id",
                onupdate="CASCADE",
                ondelete="CASCADE",
                deferrable=False,
            ),
        ),
        sa.UniqueConstraint("user_id", "permission_id"),
    )

    op.create_table(
        "django_admin_log",
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
                deferrable=False,
            ),
        ),
        sa.Column(
            "user_id",
            sa.BigInteger,
            sa.ForeignKey(
                "auth_user.id",
                onupdate="CASCADE",
                ondelete="CASCADE",
                deferrable=False,
            ),
        ),
    )

    op.create_table(
        "django_session",
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

    op.create_table(
        "django_migrations",
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


def downgrade() -> None:
    op.drop_table("auth_group_permissions")
    op.drop_table("auth_user_groups")
    op.drop_table("auth_user_user_permissions")
    op.drop_table("django_admin_log")
    op.drop_table("django_session")
    op.drop_table("django_migrations")
    op.drop_table("auth_permission")
    op.drop_table("auth_user")
    op.drop_table("auth_group")
    op.drop_table("django_content_type")
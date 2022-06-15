"""auth init

Revision ID: a522b478adde
Revises: 
Create Date: 2022-06-15 15:12:49.946793

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a522b478adde"
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

    django_content_type = op.create_table(
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

    auth_permission = op.create_table(
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

    op.bulk_insert(
        django_content_type,
        [
            {
                "app_label": "admin",
                "model": "logentry",
            },
            {
                "app_label": "auth",
                "model": "permission",
            },
            {
                "app_label": "auth",
                "model": "group",
            },
            {
                "app_label": "auth",
                "model": "user",
            },
            {
                "app_label": "contenttypes",
                "model": "contenttype",
            },
            {
                "app_label": "sessions",
                "model": "session",
            },
        ],
    )

    op.bulk_insert(
        auth_permission,
        [
            {
                "name": "Can add log entry",
                "content_type_id": 1,
                "codename": "add_logentry",
            },
            {
                "name": "Can change log entry",
                "content_type_id": 1,
                "codename": "change_logentry",
            },
            {
                "name": "Can delete log entry",
                "content_type_id": 1,
                "codename": "delete_logentry",
            },
            {
                "name": "Can view log entry",
                "content_type_id": 1,
                "codename": "view_logentry",
            },
            {
                "name": "Can add permission",
                "content_type_id": 2,
                "codename": "add_permission",
            },
            {
                "name": "Can change permission",
                "content_type_id": 2,
                "codename": "change_permission",
            },
            {
                "name": "Can delete permission",
                "content_type_id": 2,
                "codename": "delete_permission",
            },
            {
                "name": "Can view permission",
                "content_type_id": 2,
                "codename": "view_permission",
            },
            {
                "name": "Can add group",
                "content_type_id": 3,
                "codename": "add_group",
            },
            {
                "name": "Can change group",
                "content_type_id": 3,
                "codename": "change_group",
            },
            {
                "name": "Can delete group",
                "content_type_id": 3,
                "codename": "delete_group",
            },
            {
                "name": "Can view group",
                "content_type_id": 3,
                "codename": "view_group",
            },
            {
                "name": "Can add user",
                "content_type_id": 4,
                "codename": "add_user",
            },
            {
                "name": "Can change user",
                "content_type_id": 4,
                "codename": "change_user",
            },
            {
                "name": "Can delete user",
                "content_type_id": 4,
                "codename": "delete_user",
            },
            {
                "name": "Can view user",
                "content_type_id": 4,
                "codename": "view_user",
            },
            {
                "name": "Can add content type",
                "content_type_id": 5,
                "codename": "add_contenttype",
            },
            {
                "name": "Can change content type",
                "content_type_id": 5,
                "codename": "change_contenttype",
            },
            {
                "name": "Can delete content type",
                "content_type_id": 5,
                "codename": "delete_contenttype",
            },
            {
                "name": "Can view content type",
                "content_type_id": 5,
                "codename": "view_contenttype",
            },
            {
                "name": "Can add session",
                "content_type_id": 6,
                "codename": "add_session",
            },
            {
                "name": "Can change session",
                "content_type_id": 6,
                "codename": "change_session",
            },
            {
                "name": "Can delete session",
                "content_type_id": 6,
                "codename": "delete_session",
            },
            {
                "name": "Can view session",
                "content_type_id": 6,
                "codename": "view_session",
            },
        ],
    )


def downgrade() -> None:
    op.drop_table("django_migrations")
    op.drop_table("django_session")
    op.drop_table("django_admin_log")
    op.drop_table("auth_user_user_permissions")
    op.drop_table("auth_user_groups")
    op.drop_table("auth_group_permissions")
    op.drop_table("auth_permission")
    op.drop_table("django_content_type")
    op.drop_table("auth_group")
    op.drop_table("auth_user")

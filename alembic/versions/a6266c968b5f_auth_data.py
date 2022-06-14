"""auth_data

Revision ID: a6266c968b5f
Revises: ef6fbe3476c9
Create Date: 2022-06-15 01:34:20.857151

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "a6266c968b5f"
down_revision = "ef6fbe3476c9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    meta = sa.MetaData(bind=op.get_bind())
    meta.reflect(
        only=(
            "django_content_type",
            "auth_permission",
        )
    )

    django_content_type = sa.Table("django_content_type", meta)
    auth_permission = sa.Table("auth_permission", meta)

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
    pass

"""create token table

Revision ID: 4f660ac365e8
Revises: a522b478adde
Create Date: 2022-07-18 23:39:02.110220

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "4f660ac365e8"
down_revision = "a522b478adde"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_token",
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
            index=True,
        ),
    )


def downgrade() -> None:
    op.drop_table("auth_token")

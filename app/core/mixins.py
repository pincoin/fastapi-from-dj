import sqlalchemy as sa


def timestamped_mixin_factory():
    return (
        sa.Column(
            "created",
            sa.types.TIMESTAMP(timezone=True),
        ),
        sa.Column(
            "modified",
            sa.types.TIMESTAMP(timezone=True),
        ),
    )


def timeframed_mixin_factory():
    return (
        sa.Column(
            "start",
            sa.types.TIMESTAMP(timezone=True),
        ),
        sa.Column(
            "end",
            sa.types.TIMESTAMP(timezone=True),
        ),
    )


def soft_deletable_mixin_factory():
    return (
        sa.Column(
            "is_removed",
            sa.Boolean,
            default=False,
        ),
    )

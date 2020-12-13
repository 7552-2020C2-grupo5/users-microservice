"""fix now string

Revision ID: 8acb735fe1c7
Revises: 2b1be7793f6b
Create Date: 2020-12-13 20:06:45.002755

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8acb735fe1c7'
down_revision = '2b1be7793f6b'
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """UPDATE "user" SET register_date = date('now') WHERE register_date = 'now()'"""
    )


def downgrade():
    pass

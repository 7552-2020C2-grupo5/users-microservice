"""wallet attributes

Revision ID: e9de42749257
Revises: 3be622233776
Create Date: 2021-02-10 05:13:23.840153

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e9de42749257'
down_revision = '3be622233776'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('wallet_address', sa.String(length=256), nullable=True))
    op.add_column('user', sa.Column('wallet_mnemonic', sa.String(length=256), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'wallet_mnemonic')
    op.drop_column('user', 'wallet_address')
    # ### end Alembic commands ###

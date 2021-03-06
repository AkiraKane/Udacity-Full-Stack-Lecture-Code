"""empty message

Revision ID: 0795c1a0a4de
Revises: dbcb71304ca4
Create Date: 2020-04-02 18:27:29.718565

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0795c1a0a4de'
down_revision = 'dbcb71304ca4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('todos', 'list_id',
               existing_type=sa.INTEGER(),
               nullable=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('todos', 'list_id',
               existing_type=sa.INTEGER(),
               nullable=True)
    # ### end Alembic commands ###

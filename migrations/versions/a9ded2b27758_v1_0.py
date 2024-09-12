"""v1.0

Revision ID: a9ded2b27758
Revises: 2e01f58d11e1
Create Date: 2024-09-12 11:31:49.604952

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'a9ded2b27758'
down_revision = '2e01f58d11e1'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('comment', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_comment_user', 'user', ['user_id'], ['id'])

    op.execute('UPDATE comment SET user_id = 1 WHERE user_id IS NULL;')

    with op.batch_alter_table('comment', schema=None) as batch_op:
        batch_op.alter_column('user_id', nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('comment', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('user_id')

    # ### end Alembic commands ###

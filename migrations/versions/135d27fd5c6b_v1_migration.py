"""v1 migration

Revision ID: 135d27fd5c6b
Revises: f601b9c96051
Create Date: 2024-08-11 16:28:12.839063

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '135d27fd5c6b'
down_revision = 'f601b9c96051'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=150), nullable=False),
    sa.Column('password_hash', sa.String(length=150), nullable=True),
    sa.Column('first_name', sa.String(length=150), nullable=True),
    sa.Column('last_name', sa.String(length=150), nullable=True),
    sa.Column('telegram_id', sa.String(length=150), nullable=True),
    sa.Column('vk_id', sa.String(length=150), nullable=True),
    sa.Column('profile_picture', sa.String(length=300), nullable=True),
    sa.Column('email', sa.String(length=150), nullable=True),
    sa.Column('provider', sa.String(length=50), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('telegram_id'),
    sa.UniqueConstraint('username'),
    sa.UniqueConstraint('vk_id'),
    mysql_charset='utf8',
    mysql_engine='InnoDB'
    )
    op.create_table('comment',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('post_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['post_id'], ['blog_post.id'], ),
    sa.PrimaryKeyConstraint('id'),
    mysql_charset='utf8',
    mysql_engine='InnoDB'
    )
    with op.batch_alter_table('project', schema=None) as batch_op:
        batch_op.add_column(sa.Column('url', sa.String(length=200), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('project', schema=None) as batch_op:
        batch_op.drop_column('url')

    op.drop_table('comment')
    op.drop_table('user')
    # ### end Alembic commands ###

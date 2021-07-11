"""init migrate

Revision ID: a331a8f1b9ac
Revises: 
Create Date: 2021-06-06 11:28:56.528796

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a331a8f1b9ac'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('guest_user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('fname', sa.String(length=70), nullable=False),
    sa.Column('lname', sa.String(length=70), nullable=False),
    sa.Column('gender', sa.String(), nullable=False),
    sa.Column('email', sa.String(), nullable=False),
    sa.Column('phone_number', sa.String(), nullable=False),
    sa.Column('username', sa.String(length=30), nullable=False),
    sa.Column('password', sa.String(length=60), nullable=False),
    sa.Column('image_file', sa.String(length=20), nullable=False),
    sa.Column('is_admin', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('phone_number'),
    sa.UniqueConstraint('username')
    )
    op.create_table('post',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=100), nullable=False),
    sa.Column('date_posted', sa.DateTime(), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('hashtags', sa.String(), nullable=True),
    sa.Column('image_file', sa.String(length=100), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('post')
    op.drop_table('user')
    op.drop_table('guest_user')
    # ### end Alembic commands ###

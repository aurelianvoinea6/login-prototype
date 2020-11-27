"""empty message

Revision ID: 5407d2b79515
Revises: dd1c78edb018
Create Date: 2020-11-27 13:47:33.974166

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '5407d2b79515'
down_revision = 'dd1c78edb018'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('authors', 'book',
               existing_type=mysql.VARCHAR(length=20),
               nullable=True)
    op.alter_column('authors', 'country',
               existing_type=mysql.VARCHAR(length=50),
               nullable=True)
    op.alter_column('authors', 'name',
               existing_type=mysql.VARCHAR(length=50),
               nullable=True)
    op.alter_column('user', 'email',
               existing_type=mysql.VARCHAR(length=120),
               nullable=True)
    op.alter_column('user', 'is_active',
               existing_type=mysql.TINYINT(display_width=1),
               nullable=True)
    op.alter_column('user', 'password',
               existing_type=mysql.VARCHAR(length=80),
               nullable=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('user', 'password',
               existing_type=mysql.VARCHAR(length=80),
               nullable=False)
    op.alter_column('user', 'is_active',
               existing_type=mysql.TINYINT(display_width=1),
               nullable=False)
    op.alter_column('user', 'email',
               existing_type=mysql.VARCHAR(length=120),
               nullable=False)
    op.alter_column('authors', 'name',
               existing_type=mysql.VARCHAR(length=50),
               nullable=False)
    op.alter_column('authors', 'country',
               existing_type=mysql.VARCHAR(length=50),
               nullable=False)
    op.alter_column('authors', 'book',
               existing_type=mysql.VARCHAR(length=20),
               nullable=False)
    # ### end Alembic commands ###

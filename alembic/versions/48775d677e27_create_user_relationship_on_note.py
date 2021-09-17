"""create user relationship on note

Revision ID: 48775d677e27
Revises: 
Create Date: 2021-09-11 13:56:03.269671

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
from sqlalchemy import Column, INTEGER, ForeignKey

revision = '48775d677e27'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("note", Column("user_id", INTEGER, ForeignKey("user.id"), nullable=True))
    op.execute("UPDATE note SET user_id = notebook.user_id from notebook WHERE note.user_id IS NULL")
    op.alter_column("note", "user_id", nullable=False)


def downgrade():
    op.drop_column("note", "user_id")

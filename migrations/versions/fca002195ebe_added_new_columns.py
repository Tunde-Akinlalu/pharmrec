"""added new columns

Revision ID: fca002195ebe
Revises: 
Create Date: 2022-06-02 16:32:01.325540

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fca002195ebe'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('pharmacy', sa.Column('scheme', sa.String(length=200), nullable=False))
    op.add_column('pharmacy', sa.Column('medication1', sa.String(length=200), nullable=False))
    op.add_column('pharmacy', sa.Column('medication2', sa.String(length=200), nullable=False))
    op.add_column('pharmacy', sa.Column('medication3', sa.String(length=200), nullable=False))
    op.add_column('pharmacy', sa.Column('medication4', sa.String(length=200), nullable=False))
    op.add_column('pharmacy', sa.Column('payment', sa.Integer(), nullable=False))
    op.drop_column('pharmacy', 'name')
    op.drop_column('pharmacy', 'medication')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('pharmacy', sa.Column('medication', sa.VARCHAR(length=200), nullable=False))
    op.add_column('pharmacy', sa.Column('name', sa.VARCHAR(length=200), nullable=False))
    op.drop_column('pharmacy', 'payment')
    op.drop_column('pharmacy', 'medication4')
    op.drop_column('pharmacy', 'medication3')
    op.drop_column('pharmacy', 'medication2')
    op.drop_column('pharmacy', 'medication1')
    op.drop_column('pharmacy', 'scheme')
    # ### end Alembic commands ###

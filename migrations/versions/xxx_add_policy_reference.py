def upgrade():
    op.add_column('policy', sa.Column('reference_number', sa.String(50), nullable=True))
    # Make it nullable first to handle existing records
    op.execute('UPDATE policy SET reference_number = id::text WHERE reference_number IS NULL')
    # Then make it not nullable
    op.alter_column('policy', 'reference_number', nullable=False)

def downgrade():
    op.drop_column('policy', 'reference_number') 
"""
add doc_emb column and HNSW indexes

Revision ID: add_doc_emb_20250928
Revises: None
Create Date: 2025-09-28
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_doc_emb_20250928'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Ensure vector extension is available
    op.execute("CREATE EXTENSION IF NOT EXISTS vector;")

    # Add doc_emb column (vector(1536)) if not exists
    # Alembic lacks native IF NOT EXISTS for columns; guard via DO block
    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
              IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name='messages' AND column_name='doc_emb'
              ) THEN
                ALTER TABLE messages ADD COLUMN doc_emb vector(1536);
              END IF;
            END$$;
            """
        )
    )

    # Create HNSW indexes for doc_emb
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_messages_doc_emb_hnsw
          ON messages USING hnsw (doc_emb vector_cosine_ops)
          WITH (m = 16, ef_construction = 64);
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_messages_doc_emb_hnsw_phish
          ON messages USING hnsw (doc_emb vector_cosine_ops)
          WITH (m = 16, ef_construction = 64)
          WHERE label = 1;
        """
    )


def downgrade() -> None:
    # Drop indexes first
    op.execute("DROP INDEX IF EXISTS idx_messages_doc_emb_hnsw_phish;")
    op.execute("DROP INDEX IF EXISTS idx_messages_doc_emb_hnsw;")
    # Drop column
    op.execute("ALTER TABLE messages DROP COLUMN IF EXISTS doc_emb;")



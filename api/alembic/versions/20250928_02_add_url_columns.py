"""
add url_extracted and url_emb with HNSW index

Revision ID: add_url_cols_20250928
Revises: add_doc_emb_20250928
Create Date: 2025-09-28
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_url_cols_20250928'
down_revision = 'add_doc_emb_20250928'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Ensure vector extension is available
    op.execute("CREATE EXTENSION IF NOT EXISTS vector;")

    # Add url_extracted column if it doesn't exist
    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
              IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name='messages' AND column_name='url_extracted'
              ) THEN
                ALTER TABLE messages ADD COLUMN url_extracted TEXT;
              END IF;
            END$$;
            """
        )
    )

    # Add url_emb column if it doesn't exist
    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
              IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name='messages' AND column_name='url_emb'
              ) THEN
                ALTER TABLE messages ADD COLUMN url_emb vector(1536);
              END IF;
            END$$;
            """
        )
    )

    # Create HNSW index for url_emb
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_messages_url_emb_hnsw
          ON messages USING hnsw (url_emb vector_cosine_ops)
          WITH (m = 16, ef_construction = 64);
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_messages_url_emb_hnsw;")
    op.execute("ALTER TABLE messages DROP COLUMN IF EXISTS url_emb;")
    op.execute("ALTER TABLE messages DROP COLUMN IF EXISTS url_extracted;")



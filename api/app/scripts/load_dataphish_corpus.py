"""
Load DataPhish training set into vector database with embeddings.

Usage:
    DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/app \
    PYTHONPATH=api /home/safayat/anaconda3/envs/cybercane/bin/python \
    api/app/scripts/load_dataphish_corpus.py --split train --limit 8000
"""

import argparse
import json
import logging
import os
import time
from pathlib import Path
from typing import List

import sqlalchemy as sa
from sqlalchemy.orm import Session

from app.db import engine
from app.models import Message

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_embedding_client():
    """Initialize OpenAI client for embeddings."""
    try:
        from openai import OpenAI
    except ImportError:
        raise RuntimeError("openai package not available")

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")

    return OpenAI(api_key=api_key)

def generate_embedding(client, text: str, model: str = "text-embedding-3-small") -> List[float]:
    """Generate embedding vector for text."""
    # Truncate to avoid token limits
    text = text[:8000]

    try:
        resp = client.embeddings.create(model=model, input=[text])
        return resp.data[0].embedding
    except Exception as e:
        logger.error(f"Embedding generation failed: {e}")
        raise

def load_jsonl_split(split_name: str) -> List[dict]:
    """Load specified split from datasets directory."""
    repo_root = Path(__file__).resolve().parents[3]
    split_file = repo_root / "datasets" / f"dataphish_{split_name}.jsonl"

    if not split_file.exists():
        raise FileNotFoundError(f"Split file not found: {split_file}")

    data = []
    with open(split_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                data.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    logger.info(f"Loaded {len(data)} emails from {split_file}")
    return data

def insert_to_database(session: Session, email_data: dict, embedding: List[float], split_name: str):
    """Insert email record with embedding into messages table."""
    # Map Type to binary label
    label = 1 if email_data.get("Type") in ["Phishing", "Spam", "Phishing Simulation"] else 0

    message = Message(
        sender_email=email_data.get("Sender", "unknown@example.com"),
        sender=email_data.get("Sender", ""),
        subject=email_data.get("Subject", ""),
        body=email_data.get("Body", ""),
        urls=0,  # Will be updated if we detect URLs
        label=label,
        doc_emb=embedding,
        verdict="benign",  # Placeholder, not used for corpus
        score=0
    )

    session.add(message)

def main():
    parser = argparse.ArgumentParser(description="Load DataPhish split to vector database")
    parser.add_argument("--split", required=True, choices=["train", "val", "test"],
                        help="Which split to load")
    parser.add_argument("--limit", type=int, default=None,
                        help="Limit number of emails to load (for testing)")
    parser.add_argument("--batch-size", type=int, default=100,
                        help="Batch size for database commits")
    args = parser.parse_args()

    logger.info("="*70)
    logger.info(f"Loading DataPhish {args.split} split to database")
    logger.info("="*70)

    # Load data
    data = load_jsonl_split(args.split)

    if args.limit:
        data = data[:args.limit]
        logger.info(f"Limited to {len(data)} emails")

    # Initialize embedding client
    logger.info("\nInitializing OpenAI client...")
    client = get_embedding_client()

    # Process and insert
    start_time = time.time()
    last_report = start_time

    with Session(engine) as session:
        for idx, email in enumerate(data):
            # Generate embedding
            text = f"{email.get('Subject', '')}\n\n{email.get('Body', '')}"

            try:
                embedding = generate_embedding(client, text)
                insert_to_database(session, email, embedding, args.split)

                # Commit in batches
                if (idx + 1) % args.batch_size == 0:
                    session.commit()

                    # Progress reporting
                    current_time = time.time()
                    if current_time - last_report >= 60:
                        elapsed = current_time - start_time
                        rate = (idx + 1) / elapsed
                        remaining = len(data) - (idx + 1)
                        eta_seconds = remaining / rate if rate > 0 else 0

                        logger.info(
                            f"PROGRESS: {idx+1}/{len(data)} ({(idx+1)/len(data)*100:.1f}%) | "
                            f"Rate: {rate:.2f}/sec | ETA: {eta_seconds/60:.1f}min"
                        )
                        last_report = current_time
                    elif (idx + 1) % 50 == 0:
                        logger.info(f"Processed {idx+1}/{len(data)}")

            except Exception as e:
                logger.error(f"Failed on email {idx}: {e}")
                session.rollback()
                continue

        # Final commit
        session.commit()

    total_time = time.time() - start_time
    logger.info(f"\n{'='*70}")
    logger.info(f"✓ Loaded {len(data)} emails in {total_time/60:.2f} minutes")
    logger.info(f"  Average rate: {len(data)/total_time:.2f} emails/sec")
    logger.info(f"{'='*70}")

if __name__ == "__main__":
    main()

"""
Retrieval Quality Sampling Script

Generates a sample of 50 query emails paired with their top retrieved neighbors
for manual relevance evaluation (Issue #3).

Output: CSV file with columns:
- query_id
- query_subject
- query_body_preview
- top_neighbor_id
- top_neighbor_subject
- top_neighbor_similarity
- top_neighbor_body_preview
"""

import pandas as pd
import re
from app.schemas import EmailIn
from app.pipeline.classify import classify_email
from app.ai_service.service import analyze_email
from pathlib import Path

def clean_sender(sender_val) -> str:
    """Extract a valid-ish email address from messy sender strings."""
    s = str(sender_val).strip()
    # 1. Look for content inside angle brackets <email>
    match = re.search(r'<([^>]+)>', s)
    if match:
        candidate = match.group(1).strip()
        if "@" in candidate: 
            return candidate.replace(" ", "") # Remove spaces (common in this dataset)
    
    # 2. Look for simple email pattern if no brackets
    match = re.search(r'[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}', s)
    if match:
        return match.group(0)
        
    # 3. Fallback or return original if it looks okay-ish
    if "@" in s:
        return s.replace(" ", "")
        
    return "unknown@example.com"

def sample_retrieval_pairs(sample_size: int = 50, output_path: str = "/app/reports/retrieval_quality_sample.csv"):
    print(f"Sampling {sample_size} emails for retrieval quality check...")
    
    # Load test set
    df = pd.read_csv("/app/test_data.csv")
    
    # Filter for phishing emails only (label=1) to check if we retrieve other phishing
    # or just take random sample. Instruction says "50 retrieved neighbors".
    # Taking random sample from full test set is more representative.
    sample = df.sample(n=min(sample_size, len(df)), random_state=42)
    
    results = []
    
    for idx, row in sample.iterrows():
        try:
            # Construct payload with cleaned sender
            clean_s = clean_sender(row.get("sender", "unknown"))
            
            email_in = EmailIn(
                sender=clean_s,
                subject=str(row.get("subject", "")),
                body=str(row.get("body", "")),
                url=int(row.get("url", 0))
            )
            
            # Phase 1
            phase1 = classify_email(email_in.model_dump())
            
            # Phase 2 (RAG)
            analysis = analyze_email(email_in, phase1, neighbors_k=1)
            
            # Get top neighbor
            if analysis.neighbors:
                top_n = analysis.neighbors[0]
                
                results.append({
                    "query_id": row.get("id", idx),
                    "query_subject": email_in.subject[:100],
                    "query_body": email_in.body[:200].replace("\n", " "),
                    "retrieved_id": top_n.id,
                    "similarity": f"{top_n.similarity:.4f}",
                    "retrieved_subject": (top_n.subject or "")[:100],
                    "retrieved_body": (top_n.body or "")[:200].replace("\n", " ")
                })
                
        except Exception as e:
            print(f"Skipping row {idx}: {e}")
            
    # Save to CSV
    out_df = pd.DataFrame(results)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(output_path, index=False)
    print(f"✅ Saved retrieval sample to {output_path}")

if __name__ == "__main__":
    sample_retrieval_pairs()

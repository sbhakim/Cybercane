"""
Single source of truth for evaluation labels.

Two tasks are evaluated:
  - "phish":    phishing vs legitimate. Spam is excluded from evaluation.
  - "unwanted": phishing or spam vs legitimate.

Every evaluator and baseline must derive labels through `task_label()` so that
positives are defined identically across methods.
"""

from typing import Optional

TASKS = ("phish", "unwanted")

# Fine-grained class per source record: "phishing" | "spam" | "legit"
_DATAPHISH_TYPES = {
    "phishing": "phishing",
    "phishing simulation": "phishing",
    "spam": "spam",
    "valid": "legit",
}


def fine_class(source: str, record: dict) -> str:
    """Map a raw record to its fine-grained class."""
    if source == "dataphish":
        t = str(record.get("Type", "")).strip().lower()
        if t not in _DATAPHISH_TYPES:
            raise ValueError(f"Unknown DataPhish Type: {record.get('Type')!r}")
        return _DATAPHISH_TYPES[t]
    if source == "nazario":
        # Nazario corpus contains phishing only.
        return "phishing"
    if source == "spamassassin":
        # SpamAssassin label: 1 = spam, 0 = ham.
        return "spam" if int(record.get("label", 0)) == 1 else "legit"
    raise ValueError(f"Unknown source: {source!r}")


def task_label(fine: str, task: str) -> Optional[int]:
    """
    Binary label for a task, or None if the record is excluded from that task.
    """
    if task not in TASKS:
        raise ValueError(f"Unknown task: {task!r}")
    if fine == "legit":
        return 0
    if fine == "phishing":
        return 1
    if fine == "spam":
        return 1 if task == "unwanted" else None
    raise ValueError(f"Unknown fine class: {fine!r}")

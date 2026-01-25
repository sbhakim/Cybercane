"""
Generate dataset card for synthetic phishing dataset.

Creates publication-ready documentation following modern ML dataset standards
(inspired by Hugging Face, Data Sheets for Datasets, etc.).
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path


CARD_TEMPLATE = """# Synthetic Healthcare Phishing Dataset

**Version:** {version}
**Generated:** {generated_date}
**Contact:** {contact}
**License:** {license}

## Dataset Description

### Overview
{description}

This dataset contains **{total_samples} synthetic healthcare phishing emails** generated using a multi-model approach for evaluating privacy-preserving phishing detection systems in regulated domains (healthcare, finance, legal).

### Key Statistics
- **Total samples:** {total_samples}
- **Categories:** {num_categories} ({category_list})
- **Generator models:** {num_models} ({model_list})
- **Holdout models:** {holdout_models}
- **URL presence:** {url_percentage:.1f}%
- **Unique subjects:** {unique_subjects_pct:.1f}%

### Generation Protocol

**Provenance Tracking:**
Every sample includes full generation metadata for reproducibility:
- `gen_model`: LLM used for generation
- `gen_temperature`: Temperature parameter
- `gen_seed`: Random seed ({seed})
- `prompt_version`: Prompt template version ({prompt_version})
- `gen_timestamp`: Generation timestamp (ISO 8601)
- `template_id`: Source template identifier

**Multi-Model Generation:**
Samples distributed across {num_models} generator models to reduce model-specific bias:
{model_distribution}

**Quality Filters Applied:**
- URL requirement: {url_required}
- Body length: {min_body_length}-{max_body_length} chars
- Subject length: {min_subject_length}-{max_subject_length} chars
- Category keyword validation: {require_keywords}

### Deduplication

**Exact Duplicates:**
- Removed: {exact_removed} samples
- Method: SHA-256 hash of subject+body

**Near-Duplicates:**
- Threshold: {near_dup_threshold} cosine similarity
- Method: TF-IDF (1-3 grams)
- Removed: {near_removed} samples

**Retention Rate:** {retention_rate:.1f}%

### Contamination Control

**Corpora Checked:**
{corpora_list}

**Threshold:** {contamination_threshold} cosine similarity
**Embedding Model:** {embedding_model}
**Contaminated Samples Removed:** {contaminated_count}
**Contamination Rate:** {contamination_rate:.2f}%

**Similarity Distribution:**
- Mean: {sim_mean:.4f}
- Median: {sim_median:.4f}
- P95: {sim_p95:.4f}
- P99: {sim_p99:.4f}
- Max: {sim_max:.4f}

## Attack Categories

{category_descriptions}

## Data Fields

### Core Fields
- `id` (string): Unique sample identifier
- `category` (string): Attack category
- `subject` (string): Email subject line
- `body` (string): Email body text
- `sender` (string): Typosquatted sender address
- `label` (int): Always 1 (phishing)
- `urls` (int): URL presence flag (0/1)

### Provenance Metadata
- `gen_model` (string): Generator model name
- `gen_provider` (string): API provider (openai, anthropic)
- `gen_temperature` (float): Sampling temperature
- `gen_seed` (int): Random seed
- `gen_timestamp` (string): ISO 8601 timestamp
- `prompt_version` (string): Prompt template version
- `template_id` (string): Source template hash
- `sample_index` (int): Index within category

### Quality Metrics
- `body_length` (int): Character count
- `subject_length` (int): Character count
- `sample_hash` (string): SHA-256 content hash

## Intended Use

### Primary Use
Evaluating phishing detection systems in **privacy-critical domains** where:
1. False positives disrupt critical workflows (healthcare appointments, insurance claims)
2. Vulnerable populations (elderly, low digital literacy) require extra protection
3. Privacy regulations prohibit external data transmission

### Out-of-Scope Use
- **Training phishing detectors** (synthetic data may not generalize)
- **Benchmarking general phishing systems** (use real-world datasets like DataPhish 2025)
- **Adversarial research** without ethical review

## Limitations

### Known Limitations
1. **Single-domain focus:** Healthcare-specific; may not generalize to other domains
2. **LLM generation artifacts:** Patterns may differ from human-authored phishing
3. **Template-based diversity:** Despite deduplication, samples share structural patterns
4. **Temporal validity:** Tactics reflect 2025-era phishing; may become outdated
5. **English-only:** No multilingual coverage

### Bias Considerations
- **Generator bias:** Despite multi-model approach, all generators are frontier LLMs (potential homogeneity)
- **Category balance:** Equal distribution (50/category) may not reflect real-world prevalence
- **Sophistication spectrum:** Focuses on professional-tone attacks; misses low-effort spam

## Ethical Considerations

### Responsible Use
This dataset is published for **defensive security research only**. Users must:
- Conduct research under institutional ethics review
- Not use samples for unauthorized phishing campaigns
- Not distribute samples without attribution
- Report vulnerabilities discovered to affected organizations

### Vulnerable Populations
Samples target **elderly patients** and **vulnerable populations**. Researchers must:
- Consider dignity and respect in evaluation design
- Avoid re-traumatizing participants in user studies
- Ensure informed consent for human subject research

## Reproducibility

### Regeneration
To reproduce this dataset:
```bash
# 1. Clone repository
git clone https://github.com/sbhakim/Cybercane
cd Cybercane

# 2. Set API keys
export OPENAI_API_KEY="your-key"
export DEEPSEEK_API_KEY="your-key"
export ANTHROPIC_API_KEY="your-key"

# 3. Run pipeline
python -m app.evaluation.run_synthetic_pipeline_v2 \\
  --config api/app/evaluation/configs/synthetic_healthcare_v1.json \\
  --corpora datasets/train_combined.csv datasets/val_combined.csv datasets/test_combined.csv
```

**Deterministic Seed:** {seed}
**Expected Output:** ~{total_samples} samples (±5% due to API variability)

### Files
- **Dataset:** `{dataset_path}`
- **Manifest:** `{manifest_path}`
- **Dedup Report:** `{dedup_report_path}`
- **Contamination Report:** `{contamination_report_path}`

## Citation

If you use this dataset, please cite:

```bibtex
@misc{{cybercane_synthetic_{version},
  title={{Synthetic Healthcare Phishing Dataset for Privacy-Preserving Detection}},
  author={{[Authors]}},
  year={{2025}},
  url={{https://github.com/sbhakim/Cybercane}},
  note={{Version {version}, generated {generated_date}}}
}}
```

## Changelog

### v1.0 ({generated_date})
- Initial release
- {total_samples} samples across {num_categories} categories
- Multi-model generation ({num_models} models)
- Deduplication and contamination filtering
- Full provenance tracking

## Contact

For questions, issues, or collaboration:
- **GitHub:** https://github.com/sbhakim/Cybercane/issues
- **Email:** {contact}

---
**Generated by:** CyberCane Synthetic Pipeline v2.0
**Last Updated:** {generated_date}
"""


def load_manifest(path: Path) -> dict:
    """Load manifest JSON."""
    with open(path) as f:
        return json.load(f)


def format_model_distribution(dist: dict) -> str:
    """Format model distribution as markdown list."""
    total = sum(dist.values())
    lines = []
    for model, count in sorted(dist.items(), key=lambda x: -x[1]):
        pct = count / total * 100 if total > 0 else 0
        lines.append(f"- {model}: {count} samples ({pct:.1f}%)")
    return "\n".join(lines)


def format_category_descriptions(categories: dict) -> str:
    """Format category descriptions."""
    lines = []
    for cat_name, cat_info in categories.items():
        count = cat_info.get("count", "N/A")
        desc = cat_info.get("description", "No description")
        lines.append(f"### {cat_name.replace('_', ' ').title()}")
        lines.append(f"**Count:** {count}  ")
        lines.append(f"**Description:** {desc}\n")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate dataset card")
    parser.add_argument(
        "--manifest",
        required=True,
        help="Manifest JSON path"
    )
    parser.add_argument(
        "--output",
        default="datasets/DATASET_SYNTHETIC_HEALTHCARE_V1.md",
        help="Output dataset card path"
    )
    parser.add_argument(
        "--contact",
        default="safayat.b.hakim@gmail.com",
        help="Contact email"
    )
    parser.add_argument(
        "--license",
        default="MIT",
        help="Dataset license"
    )
    args = parser.parse_args()

    # Load manifest
    manifest_path = Path(args.manifest)
    manifest = load_manifest(manifest_path)

    # Extract data
    metadata = manifest.get("metadata", {})
    gen_config = manifest.get("generation_config", {})
    categories = manifest.get("categories", {})
    final_stats = manifest.get("final_dataset", {}).get("statistics", {})
    diversity = manifest.get("final_dataset", {}).get("diversity_metrics", {})
    dedup = manifest.get("deduplication", {})
    contamination = manifest.get("contamination_check", {})

    # Prepare template variables
    total_samples = final_stats.get("total_samples", 0)
    model_dist = final_stats.get("samples_by_model", {})
    category_dist = final_stats.get("samples_by_category", {})

    template_vars = {
        # Metadata
        "version": metadata.get("dataset_version", "v1.0"),
        "generated_date": metadata.get("generated_at", datetime.utcnow().isoformat()),
        "contact": args.contact,
        "license": args.license,
        "description": metadata.get("description", "Multi-model synthetic healthcare phishing dataset"),

        # Statistics
        "total_samples": total_samples,
        "num_categories": len(categories),
        "category_list": ", ".join(categories.keys()),
        "num_models": len(gen_config.get("models", [])),
        "model_list": ", ".join(m.get("name", "unknown") for m in gen_config.get("models", [])),
        "holdout_models": ", ".join(gen_config.get("holdout_models", [])),
        "url_percentage": final_stats.get("url_presence", {}).get("percentage", 0),
        "unique_subjects_pct": diversity.get("unique_subjects", {}).get("percentage", 0),

        # Generation config
        "seed": gen_config.get("seed", 42),
        "prompt_version": gen_config.get("prompt_version", "unknown"),
        "model_distribution": format_model_distribution(model_dist),

        # Quality filters
        "url_required": "Yes",
        "min_body_length": 100,
        "max_body_length": 1000,
        "min_subject_length": 5,
        "max_subject_length": 100,
        "require_keywords": "Yes",

        # Deduplication
        "exact_removed": dedup.get("results", {}).get("exact_duplicates_removed", 0),
        "near_dup_threshold": 0.85,
        "near_removed": dedup.get("results", {}).get("near_duplicates_removed", 0),
        "retention_rate": dedup.get("results", {}).get("retention_rate", 1.0) * 100,

        # Contamination
        "corpora_list": "\n".join(f"- {Path(p).name}" for p in contamination.get("corpora_files", [])),
        "contamination_threshold": contamination.get("threshold", 0.90),
        "embedding_model": contamination.get("embedding_model", "text-embedding-3-small"),
        "contaminated_count": contamination.get("results", {}).get("contaminated_samples", 0),
        "contamination_rate": contamination.get("results", {}).get("contamination_rate", 0) * 100,
        "sim_mean": contamination.get("statistics", {}).get("similarity_stats", {}).get("mean", 0),
        "sim_median": contamination.get("statistics", {}).get("similarity_stats", {}).get("median", 0),
        "sim_p95": contamination.get("statistics", {}).get("similarity_stats", {}).get("p95", 0),
        "sim_p99": contamination.get("statistics", {}).get("similarity_stats", {}).get("p99", 0),
        "sim_max": contamination.get("statistics", {}).get("similarity_stats", {}).get("max", 0),

        # Categories
        "category_descriptions": format_category_descriptions(categories),

        # Paths
        "dataset_path": "reports/synthetic_healthcare_phishing_v1_clean.csv",
        "manifest_path": str(manifest_path),
        "dedup_report_path": "reports/synthetic_healthcare_phishing_v1_dedup_report.json",
        "contamination_report_path": "reports/synthetic_healthcare_phishing_v1_clean_contamination_report.json",
    }

    # Generate card
    card_content = CARD_TEMPLATE.format(**template_vars)

    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(card_content)

    print(f"✓ Generated dataset card: {output_path}")
    print(f"\n📄 Preview (first 20 lines):")
    print("─" * 80)
    for line in card_content.split("\n")[:20]:
        print(line)
    print("─" * 80)
    print(f"\nFull card: {output_path}")


if __name__ == "__main__":
    main()

"""
End-to-end synthetic phishing generation pipeline.

Orchestrates:
1. Multi-model generation with provenance
2. Deduplication (exact + near-dup)
3. Contamination checking
4. Manifest generation
5. Dataset card creation

Conference-grade reproducible pipeline.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import List


class PipelineStep:
    """Represents a single pipeline step."""

    def __init__(self, name: str, command: List[str], description: str):
        self.name = name
        self.command = command
        self.description = description

    def run(self) -> bool:
        """Execute step and return success status."""
        print(f"\n{'='*80}")
        print(f"STEP: {self.name}")
        print(f"{'='*80}")
        print(f"Description: {self.description}")
        print(f"Command: {' '.join(self.command)}")
        print(f"{'='*80}\n")

        try:
            result = subprocess.run(
                self.command,
                check=True,
                capture_output=False,
                text=True
            )
            print(f"\n✓ {self.name} completed successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"\n✗ {self.name} failed with exit code {e.returncode}")
            return False
        except Exception as e:
            print(f"\n✗ {self.name} failed with error: {e}")
            return False


def build_pipeline(
    config_path: str,
    corpora_paths: List[str],
    skip_generation: bool = False,
    skip_contamination: bool = False
) -> List[PipelineStep]:
    """Build pipeline steps."""
    steps = []

    # Intermediate file paths (derived from config)
    raw_output = "reports/synthetic_healthcare_phishing_v1_raw.csv"
    dedup_output = "reports/synthetic_healthcare_phishing_v1_dedup.csv"
    clean_output = "reports/synthetic_healthcare_phishing_v1_clean.csv"
    dedup_report = "reports/synthetic_healthcare_phishing_v1_dedup_report.json"
    contamination_report = "reports/synthetic_healthcare_phishing_v1_clean_contamination_report.json"
    manifest_output = "reports/synthetic_generation_manifest_v1.json"

    # Step 1: Generation
    if not skip_generation:
        steps.append(PipelineStep(
            name="1. Multi-Model Generation",
            command=[
                sys.executable, "-m", "app.evaluation.generate_healthcare_phishing_v2",
                "--config", config_path,
                "--output", raw_output,
            ],
            description="Generate synthetic phishing emails with multi-model provenance tracking"
        ))

    # Step 2: Deduplication
    steps.append(PipelineStep(
        name="2. Deduplication",
        command=[
            sys.executable, "-m", "app.evaluation.deduplicate_synthetic",
            "--input", raw_output,
            "--output", dedup_output,
            "--threshold", "0.85",
            "--report", dedup_report,
        ],
        description="Remove exact and near-duplicate samples (threshold=0.85)"
    ))

    # Step 3: Contamination Check
    if not skip_contamination and corpora_paths:
        steps.append(PipelineStep(
            name="3. Contamination Check",
            command=[
                sys.executable, "-m", "app.evaluation.check_contamination",
                "--input", dedup_output,
                "--corpora", *corpora_paths,
                "--output", clean_output,
                "--threshold", "0.90",
                "--report", contamination_report,
                "--model", "text-embedding-3-small",
            ],
            description="Check for overlap with train/val/test corpora (threshold=0.90)"
        ))
    else:
        # If skipping contamination, final output is dedup output
        clean_output = dedup_output

    # Step 4: Manifest Generation
    manifest_cmd = [
        sys.executable, "-m", "app.evaluation.generate_manifest",
        "--config", config_path,
        "--final-data", clean_output,
        "--output", manifest_output,
    ]
    if not skip_generation:
        manifest_cmd.extend(["--dedup-report", dedup_report])
    if not skip_contamination and corpora_paths:
        manifest_cmd.extend(["--contamination-report", contamination_report])

    steps.append(PipelineStep(
        name="4. Manifest Generation",
        command=manifest_cmd,
        description="Generate comprehensive reproducibility manifest"
    ))

    # Step 5: Dataset Card (template only - user fills in)
    steps.append(PipelineStep(
        name="5. Dataset Card Template",
        command=[
            sys.executable, "-m", "app.evaluation.create_dataset_card",
            "--manifest", manifest_output,
            "--output", "datasets/DATASET_SYNTHETIC_HEALTHCARE_V1.md",
        ],
        description="Create dataset card template for documentation"
    ))

    return steps


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run end-to-end synthetic phishing generation pipeline"
    )
    parser.add_argument(
        "--config",
        default="api/app/evaluation/configs/synthetic_healthcare_v1.json",
        help="Generation config JSON path"
    )
    parser.add_argument(
        "--corpora",
        nargs="+",
        help="Real corpus CSV paths for contamination checking (train, val, test)"
    )
    parser.add_argument(
        "--skip-generation",
        action="store_true",
        help="Skip generation step (use existing raw data)"
    )
    parser.add_argument(
        "--skip-contamination",
        action="store_true",
        help="Skip contamination check (faster, less rigorous)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print pipeline steps without executing"
    )
    args = parser.parse_args()

    print(f"{'='*80}")
    print(f"SYNTHETIC PHISHING GENERATION PIPELINE V2")
    print(f"{'='*80}")
    print(f"Config: {args.config}")
    print(f"Corpora: {len(args.corpora) if args.corpora else 0} files")
    print(f"Skip generation: {args.skip_generation}")
    print(f"Skip contamination: {args.skip_contamination}")
    print(f"{'='*80}\n")

    # Build pipeline
    pipeline = build_pipeline(
        config_path=args.config,
        corpora_paths=args.corpora or [],
        skip_generation=args.skip_generation,
        skip_contamination=args.skip_contamination
    )

    print(f"Pipeline: {len(pipeline)} steps")
    for i, step in enumerate(pipeline, 1):
        print(f"  {i}. {step.name}")

    if args.dry_run:
        print(f"\n[DRY RUN] Pipeline commands:")
        for step in pipeline:
            print(f"\n{step.name}:")
            print(f"  {' '.join(step.command)}")
        return

    # Execute pipeline
    print(f"\n{'='*80}")
    print(f"EXECUTING PIPELINE")
    print(f"{'='*80}")

    success_count = 0
    for i, step in enumerate(pipeline, 1):
        print(f"\n[{i}/{len(pipeline)}] Starting: {step.name}")

        success = step.run()

        if success:
            success_count += 1
        else:
            print(f"\n{'='*80}")
            print(f"PIPELINE FAILED AT STEP {i}: {step.name}")
            print(f"{'='*80}")
            print(f"Completed: {success_count}/{len(pipeline)} steps")
            sys.exit(1)

    # Success summary
    print(f"\n{'='*80}")
    print(f"PIPELINE COMPLETED SUCCESSFULLY")
    print(f"{'='*80}")
    print(f"All {len(pipeline)} steps completed")
    print(f"\n📂 Output files:")
    print(f"  - Final dataset: reports/synthetic_healthcare_phishing_v1_clean.csv")
    print(f"  - Manifest: reports/synthetic_generation_manifest_v1.json")
    print(f"  - Dataset card: datasets/DATASET_SYNTHETIC_HEALTHCARE_V1.md")
    print(f"  - Dedup report: reports/synthetic_healthcare_phishing_v1_dedup_report.json")
    if not args.skip_contamination:
        print(f"  - Contamination report: reports/synthetic_healthcare_phishing_v1_clean_contamination_report.json")
    print(f"\n✓ Ready for evaluation and manuscript integration")
    print(f"{'='*80}")


if __name__ == "__main__":
    main()

"""
Complete healthcare validation pipeline.

Orchestrates:
1. Synthetic phishing generation (naive baseline + sophisticated healthcare attacks)
2. Evaluation on synthetic datasets

This script can be run in stages or all at once.
"""
import subprocess
import sys
import os
import argparse


def run_command(cmd: list, description: str) -> int:
    """Run a subprocess command with logging."""
    print(f"\n{'='*80}")
    print(f"STEP: {description}")
    print(f"CMD: {' '.join(cmd)}")
    print(f"{'='*80}\n")
    result = subprocess.run(cmd, cwd="/app")
    if result.returncode != 0:
        print(f"❌ FAILED: {description} (exit code {result.returncode})")
        return result.returncode
    print(f"✅ SUCCESS: {description}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Run healthcare validation pipeline")
    parser.add_argument(
        "--skip-generate",
        action="store_true",
        help="Skip synthetic data generation (use existing CSV)",
    )
    parser.add_argument(
        "--skip-evaluate",
        action="store_true",
        help="Skip evaluation (use existing results)",
    )
    parser.add_argument(
        "--count-per-category",
        type=int,
        default=50,
        help="Number of synthetic emails per category (default: 50)",
    )
    args = parser.parse_args()

    steps_run = []
    failed = False

    # Step 1: Generate synthetic healthcare phishing
    if not args.skip_generate:
        ret = run_command(
            [
                "python", "-m", "app.evaluation.generate_healthcare_phishing",
                "--count-per-category", str(args.count_per_category),
                "--save-every", "10",
                "--temperature", "0.8",
            ],
            "Generate synthetic healthcare phishing emails",
        )
        if ret != 0:
            print("⚠️  Generation failed. You can retry with --skip-generate if data exists.")
            failed = True
        else:
            steps_run.append("✅ Generated synthetic phishing")

    # Step 2: Evaluate on synthetic dataset
    if not args.skip_evaluate and not failed:
        ret = run_command(
            [
                "python", "-m", "app.evaluation.evaluate_healthcare_synthetic",
                "--benign-sample", "200",
                "--k", "8",
            ],
            "Evaluate CyberCane on synthetic healthcare dataset",
        )
        if ret != 0:
            print("⚠️  Evaluation failed. Check that synthetic CSV exists.")
            failed = True
        else:
            steps_run.append("✅ Evaluated synthetic dataset")

    # Summary
    print(f"\n{'='*80}")
    print("HEALTHCARE VALIDATION PIPELINE COMPLETE")
    print(f"{'='*80}")
    for step in steps_run:
        print(step)

    if failed:
        print("\n❌ Some steps failed. See errors above.")
        sys.exit(1)
    else:
        print("\n✅ All steps completed successfully!")
        print("\n📋 Results saved to reports/ directory:")
        print("   - healthcare_synthetic_results.csv")
        print("   - healthcare_synthetic_results_by_category.csv")
        print("   - naive_baseline_results.csv")
        sys.exit(0)


if __name__ == "__main__":
    main()

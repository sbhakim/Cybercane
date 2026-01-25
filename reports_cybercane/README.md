# CyberCane Research Evaluation Scripts

This directory holds the six focused evaluation scripts for the CyberCane pipeline. Each script writes timestamped CSV outputs under `reports/<analysis>_YYYYMMDD_HHMMSS/tables/`.

## Prerequisites
- Run from repo root with `PYTHONPATH=api`.
- Input splits are expected under `reports/` (e.g., `reports/combined_eval_split_test.csv`).
- DNS checks are optional and add network latency when enabled.

## Scripts (concise)

1) `retrieval_augmented_ablation_study.py`  
Phase 1 baseline plus a scaffold for RAG k-ablation. The RAG block is stubbed; wire to `app.ai_service.service` or supply precomputed predictions.  
```bash
PYTHONPATH=api python reports_cybercane/retrieval_augmented_ablation_study.py \
  --test reports/combined_eval_split_test.csv --tuned --enable-dns --k-values 3,5,8
```

2) `paired_statistical_tests.py`  
Paired McNemar test and bootstrap CIs for two prediction columns. Expects `pred_phase1_only` and `pred_rag_k8`.  
```bash
PYTHONPATH=api python reports_cybercane/paired_statistical_tests.py \
  --predictions reports/rag_ablations_YYYYMMDD_HHMMSS/tables/rag_ablation_predictions.csv \
  --n-bootstrap 10000 --seed 42
```

3) `leave_one_out_feature_analysis.py`  
Leave-one-out ablation over deterministic rules; writes per-rule precision/recall/FPR deltas.  
```bash
PYTHONPATH=api python reports_cybercane/leave_one_out_feature_analysis.py \
  --test reports/combined_eval_split_test.csv --threshold 2
```

4) `failure_case_taxonomy.py`  
Categorizes false negatives and false positives using Phase 1 signals and content heuristics.  
```bash
PYTHONPATH=api python reports_cybercane/failure_case_taxonomy.py \
  --predictions reports/rag_ablations_YYYYMMDD_HHMMSS/tables/rag_ablation_predictions.csv \
  --pred-column pred_rag_k8 --sample-size 20
```

5) `threshold_optimization.py`  
Sweeps Phase 1 score thresholds on validation data and selects the best precision-constrained operating point.  
```bash
PYTHONPATH=api python reports_cybercane/threshold_optimization.py \
  --val reports/combined_eval_split_val.csv --tuned --enable-dns --min-precision 0.95
```

6) `explanation_quality_evaluation.py`  
Summarizes deterministic explanation tags and lengths. RAG similarity is currently a placeholder.  
```bash
PYTHONPATH=api python reports_cybercane/explanation_quality_evaluation.py \
  --test reports/combined_eval_split_test.csv --tuned --enable-dns
```

## Outputs
Each script creates a timestamped folder in `reports/` with CSV tables (for example: `rag_ablation_metrics.csv`, `feature_importance.csv`, `threshold_metrics.csv`, `explanation_summary.csv`).
- **`weight_sensitivity_analysis.py`**: Analyzes performance sensitivity to individual weight perturbations

### Visualization & Table Generation
- **`generate_confusion_matrices.py`**: Creates confusion matrix visualizations for figures
- **`format_results_tables.py`**: Converts CSV results to LaTeX-formatted tables
- **`plot_operating_curves.py`**: Matplotlib figures for ROC/PR curves

### Reproducibility & Validation
- **`seed_all_experiments.py`**: Sets random seeds (42) for NumPy, PyTorch, sklearn to ensure reproducibility
- **`validate_test_set_integrity.py`**: Checks for data leakage between train/val/test splits
- **`rerun_all_evaluations.sh`**: Bash script to reproduce all experiments from scratch

---

## Environment Setup

### Prerequisites
- Python 3.9+
- PostgreSQL 14+ with pgvector extension (for RAG experiments)
- OpenAI API key or DeepSeek API key (for embeddings)

### Installation
```bash
# Install Python dependencies
cd api
pip install -r requirements.txt

# Set API keys (for RAG experiments only)
export OPENAI_API_KEY="sk-..."
# OR
export DEEPSEEK_API_KEY="sk-..."

# Verify database connection (for RAG experiments only)
python -c "from app.ai_service import service; print('Database ready')"
```

### Running Scripts
All scripts use `PYTHONPATH=api` to ensure correct module imports:

```bash
PYTHONPATH=api python reports_cybercane/SCRIPT_NAME.py [args]
```

---

## Reproducibility Notes

### Random Seeds
All experiments use fixed random seed (42) for reproducibility:
- NumPy random operations
- Train/test splitting
- Bootstrap resampling
- RAG neighbor retrieval (if tie-breaking needed)

### Data Splits
Pre-computed stratified splits ensure consistency:
- **Train**: 60% (n=15,000) - Used for embedding corpus only (no supervised training)
- **Val**: 20% (n=5,000) - Used for threshold/weight tuning
- **Test**: 20% (n=5,000) - Held-out for final evaluation

### Validation Set Usage
- Threshold optimization: Uses validation set only (NOT test set)
- Rule weight tuning: Uses validation set only
- All reported results: Use pre-selected hyperparameters on test set (no peeking)

---

## Summary

These 6 scripts collectively demonstrate:

1. **Experimental Methodology**: Ablation studies, statistical significance testing, leave-one-out analysis
2. **Reproducibility**: Fixed seeds, pre-computed splits, detailed documentation
3. **Transparency**: Failure case taxonomy explains limitations
4. **Explainability**: Quantified explanation quality through metrics
5. **Healthcare Applicability**: Precision-first design with operational cost analysis

All experimental claims are backed by these systematic evaluations.

---

**Last Updated**: January 2026
**CyberCane Version**: 1.0

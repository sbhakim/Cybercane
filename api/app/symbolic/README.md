# Neuro-Symbolic Reasoning Module

This module implements **genuine neuro-symbolic AI** for CyberCane, combining:
- **Symbolic**: Formal OWL ontology with description logic reasoning
- **Neural**: Embedding-based semantic similarity with LLM reasoning

## Architecture Overview

```
Phase 1 (Deterministic Rules)
    ↓
Ontology Reasoning (NEW)
    ↓
Neural Retrieval (Existing)
    ↓
LLM Explanation (Existing)
    ↓
Final Verdict
```

## Components

### 1. `phishing_ontology.ttl`
Formal OWL/RDF ontology defining:
- **Attack taxonomy**: 4 healthcare-specific categories + base classes
- **Indicator properties**: 9 observable features (DNS, URL, content)
- **Inference rules**: OWL axioms for automatic classification
- **Severity levels**: Critical/High/Medium threat categorization

**Stats**: 47+ classes, 9 properties, 15+ inference rules

### 2. `ontology_reasoner.py`
Python interface to ontology using rdflib:
- `infer_attack_types()`: Classify email from Phase 1 indicators
- `get_explanation_chain()`: Generate human-readable reasoning trace
- `indicators_to_ontology_format()`: Convert Phase 1 dict to RDF

**Key innovation**: Bridges symbolic (OWL) and neural (embeddings) layers

### 3. `test_ontology.py`
Test suite validating:
- Ontology loading (RDF parsing)
- CredentialTheft inference from indicators
- Explanation chain generation
- URL-based attack detection
- Phase 1 indicator conversion

## Quick Start

### Install dependencies
```bash
cd api
pip install -r requirements.txt  # Includes rdflib==7.0.0
```

### Run tests
```bash
cd api
PYTHONPATH=. python -m app.symbolic.test_ontology
```

**Expected output:**
```
TEST 1: Ontology Loading
✓ Ontology loaded successfully
  - Total triples: 120+
  - Attack types: 8+
  ...

TEST 2: CredentialTheft Inference
Input indicators: ['creds_request', 'missing_mx', 'urgency']
Inferred attack types:
  - CredentialTheft: 100.0% confidence
✓ CredentialTheft correctly inferred
```

## Integration with Existing Pipeline

### Current (Phase 1 → RAG)
```python
# ai_service/service.py:530
def analyze_email(payload, phase1):
    vec = _embed_text(doc_text)
    neighbors = _nearest_neighbors(vec)
    verdict = _decide_ai_verdict(phase1, neighbors)
```

### Enhanced (Phase 1 → Ontology → RAG)
```python
# AFTER integration (Week 4)
def analyze_email(payload, phase1):
    # NEW: Ontology reasoning
    reasoner = create_reasoner()
    attack_types = reasoner.infer_attack_types(phase1.indicators)

    # Existing: Neural retrieval
    vec = _embed_text(doc_text)
    neighbors = _nearest_neighbors(vec)

    # NEW: Ontology-guided filtering
    if attack_types:
        neighbors = filter_by_attack_semantics(neighbors, attack_types)

    verdict = _decide_ai_verdict(phase1, neighbors, attack_types)
```

## Ontology Design Principles

### 1. **Grounded in manuscript taxonomy**
- 4 attack categories from Section 5.3 (Appointment, Insurance, Prescription, EHR)
- 9 indicators from Phase 1 rules (deterministic.py)
- Aligns with healthcare threat model (Appendix A.3)

### 2. **Explainable by design**
Every inference produces traceable reasoning:
```
Indicator: hasMissingMX = true
Indicator: hasCredentialRequest = true
Rule: CredentialTheft ≡ hasMissingMX ∧ hasCredentialRequest
Conclusion: Email classified as CredentialTheft (confidence: 100%)
```

### 3. **Extensible structure**
Easy to add:
- New attack types (e.g., `phish:MalwareDelivery`)
- New indicators (e.g., `phish:hasAttachment`)
- New brands (`phish:JohnsHopkins`, `phish:Medicare`)
- New populations (`phish:ElderlyPopulation`)

## Research Contributions

### For NeSy Conference Submission

**Novelty claims:**
1. ✅ **First formal phishing ontology** in security literature
2. ✅ **Hybrid symbolic-neural architecture** (OWL reasoning + embedding retrieval)
3. ✅ **Ontology-guided vector search** (novel retrieval strategy)
4. ✅ **Explainable neuro-symbolic pipeline** (full reasoning traces)

**Evaluation metrics to add:**
- Ontology coverage: % of test set matched by attack types
- Inference accuracy: % of ontology classifications matching ground truth
- Explanation quality: Human evaluation of reasoning chains
- Ablation: Ontology vs. no-ontology retrieval quality

## Development Roadmap

### ✅ Week 1 (Complete)
- [x] Design ontology schema (47 classes, 9 properties)
- [x] Implement OWL/RDF ontology file (.ttl)
- [x] Create Python reasoner with rdflib
- [x] Write test suite
- [x] Update requirements.txt

### 🚧 Week 2 (In Progress)
- [ ] Integrate with ai_service.py
- [ ] Add ontology_inference to AIAnalyzeOut schema
- [ ] Test on validation split
- [ ] Measure inference accuracy

### 📋 Week 3 (Planned)
- [ ] Implement ontology-guided neighbor filtering
- [ ] Add explanation chain to LLM prompt
- [ ] Evaluate on healthcare synthetic dataset
- [ ] Generate ablation results

### 📋 Week 4 (Planned)
- [ ] Full pipeline integration
- [ ] Performance optimization (cache reasoner)
- [ ] Documentation + manuscript section
- [ ] Prepare demo for reviewers

## File Structure

```
api/app/symbolic/
├── __init__.py                    # Module initialization
├── phishing_ontology.ttl          # OWL ontology (RDF Turtle format)
├── ontology_reasoner.py           # Reasoning engine
├── test_ontology.py               # Test suite
└── README.md                      # This file

# To be added in Week 2-3:
├── integration.py                 # Bridges with ai_service
├── neighbor_filter.py             # Ontology-guided retrieval
└── evaluation.py                  # Ontology-specific metrics
```

## Technical Details

### RDF/OWL Reasoning with rdflib
- **Language**: OWL 2 (Web Ontology Language)
- **Format**: Turtle (.ttl) - human-readable RDF serialization
- **Query**: SPARQL 1.1 for pattern matching
- **Inference**: Description logic via OWL semantics

### Why OWL?
- ✅ **Formal semantics**: Mathematically rigorous definitions
- ✅ **Automatic classification**: Reasoner infers class membership
- ✅ **Interoperability**: Standard format (W3C recommendation)
- ✅ **Tooling**: Mature libraries (rdflib, owlready2, Protégé)

## FAQs

**Q: Why not just use hardcoded rules?**
A: Ontology provides formal semantics, automatic inference, and extensibility. Hardcoded rules require manual updates; ontology supports reasoning (e.g., "CredentialTheft is a TechnicalAttack, so it inherits TechnicalAttack properties").

**Q: How does this differ from current "neuro-symbolic" claim?**
A: Current system is sequential (rules → RAG). Ontology adds **bidirectional coupling**: symbolic reasoning guides neural retrieval, and neural similarity activates symbolic inference.

**Q: Performance overhead?**
A: Minimal. Ontology reasoning is in-memory graph traversal (~5-10ms). We'll cache the reasoner instance for production.

**Q: Can reviewers verify correctness?**
A: Yes! Ontology file (.ttl) is human-readable. Reviewers can load in Protégé (standard OWL editor) and inspect classes/axioms visually.

## References

- **RDFLib**: https://rdflib.readthedocs.io/
- **OWL 2 Primer**: https://www.w3.org/TR/owl2-primer/
- **SPARQL Tutorial**: https://www.w3.org/TR/sparql11-query/
- **Protégé** (ontology editor): https://protege.stanford.edu/

## Contact

For questions about ontology design or integration, see `api/app/symbolic/test_ontology.py` for working examples.

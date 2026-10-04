"""
Ontology-based semantic reasoner for phishing detection.

This module implements formal OWL reasoning over the PhishOnt ontology to:
1. Classify emails into attack types using description logic
2. Infer attack patterns from observable indicators
3. Provide explainable reasoning chains for transparency

Key innovation: Combines symbolic reasoning (OWL inference) with neural
retrieval (embedding similarity) for true neuro-symbolic architecture.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from rdflib import BNode, Graph, Literal, Namespace, URIRef
from rdflib.collection import Collection
from rdflib.namespace import RDF, RDFS, OWL

logger = logging.getLogger(__name__)


class PhishingOntologyReasoner:
    """
    Semantic reasoner using PhishOnt formal ontology.

    The reasoner loads the OWL ontology and performs SPARQL-based inference
    to classify phishing attacks based on observed indicators.

    Usage:
        reasoner = PhishingOntologyReasoner()
        indicators = {"hasMissingMX": True, "hasCredentialRequest": True}
        attack_types = reasoner.infer_attack_types(indicators)
        # Returns: [("CredentialTheft", 1.0), ...]
    """

    def __init__(self, ontology_path: Optional[Path] = None):
        """
        Initialize reasoner with PhishOnt ontology.

        Args:
            ontology_path: Path to .ttl ontology file (defaults to bundled ontology)
        """
        self.graph = Graph()
        self.PHISH = Namespace("http://cybercane.ai/ontology/phishing#")

        # Load ontology
        if ontology_path is None:
            ontology_path = Path(__file__).parent / "phishing_ontology.ttl"

        try:
            self.graph.parse(ontology_path, format="turtle")
            logger.info(f"Loaded ontology with {len(self.graph)} triples")
        except Exception as e:
            logger.error(f"Failed to load ontology: {e}")
            raise

        # Cache attack type URIs for performance
        self._attack_types = self._get_all_attack_types()
        # Attack-pattern rules parsed from owl:equivalentClass axioms (single source of truth).
        self._rules = self._parse_rules()
        logger.info(f"Discovered {len(self._attack_types)} attack types in ontology")

    def _get_all_attack_types(self) -> List[URIRef]:
        """
        Query ontology for all PhishingAttack subclasses.

        Returns:
            List of attack type URIs
        """
        query = """
        PREFIX phish: <http://cybercane.ai/ontology/phishing#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT DISTINCT ?attack_type
        WHERE {
            ?attack_type rdfs:subClassOf* phish:PhishingAttack .
            FILTER(?attack_type != phish:PhishingAttack)
        }
        """

        results = self.graph.query(query)
        return [row.attack_type for row in results]

    def _map_indicator_to_property(self, indicator_key: str) -> str:
        """
        Map Phase 1 indicator keys to ontology property names.

        Args:
            indicator_key: Key from phase1.indicators (e.g., "missing_mx")

        Returns:
            Ontology property name (e.g., "hasMissingMX")
        """
        # Mapping from deterministic.py indicator keys to ontology properties
        mapping = {
            "missing_mx": "hasMissingMX",
            "no_spf": "hasMissingSPF",
            "no_dmarc": "hasMissingDMARC",
            "ip_literal_link": "hasIPLiteralURL",
            "shortened_url": "hasShortenedURL",
            "domain_mismatch": "hasDomainMismatch",
            "urgency": "hasUrgencyLanguage",
            "creds_request": "hasCredentialRequest",
            "freemail_sender": "hasFreemailSender",
            "freemail_brand_claim": "hasFreemailSender",
            # Add more mappings as ontology expands
        }

        return mapping.get(indicator_key, indicator_key)

    def infer_attack_types(self,
                           indicators: Dict[str, bool],
                           min_confidence: float = 1.0,
                           include_partial: bool = False) -> List[Tuple[str, float]]:
        """
        Attack classes supported by the observed indicators.

        By default only entailed classes (every premise of the defining axiom
        holds) are returned, each with value 1.0. Partial matches are returned
        only with include_partial=True, as (name, coverage m/r) with coverage
        >= min_confidence; coverage is a matching ratio, not a probability.
        """
        if not indicators:
            logger.warning("No indicators provided for inference")
            return []
        res = self.classify(indicators, min_suggest_coverage=min(min_confidence, 1.0))
        ranked = [(name, 1.0) for name in res["entailed"]]
        if include_partial:
            ranked += [(name, cov) for name, cov, _ in res["suggested"] if cov >= min_confidence]
        return ranked

    def _parse_rules(self) -> Dict[str, Dict[str, List[str]]]:
        """
        Read each defined class from its owl:equivalentClass axiom.

        Supported pattern: an owl:intersectionOf whose members are
        hasValue-true restrictions (required premises, "all_of") or one
        owl:unionOf of such restrictions ("any_of").
        """
        def prop_of(node) -> Optional[str]:
            prop = self.graph.value(node, OWL.onProperty)
            val = self.graph.value(node, OWL.hasValue)
            if prop is None or val is None or not bool(val.toPython()):
                return None
            return self._uri_to_name(prop)

        rules: Dict[str, Dict[str, List[str]]] = {}
        for cls, expr in self.graph.subject_objects(OWL.equivalentClass):
            members = self.graph.value(expr, OWL.intersectionOf)
            if members is None:
                continue
            all_of, any_of = [], []
            for m in Collection(self.graph, members):
                union = self.graph.value(m, OWL.unionOf)
                if union is not None:
                    any_of.extend(p for p in (prop_of(u) for u in Collection(self.graph, union)) if p)
                else:
                    p = prop_of(m)
                    if p:
                        all_of.append(p)
            rules[self._uri_to_name(cls)] = {"all_of": all_of, "any_of": any_of}
        return rules

    def _get_attack_rule(self, attack_type_uri: URIRef) -> Dict[str, List[str]]:
        """Rule structure for an attack type (empty if the class has no defining axiom)."""
        return self._rules.get(self._uri_to_name(attack_type_uri), {"all_of": [], "any_of": []})

    def _superclasses(self, name: str) -> List[str]:
        out = []
        for sup in self.graph.transitive_objects(self._name_to_uri(name), RDFS.subClassOf):
            if isinstance(sup, BNode):
                continue
            sname = self._uri_to_name(sup)
            if sname not in (name, "PhishingAttack"):
                out.append(sname)
        return out

    def classify(self, indicators: Dict[str, bool], min_suggest_coverage: float = 0.5) -> Dict[str, list]:
        """
        Classify observed indicators against the defined attack classes.

        Returns:
            entailed:  defined classes whose premises all hold (asserted)
            inherited: superclasses of entailed classes (asserted via rdfs:subClassOf)
            suggested: partial matches as (name, coverage m/r, missing premises);
                       these are NOT asserted and are reported only as hints
        """
        present = {self._map_indicator_to_property(k) for k, v in (indicators or {}).items() if v}
        entailed, suggested = [], []
        for name, rule in sorted(self._rules.items()):
            all_of, any_of = rule["all_of"], rule["any_of"]
            missing = [p for p in all_of if p not in present]
            any_ok = (not any_of) or any(p in present for p in any_of)
            if not any_ok:
                missing.append("one of (" + ", ".join(any_of) + ")")
            required = len(all_of) + (1 if any_of else 0)
            coverage = (required - len(missing)) / required if required else 0.0
            if not missing:
                entailed.append(name)
            elif coverage >= min_suggest_coverage:
                suggested.append((name, coverage, missing))
        inherited = sorted({s for e in entailed for s in self._superclasses(e)} - set(entailed))
        suggested.sort(key=lambda x: -x[1])
        return {"entailed": entailed, "inherited": inherited, "suggested": suggested}

    def get_explanation_chain(self,
                               indicators: Dict[str, bool],
                               attack_type: str) -> List[str]:
        """
        Generate human-readable explanation of inference chain.

        Args:
            indicators: Active indicators from Phase 1
            attack_type: Inferred attack type name

        Returns:
            List of explanation strings showing reasoning steps

        Example:
            ["Detected: Missing MX record",
             "Detected: Credential request language",
             "Rule: CredentialTheft = hasMissingMX AND hasCredentialRequest",
             "Conclusion: Email classified as CredentialTheft (confidence: 100%)"]
        """
        explanations = []

        # Step 1: List detected indicators
        active = {k: v for k, v in indicators.items() if v}
        for key in active:
            prop_name = self._map_indicator_to_property(key)
            explanations.append(f"✓ Detected: {self._format_property_name(prop_name)}")

        # Step 2: Show inference rule
        attack_uri = self._name_to_uri(attack_type)
        rule = self._get_attack_rule(attack_uri)
        all_of = rule.get("all_of", [])
        any_of = rule.get("any_of", [])

        if all_of or any_of:
            all_str = " AND ".join(self._format_property_name(ind) for ind in all_of) if all_of else ""
            any_str = " OR ".join(self._format_property_name(ind) for ind in any_of) if any_of else ""
            if all_str and any_str:
                rule_str = f"{all_str} AND ({any_str})"
            else:
                rule_str = all_str or any_str
            explanations.append(f"⚙ Rule: {attack_type} requires {rule_str}")

        # Step 3: Conclusion (asserted only when every premise holds)
        res = self.classify(indicators, min_suggest_coverage=0.0)
        if attack_type in res["entailed"]:
            explanations.append(f"✓ Conclusion: all premises hold; {attack_type} is asserted")
        else:
            partial = next((x for x in res["suggested"] if x[0] == attack_type), None)
            if partial:
                _, cov, missing = partial
                explanations.append(
                    f"△ Partial match only ({cov * 100:.0f}% of premises); not asserted. "
                    f"Missing: {', '.join(self._format_property_name(m) for m in missing)}"
                )

        return explanations

    def _uri_to_name(self, uri: URIRef) -> str:
        """Extract class/property name from URI."""
        return str(uri).split("#")[-1]

    def _name_to_uri(self, name: str) -> URIRef:
        """Convert name to full URI."""
        return URIRef(f"http://cybercane.ai/ontology/phishing#{name}")

    def _format_property_name(self, prop: str) -> str:
        """
        Format camelCase property to human-readable.

        Example: "hasMissingMX" -> "Missing MX record"
        """
        # Remove "has" prefix
        if prop.startswith("has"):
            prop = prop[3:]

        # Insert spaces before capitals
        import re
        spaced = re.sub(r'([A-Z])', r' \1', prop).strip()

        return spaced

    def get_ontology_stats(self) -> Dict[str, int]:
        """
        Return statistics about loaded ontology.

        Returns:
            Dictionary with counts of classes, properties, axioms
        """
        return {
            "total_triples": len(self.graph),
            "attack_types": len(self._attack_types),
            "classes": len(list(self.graph.subjects(RDF.type, OWL.Class))),
            "properties": len(list(self.graph.subjects(RDF.type, OWL.DatatypeProperty))),
        }


# ============================================================================
# Utility Functions for Integration
# ============================================================================

def create_reasoner() -> PhishingOntologyReasoner:
    """
    Factory function to create ontology reasoner instance.

    Provides graceful fallback if ontology loading fails.

    Returns:
        Initialized reasoner or None if loading fails
    """
    try:
        reasoner = PhishingOntologyReasoner()
        logger.info(f"Ontology reasoner initialized: {reasoner.get_ontology_stats()}")
        return reasoner
    except Exception as e:
        logger.error(f"Failed to initialize ontology reasoner: {e}")
        logger.warning("System will fall back to Phase 1-only detection")
        return None


def indicators_to_ontology_format(phase1_indicators: Dict) -> Dict[str, bool]:
    """
    Convert Phase 1 indicators dict to ontology-compatible format.

    Args:
        phase1_indicators: Raw indicators from deterministic.py

    Returns:
        Boolean dictionary suitable for ontology reasoning
    """
    # Extract boolean indicators
    bool_indicators = {}

    # Direct boolean mappings
    for key in ["urgency", "creds_request", "freemail_brand_claim", "freemail_sender"]:
        if key in phase1_indicators:
            bool_indicators[key] = bool(phase1_indicators[key])

    # DNS/auth indicators
    if "auth" in phase1_indicators:
        auth = phase1_indicators["auth"]
        bool_indicators["missing_mx"] = auth.get("has_mx", True) is False
        bool_indicators["no_spf"] = auth.get("spf_present", True) is False
        bool_indicators["no_dmarc"] = auth.get("dmarc_present", True) is False

    # URL indicators
    if "ip_literal_link" in phase1_indicators:
        bool_indicators["ip_literal_link"] = True

    if "shortened_url" in phase1_indicators:
        bool_indicators["shortened_url"] = True

    # Domain mismatch (infer from lookalike or domain_mismatch)
    if phase1_indicators.get("lookalike") or phase1_indicators.get("domain_mismatch"):
        bool_indicators["domain_mismatch"] = True

    return bool_indicators

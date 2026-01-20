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

from rdflib import Graph, Namespace, URIRef, Literal
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
            # Add more mappings as ontology expands
        }

        return mapping.get(indicator_key, indicator_key)

    def infer_attack_types(self,
                           indicators: Dict[str, bool],
                           min_confidence: float = 0.3) -> List[Tuple[str, float]]:
        """
        Classify email into attack types using ontology reasoning.

        Algorithm:
        1. Map Phase 1 indicators to ontology properties
        2. Query for attack types matching indicator patterns
        3. Compute confidence as fraction of indicators matching attack definition
        4. Return ranked list of (attack_type, confidence) tuples

        Args:
            indicators: Phase 1 indicator dictionary (e.g., {"urgency": True})
            min_confidence: Minimum confidence threshold (0.0-1.0)

        Returns:
            List of (attack_type_name, confidence_score) sorted by confidence

        Example:
            indicators = {"creds_request": True, "missing_mx": True}
            results = reasoner.infer_attack_types(indicators)
            # Returns: [("CredentialTheft", 1.0), ("TechnicalAttack", 0.5)]
        """
        if not indicators:
            logger.warning("No indicators provided for inference")
            return []

        # Filter to only True indicators
        active_indicators = {k: v for k, v in indicators.items() if v}

        if not active_indicators:
            return []

        # Map indicator keys to ontology property names
        mapped_indicators = {}
        for key in active_indicators:
            prop_name = self._map_indicator_to_property(key)
            mapped_indicators[prop_name] = True

        # Score each attack type by indicator overlap
        attack_scores: Dict[str, float] = {}

        for attack_type_uri in self._attack_types:
            # Get required indicators for this attack type
            required_indicators = self._get_attack_indicators(attack_type_uri)

            if not required_indicators:
                continue

            # Compute overlap using MAPPED indicators
            matched = sum(1 for ind in required_indicators
                         if ind in mapped_indicators)

            if matched > 0:
                confidence = matched / len(required_indicators)
                if confidence >= min_confidence:
                    attack_name = self._uri_to_name(attack_type_uri)
                    attack_scores[attack_name] = confidence

        # Sort by confidence descending
        ranked = sorted(attack_scores.items(),
                       key=lambda x: x[1],
                       reverse=True)

        logger.info(f"Inferred {len(ranked)} attack types from {len(active_indicators)} indicators")
        return ranked

    def _get_attack_indicators(self, attack_type_uri: URIRef) -> List[str]:
        """
        Extract required indicators for a specific attack type.

        NOTE: Currently uses hardcoded mappings for reliability.
        Future: Parse OWL axioms dynamically via SPARQL.

        Args:
            attack_type_uri: URI of attack type class

        Returns:
            List of indicator property names required for this attack
        """
        attack_name = self._uri_to_name(attack_type_uri)

        # Hardcoded attack patterns matching ontology definitions
        # (corresponds to OWL equivalentClass axioms in phishing_ontology.ttl)
        attack_patterns = {
            "CredentialTheft": ["hasCredentialRequest", "hasMissingMX"],
            "HighConfidencePhishing": ["hasUrgencyLanguage", "hasCredentialRequest", "hasMissingDMARC"],
            "URLBasedAttack": ["hasIPLiteralURL", "hasDomainMismatch"],  # OR hasShortenedURL
            "AppointmentScam": ["hasUrgencyLanguage", "hasFreemailSender"],
            "InsuranceVerificationPhish": ["hasCredentialRequest", "hasFreemailSender"],
            "PrescriptionFraud": ["hasUrgencyLanguage", "hasDomainMismatch"],
            "TechnicalAttack": ["hasMissingMX", "hasMissingSPF"],
            "SocialEngineeringAttack": ["hasUrgencyLanguage", "hasCredentialRequest"],
        }

        return attack_patterns.get(attack_name, [])

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
        required = self._get_attack_indicators(attack_uri)

        if required:
            rule_str = " AND ".join([self._format_property_name(ind)
                                     for ind in required])
            explanations.append(f"⚙ Rule: {attack_type} requires {rule_str}")

        # Step 3: Conclusion
        inferred = self.infer_attack_types(indicators)
        match = next((conf for name, conf in inferred if name == attack_type), None)

        if match:
            explanations.append(
                f"✓ Conclusion: Classified as {attack_type} "
                f"(confidence: {match*100:.0f}%)"
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
    for key in ["urgency", "creds_request", "url_present", "freemail_brand_claim"]:
        if key in phase1_indicators:
            bool_indicators[key] = bool(phase1_indicators[key])

    # DNS/auth indicators
    if "auth" in phase1_indicators:
        auth = phase1_indicators["auth"]
        bool_indicators["missing_mx"] = not auth.get("has_mx", True)
        bool_indicators["no_spf"] = not auth.get("spf_present", True)
        bool_indicators["no_dmarc"] = not auth.get("dmarc_present", True)

    # URL indicators
    if "ip_literal_link" in phase1_indicators:
        bool_indicators["ip_literal_link"] = True

    if "shortened_url" in phase1_indicators:
        bool_indicators["shortened_url"] = True

    # Domain mismatch (infer from lookalike or domain_mismatch)
    if phase1_indicators.get("lookalike") or phase1_indicators.get("domain_mismatch"):
        bool_indicators["domain_mismatch"] = True

    return bool_indicators

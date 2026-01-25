"""
Extended healthcare phishing templates for improved diversity.

Expanded from 3 to 10+ templates per category to achieve >80% subject uniqueness.
Organized by category and attack style (aggressive/neutral/stealth).
"""

HEALTHCARE_ATTACK_TEMPLATES = {
    "appointment_scam": [
        # Aggressive (urgency + explicit threats)
        "Urgent: Your appointment at Johns Hopkins has been rescheduled. Confirm at secure-jhm-portal.com within 24 hours.",
        "IMPORTANT: We need to verify your upcoming surgery date. Click here: verify-medstar.net.",
        "FINAL NOTICE: Your scheduled procedure will be cancelled unless you respond immediately.",

        # Neutral (professional tone, subtle urgency)
        "Your COVID-19 test results are ready. View at covidresults-check.com.",
        "Appointment reminder: Please confirm your visit scheduled for next week.",
        "We have updated your appointment time. Review changes at patient-scheduling.net.",

        # Stealth (low urgency, legitimate appearance)
        "Your annual checkup is approaching. View details at wellness-portal.com.",
        "Thank you for scheduling with us. Access appointment details here.",
        "Routine appointment confirmation for Dr. Smith on May 15th.",
        "Your telemedicine consultation link is ready for tomorrow's visit.",
        "Pre-visit paperwork available for your upcoming appointment.",
    ],

    "insurance_verification": [
        # Aggressive
        "Action Required: Your health insurance coverage expires soon. Update payment info at secure-bluecross-portal.com.",
        "Medicare Notification: Verify your Part D enrollment at medicare-benefits-check.org.",
        "URGENT: Insurance claim denial - appeal within 48 hours or lose coverage.",

        # Neutral
        "Important: Your insurance claim #54782 requires additional information. Upload documents here.",
        "Annual benefits review: Confirm your coverage elections for 2026.",
        "Your insurance card has been updated. Download new card at member-services.net.",

        # Stealth
        "Open enrollment period begins next month. Review your options early.",
        "Your explanation of benefits (EOB) statement is available online.",
        "Wellness program credits available - check eligibility at member-rewards.com.",
        "Pharmacy benefit update: New formulary effective next quarter.",
        "Preventive care reminder: Annual physical covered at 100% with in-network providers.",
    ],

    "prescription_fraud": [
        # Aggressive
        "CVS Pharmacy: Your prescription is ready for pickup but payment failed. Update card at cvs-rx-secure.com.",
        "Walgreens Alert: Refill authorization needed for your medication. Respond at walgreens-verify.net.",
        "URGENT: Prescription delay due to insurance issue. Resolve now to avoid interruption.",

        # Neutral
        "Your prescription delivery requires signature confirmation: pharma-delivery-confirm.com.",
        "Refill reminder: You have 2 prescriptions ready for renewal.",
        "Your medication is ready for pickup at our Main Street location.",

        # Stealth
        "Pharmacy savings program: You may qualify for discounts on current medications.",
        "Your prescription will be ready tomorrow. We'll send a text when available.",
        "Auto-refill enrollment available for your maintenance medications.",
        "Medication therapy management: Schedule a consultation with our pharmacist.",
        "Generic alternative available for lower copay. Ask your pharmacist for details.",
    ],

    "ehr_credential_theft": [
        # Aggressive
        "Epic MyChart: Your account access will be suspended. Verify credentials at mychart-login-verify.com.",
        "Security Alert: Unusual activity detected on your patient portal. Secure your account now.",
        "CRITICAL: Your electronic health records require password reset due to security upgrade.",

        # Neutral
        "Your patient portal password will expire in 7 days. Update at portal-security.net.",
        "New feature available: Schedule appointments directly through your portal.",
        "System maintenance scheduled: Patient portal will be offline Saturday 2-4am.",

        # Stealth
        "Your lab results from recent visit are now available in your portal.",
        "Message from Dr. Johnson regarding your recent inquiry.",
        "Billing statement ready: View charges and payment options online.",
        "Prescription refill request processed - view status in your account.",
        "Care team update: New provider added to your treatment plan.",
    ],
}

SENDER_DOMAINS = {
    "appointment_scam": [
        "noreply@johnshopkins-health.com",
        "appointments@medstar-system.net",
        "scheduler@mayoclinic-portal.com",
        "reminders@clevelandclinic-visits.com",
        "notifications@mgh-appointments.org",
        "scheduling@duke-health-system.net",
        "calendar@stanford-medical.com",
        "visits@ucsf-patient-portal.net",
        "appointments@northwell-scheduling.org",
        "bookings@healthcare-systems.com",
    ],
    "insurance_verification": [
        "benefits@bluecross-verify.com",
        "notifications@medicare-benefits.org",
        "claims@uhc-insurance.net",
        "alerts@aetna-members.com",
        "updates@cigna-healthcare.org",
        "service@humana-benefits.net",
        "enrollment@anthem-verify.com",
        "support@kaiser-members.org",
        "notifications@bcbs-online.net",
        "alerts@insurance-portal.com",
    ],
    "prescription_fraud": [
        "pharmacy@cvs-rx.com",
        "refills@walgreens-pharmacy.net",
        "orders@rxdelivery-secure.com",
        "notifications@riteaid-prescriptions.org",
        "alerts@cvs-pharmacy-services.net",
        "refills@walgreens-rx-center.com",
        "service@express-scripts-mail.org",
        "delivery@pharmacy-online.net",
        "notifications@medication-center.com",
        "alerts@rx-benefits.org",
    ],
    "ehr_credential_theft": [
        "security@mychart-login.com",
        "support@epic-systems.net",
        "alerts@patient-portal-secure.com",
        "notifications@cerner-health-access.org",
        "security@athenahealth-portal.net",
        "support@healthrecords-online.com",
        "alerts@ehr-access-verify.com",
        "service@patient-gateway.org",
        "security@medical-records-portal.net",
        "notifications@health-portal-secure.com",
    ],
}

# Prompt style definitions
PROMPT_STYLES = {
    "aggressive": {
        "urgency_instruction": "Include strong urgency tactics (e.g., 'URGENT', 'within 24 hours', 'FINAL NOTICE')",
        "tone": "Alarming and time-pressured",
        "url_instruction": "Include a suspicious URL with typosquatted domain or urgent subdomain",
    },
    "neutral": {
        "urgency_instruction": "Use moderate urgency (e.g., 'please confirm', 'action required', 'expires soon')",
        "tone": "Professional and business-like",
        "url_instruction": "Include a URL that looks semi-legitimate but has subtle red flags",
    },
    "stealth": {
        "urgency_instruction": "Avoid urgency keywords. Use polite, routine language (e.g., 'available', 'ready', 'reminder')",
        "tone": "Calm, helpful, and conversational",
        "url_instruction": "Include a URL that mimics legitimate healthcare portals with only minor domain inconsistencies",
    },
}

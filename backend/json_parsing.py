import json

# Load MITRE ATT&CK Enterprise file

<<<<<<< HEAD
with open("../../../Downloads/enterprise-attack.json", "r", encoding="utf-8") as f:
=======
with open("enterprise-attack.json", "r", encoding="utf-8") as f:
>>>>>>> 38dad24 (added parsing for rag implementation)
    d = json.load(f)

# Anoseek mapping
# Anoseek label -> severity -> MITRE IDs -> Anoseek indicators/responses

anoseek_mapping = {
    "Benign": {
        "severity": 0,
        "severity_text": "Benign",
        "mitre_ids": [],
        "indicators": [
            "Traffic appears consistent with normal baseline behavior",
            "No strong attack-like pattern was detected",
            "Flow characteristics do not strongly match known malicious behavior"
        ],
        "responses": [
            "no_action",
            "continue_monitoring"
        ]
    },

    # Recon / suspicious activity
    "Infilteration": {
        "severity": 1,
        "severity_text": "Low",
        "mitre_ids": ["T1046", "T1071"],
        "indicators": [
            "Unusual communication pattern compared to the expected baseline",
            "Possible suspicious access, probing, or internal discovery-like behavior",
            "Unexpected protocol, duration, or byte-ratio behavior",
            "Requires additional context before confirming malicious activity"
        ],
        "responses": [
            "monitor_host",
            "increase_logging",
            "raise_suspicious_alert"
        ]
    },

    "Bot": {
        "severity": 1,
        "severity_text": "Low",
        "mitre_ids": ["T1071", "T1105"],
        "indicators": [
            "Repeated or periodic communication pattern",
            "Possible beacon-like traffic",
            "Unusual destination or protocol behavior",
            "Consistent timing, packet size, or directionality may suggest automated communication"
        ],
        "responses": [
            "monitor_host",
            "check_reputation",
            "increase_logging",
            "raise_suspicious_alert"
        ]
    },

    # Brute force attacks
    "SSH-Bruteforce": {
        "severity": 2,
        "severity_text": "Medium",
        "mitre_ids": ["T1110", "T1110.001"],
        "indicators": [
            "Repeated SSH connection attempts",
            "Many short sessions from the same source",
            "High number of attempts toward the same destination",
            "Low byte count per attempt may indicate failed login attempts",
            "Authentication failure logs can strengthen confidence if available"
        ],
        "responses": [
            "rate_limit_source",
            "temporary_block_ip",
            "raise_auth_alert"
        ]
    },

    "FTP-BruteForce": {
        "severity": 2,
        "severity_text": "Medium",
        "mitre_ids": ["T1110", "T1110.001"],
        "indicators": [
            "Repeated FTP connection attempts",
            "Many short sessions from the same source",
            "High attempt count toward the same destination",
            "Low or repetitive byte patterns may suggest failed login attempts",
            "FTP authentication logs can strengthen confidence if available"
        ],
        "responses": [
            "rate_limit_source",
            "temporary_block_ip",
            "raise_auth_alert"
        ]
    },

    "Brute Force -Web": {
        "severity": 2,
        "severity_text": "Medium",
        "mitre_ids": ["T1110", "T1110.001", "T1110.003"],
        "indicators": [
            "Repeated requests to a web login endpoint",
            "Many similar HTTP requests from the same source",
            "High request count with small response variation",
            "Possible repeated failed authentication responses if web or application logs are available"
        ],
        "responses": [
            "rate_limit_source",
            "waf_rule",
            "raise_auth_alert"
        ]
    },

    # DoS / DDoS attacks
    "DoS attacks-Slowloris": {
        "severity": 3,
        "severity_text": "High",
        "mitre_ids": ["T1499", "T1499.002", "T1499.003"],
        "indicators": [
            "Many long-lived connections",
            "Low traffic volume per connection",
            "Slow or incomplete HTTP requests",
            "High number of concurrent connections to the same service",
            "Server resources may become exhausted over time"
        ],
        "responses": [
            "connection_timeout_tuning",
            "rate_limit_source",
            "temporary_block_ip",
            "raise_availability_alert"
        ]
    },

    "DoS attacks-Hulk": {
        "severity": 3,
        "severity_text": "High",
        "mitre_ids": ["T1499", "T1499.002", "T1499.003"],
        "indicators": [
            "High request volume toward a web service",
            "Many HTTP-like flows in a short period",
            "Large number of requests from one or more sources",
            "Traffic may cause increased server load or degraded availability",
            "Request behavior may look automated or repetitive"
        ],
        "responses": [
            "rate_limit_source",
            "waf_rule",
            "temporary_block_ip",
            "raise_availability_alert"
        ]
    },

    "DoS attacks-GoldenEye": {
        "severity": 3,
        "severity_text": "High",
        "mitre_ids": ["T1499", "T1499.002", "T1499.003"],
        "indicators": [
            "High number of web requests",
            "Repeated requests toward the same service",
            "Possible abnormal HTTP headers or request behavior if application logs are available",
            "Traffic may cause service degradation",
            "Request behavior may indicate application-layer exhaustion"
        ],
        "responses": [
            "rate_limit_source",
            "waf_rule",
            "temporary_block_ip",
            "raise_availability_alert"
        ]
    },

    "DoS attacks-SlowHTTPTest": {
        "severity": 3,
        "severity_text": "High",
        "mitre_ids": ["T1499", "T1499.002", "T1499.003"],
        "indicators": [
            "Slow HTTP request behavior",
            "Long connection duration",
            "Low throughput per connection",
            "Many incomplete or delayed web requests",
            "High number of concurrent slow sessions"
        ],
        "responses": [
            "connection_timeout_tuning",
            "rate_limit_source",
            "temporary_block_ip",
            "raise_availability_alert"
        ]
    },

    "DDoS attacks-LOIC-HTTP": {
        "severity": 3,
        "severity_text": "High",
        "mitre_ids": ["T1498", "T1498.001", "T1499", "T1499.002", "T1499.003"],
        "indicators": [
            "High HTTP request volume",
            "Many flows toward the same destination service",
            "Possible multiple sources if distributed",
            "Request patterns may be repetitive or automated",
            "Traffic volume may affect service availability"
        ],
        "responses": [
            "rate_limit_source",
            "upstream_ddos_filtering",
            "temporary_block_ip",
            "raise_availability_alert"
        ]
    },

    "DDOS attack-HOIC": {
        "severity": 3,
        "severity_text": "High",
        "mitre_ids": ["T1498", "T1498.001", "T1499", "T1499.002", "T1499.003"],
        "indicators": [
            "High-volume HTTP-like traffic",
            "Many repeated requests toward the same service",
            "Possible distributed sources",
            "Automated request pattern may be visible",
            "Traffic may cause service degradation"
        ],
        "responses": [
            "rate_limit_source",
            "upstream_ddos_filtering",
            "temporary_block_ip",
            "raise_availability_alert"
        ]
    },

    "DDOS attack-LOIC-UDP": {
        "severity": 3,
        "severity_text": "High",
        "mitre_ids": ["T1498", "T1498.001"],
        "indicators": [
            "High UDP packet or flow volume",
            "Large number of packets toward the same destination",
            "Possible abnormal byte or packet rate",
            "Possible multiple sources if distributed",
            "Service or network availability may degrade"
        ],
        "responses": [
            "rate_limit_source",
            "upstream_ddos_filtering",
            "temporary_block_ip",
            "raise_availability_alert"
        ]
    },

    # High severity / exploitation attacks
    "SQL Injection": {
        "severity": 4,
        "severity_text": "Critical",
        "mitre_ids": ["T1190"],
        "indicators": [
            "Suspicious web request pattern",
            "Possible SQL-like payload in application logs",
            "Repeated requests to dynamic web endpoints",
            "Application logs may show database errors or abnormal query behavior",
            "Network flow alone may be insufficient to confirm SQL injection"
        ],
        "responses": [
            "waf_rule",
            "inspect_application_logs",
            "raise_critical_alert",
            "consider_service_isolation"
        ]
    },

    "Brute Force -XSS": {
        "severity": 4,
        "severity_text": "Critical",
        "mitre_ids": ["T1190"],
        "indicators": [
            "Repeated suspicious web requests",
            "Possible abnormal request parameters",
            "Application logs may show script-like or encoded payloads",
            "WAF logs can strengthen confidence",
            "Network flow alone may be insufficient to confirm XSS"
        ],
        "responses": [
            "waf_rule",
            "inspect_application_logs",
            "raise_critical_alert",
            "consider_service_isolation"
        ]
    }
}


# extract MITRE external ID from external_references

def get_mitre_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None

# build MITRE indexes

attack_patterns_by_mitre_id = {}
course_of_action_by_id = {}
mitigates_relationships = []

for obj in d["objects"]:

    # skip revoked/deprecated objects
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        continue

    if obj.get("type") == "attack-pattern":
        mitre_id = get_mitre_id(obj)

        if mitre_id:
            attack_patterns_by_mitre_id[mitre_id] = {
                "id": obj.get("id"),
                "mitre id": mitre_id,
                "name": obj.get("name"),
                "description": obj.get("description")
            }

    elif obj.get("type") == "course-of-action":
        course_of_action_by_id[obj.get("id")] = {
            "id": obj.get("id"),
            "name": obj.get("name"),
            "description": obj.get("description")
        }

    elif obj.get("type") == "relationship" and obj.get("relationship_type") == "mitigates":
        mitigates_relationships.append({
            "source_ref": obj.get("source_ref"),  # course-of-action
            "target_ref": obj.get("target_ref")   # attack-pattern
        })

<<<<<<< HEAD
<<<<<<< HEAD
=======

>>>>>>> 38dad24 (added parsing for rag implementation)
=======
>>>>>>> c3eb2bb (added rag logic + embeddings (currently supports hardcoded queries))
# ELEMENT FORMAT -->
# Anoseek wrapper:
#   anoseek label
#   anoseek severity
#   severity text
#
# MITRE attack pattern:
#   mitre id
#   attack name
#   attack description
#
# MITRE course of action:
#   mitigation
#   mitigation description
#
# Anoseek wrapper:
#   anoseek indicators
#   anoseek responses

final_rag_objects = []

for anoseek_label, anoseek_info in anoseek_mapping.items():

    # benign / labels without MITRE mapping
    if not anoseek_info["mitre_ids"]:
        new_obj = {
            "anoseek label": anoseek_label,
            "anoseek severity": anoseek_info["severity"],
            "severity text": anoseek_info["severity_text"],

            "mitre id": None,
            "attack name": None,
            "attack description": "No MITRE ATT&CK technique is mapped because this label represents benign or non-attack traffic.",

            "mitigation": None,
            "mitigation description": None,

            "anoseek indicators": anoseek_info["indicators"],
            "anoseek responses": anoseek_info["responses"]
        }

        final_rag_objects.append(new_obj)
        continue

    for mitre_id in anoseek_info["mitre_ids"]:

        attack = attack_patterns_by_mitre_id.get(mitre_id)

        if not attack:
            print(f"MITRE technique not found: {mitre_id}")
            continue

        attack_stix_id = attack["id"]
        found_mitigation = False

        for rel in mitigates_relationships:
            if rel["target_ref"] == attack_stix_id:

<<<<<<< HEAD
<<<<<<< HEAD
                # fetch the matching source of course-of-action
=======
>>>>>>> 38dad24 (added parsing for rag implementation)
=======
                # fetch the matching source of course-of-action
>>>>>>> c3eb2bb (added rag logic + embeddings (currently supports hardcoded queries))
                coa = course_of_action_by_id.get(rel["source_ref"])

                if not coa:
                    continue

                found_mitigation = True

                new_obj = {
                    "anoseek label": anoseek_label,
                    "anoseek severity": anoseek_info["severity"],
                    "severity text": anoseek_info["severity_text"],

                    "mitre id": attack["mitre id"],
                    "attack name": attack["name"],
                    "attack description": attack["description"],

                    "mitigation": coa["name"],
                    "mitigation description": coa["description"],

                    "anoseek indicators": anoseek_info["indicators"],
                    "anoseek responses": anoseek_info["responses"]
                }

                final_rag_objects.append(new_obj)

<<<<<<< HEAD
<<<<<<< HEAD
        # in cases of no MITRE technique, keeps hardcoded 
=======
        # Keep the technique even if MITRE has no direct mitigation relationship for it
>>>>>>> 38dad24 (added parsing for rag implementation)
=======
        # in cases of no MITRE technique, keeps hardcoded 
>>>>>>> c3eb2bb (added rag logic + embeddings (currently supports hardcoded queries))
        if not found_mitigation:
            new_obj = {
                "anoseek label": anoseek_label,
                "anoseek severity": anoseek_info["severity"],
                "severity text": anoseek_info["severity_text"],

                "mitre id": attack["mitre id"],
                "attack name": attack["name"],
                "attack description": attack["description"],

                "mitigation": None,
                "mitigation description": "No direct MITRE course-of-action mitigation relationship was found for this technique in enterprise-attack.json.",

                "anoseek indicators": anoseek_info["indicators"],
                "anoseek responses": anoseek_info["responses"]
            }

            final_rag_objects.append(new_obj)

<<<<<<< HEAD
<<<<<<< HEAD
# final anoseek-based RAG file
=======

# ============================================================
# Save final enriched RAG file
# ============================================================
>>>>>>> 38dad24 (added parsing for rag implementation)
=======
# final anoseek-based RAG file
>>>>>>> c3eb2bb (added rag logic + embeddings (currently supports hardcoded queries))

with open("anoseek_rag_mitre_enriched.json", "w", encoding="utf-8") as f:
    json.dump(final_rag_objects, f, indent=2, ensure_ascii=False)

print(f"Created {len(final_rag_objects)} enriched Anoseek RAG objects")
<<<<<<< HEAD
<<<<<<< HEAD
=======
print("Output file: anoseek_rag_mitre_enriched.json")
>>>>>>> 38dad24 (added parsing for rag implementation)
=======
>>>>>>> c3eb2bb (added rag logic + embeddings (currently supports hardcoded queries))

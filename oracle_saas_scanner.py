#!/usr/bin/env python3
"""
Oracle SaaS Cloud SSPM Scanner v1.0.0
SaaS Security Posture Management for Oracle Fusion Cloud, EPM Cloud
& Oracle IDCS / OCI IAM Identity Domains.

Performs live REST API checks across:
  - Oracle IDCS / OCI IAM Identity Domains — password policy, MFA,
    SSO/SAML, sign-on policies, OAuth clients, privileged groups,
    user lifecycle, network perimeters, session settings, audit
  - Oracle Fusion Cloud — configuration management, custom roles,
    data security policies, scheduled processes, audit policies,
    SoD monitoring, security console, implementation projects
  - Oracle EPM Cloud — audit data export, maintenance configuration

Compliance Framework Mapping (per finding):
  CIS Oracle Cloud Infrastructure SaaS Cloud Applications Benchmark v1.0.0
  NIST SP 800-53 Rev 5
  ISO/IEC 27001:2022
  SOC 2 Type II Trust Services Criteria

Authentication (primary): OAuth 2.0 Client Credentials via IDCS
  1. Register a Confidential Application in IDCS / Identity Domain
  2. Grant required admin scopes (see below)
  3. Pass --idcs-url, --client-id, --client-secret

Authentication (fallback): HTTP Basic Auth
  Pass --idcs-url, --username, --password

Required IDCS Application Scopes (read-only):
  urn:opc:idm:t.security.client        -- OAuth client audit
  urn:opc:idm:t.user.me                -- validate auth
  urn:opc:idm:t.groups                  -- groups / privileged roles
  urn:opc:idm:t.users                   -- user lifecycle audit
  urn:opc:idm:t.app.catalog             -- app / IdP enumeration

Required Fusion Cloud Role (read-only):
  IT Security Manager (ORA_FND_IT_SECURITY_MANAGER_JOB)

Usage:
  python oracle_saas_scanner.py \\
      --idcs-url   https://idcs-abc123.identity.oraclecloud.com \\
      --client-id  <client-id> \\
      --client-secret <secret>

  python oracle_saas_scanner.py \\
      --idcs-url   https://idcs-abc123.identity.oraclecloud.com \\
      --fusion-url https://myco.fa.us2.oraclecloud.com \\
      --client-id  <client-id> \\
      --client-secret <secret>

Env var fallback:
  ORACLE_IDCS_URL  ORACLE_FUSION_URL  ORACLE_CLIENT_ID
  ORACLE_CLIENT_SECRET  ORACLE_USERNAME  ORACLE_PASSWORD
"""

import os
import re
import sys
import json
import time
import html as html_mod
import argparse
import ipaddress
from datetime import datetime, timezone, timedelta

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

VERSION = "1.0.0"

# ============================================================
# Oracle IDCS / Fusion REST API constants
# ============================================================
IDCS_ADMIN_V1 = "/admin/v1"
IDCS_TOKEN_EP = "/oauth2/v1/token"
IDCS_SCOPE    = "urn:opc:idm:__myscopes__"

FUSION_FSCM   = "/fscmRestApi/resources/latest"
FUSION_HCM    = "/hcmRestApi/resources/latest"
EPM_BASE      = "/interop/rest/v3"

# Privileged IDCS / Identity Domain groups
PRIVILEGED_IDCS_GROUPS = {
    "Identity Domain Administrators",
    "Security Administrators",
    "Application Administrators",
    "Audit Administrators",
    "Cloud Account Administrators",
    "User Administrators",
}

# Privileged Fusion Cloud job roles
PRIVILEGED_FUSION_ROLES = {
    "ORA_FND_IT_SECURITY_MANAGER_JOB": "IT Security Manager",
    "ORA_ASM_APPLICATION_IMPLEMENTATION_CONSULTANT_JOB": "Application Implementation Consultant",
    "ORA_FND_APPLICATION_ADMINISTRATOR_JOB": "Application Administrator",
    "ORA_FND_SYSTEM_ADMINISTRATOR_JOB": "System Administrator",
    "ORA_PER_HUMAN_RESOURCE_SPECIALIST_JOB": "Human Resource Specialist",
    "ORA_FND_INTEGRATION_SPECIALIST_JOB": "Integration Specialist",
}

# High-risk IDCS OAuth scopes that indicate excessive privilege
HIGH_RISK_SCOPES = {
    "urn:opc:idm:t.user.admin",
    "urn:opc:idm:t.group.admin",
    "urn:opc:idm:t.app.admin",
    "urn:opc:idm:t.security.admin",
    "urn:opc:idm:t.audit.admin",
    "urn:opc:idm:t.mfa.admin",
    "urn:opc:idm:__myscopes__",
    "urn:opc:idm:t.idp.admin",
    "urn:opc:idm:t.schema.admin",
    "urn:opc:idm:t.policy.admin",
    "urn:opc:idm:t.domain.admin",
}

# ============================================================
# Compliance Framework Mapping
# Maps rule_id -> { framework: control_id }
# CIS Oracle SaaS v1.0.0, NIST 800-53 Rev5, ISO 27001:2022, SOC 2
# ============================================================
COMPLIANCE_MAP: dict = {
    # ── Section 1: Identity and Access Management ──
    "OSAAS-IAM-001": {"cis_oracle_saas": "1.1.1", "nist_800_53": "IA-5(1)",          "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "OSAAS-IAM-002": {"cis_oracle_saas": "1.1.1", "nist_800_53": "IA-5(1)",          "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "OSAAS-IAM-003": {"cis_oracle_saas": "1.1.1", "nist_800_53": "IA-5(1)",          "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "OSAAS-IAM-004": {"cis_oracle_saas": "1.1.1", "nist_800_53": "IA-5(1)",          "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "OSAAS-IAM-005": {"cis_oracle_saas": "1.1.1", "nist_800_53": "IA-5(1)",          "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "OSAAS-IAM-006": {"cis_oracle_saas": "1.1.2", "nist_800_53": "IA-5(1)",          "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "OSAAS-IAM-007": {"cis_oracle_saas": "1.1.2", "nist_800_53": "IA-5(1)",          "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "OSAAS-IAM-008": {"cis_oracle_saas": "1.1.3", "nist_800_53": "AC-7",             "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "OSAAS-IAM-009": {"cis_oracle_saas": "1.1.3", "nist_800_53": "AC-7",             "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "OSAAS-IAM-010": {"cis_oracle_saas": "1.2.1", "nist_800_53": "IA-2(1), IA-2(2)", "iso_27001": "A.8.5",  "soc2": "CC6.1, CC6.2"},
    "OSAAS-IAM-011": {"cis_oracle_saas": "1.2.2", "nist_800_53": "IA-2(1), AC-6",    "iso_27001": "A.8.5",  "soc2": "CC6.1, CC6.2"},
    "OSAAS-IAM-012": {"cis_oracle_saas": "1.2.3", "nist_800_53": "IA-2(12)",         "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "OSAAS-IAM-013": {"cis_oracle_saas": "1.3.1", "nist_800_53": "IA-2, IA-8",       "iso_27001": "A.8.5",  "soc2": "CC6.1, CC6.2"},
    "OSAAS-IAM-014": {"cis_oracle_saas": "1.3.2", "nist_800_53": "AC-6, CM-7",       "iso_27001": "A.8.9",  "soc2": "CC6.1, CC6.3"},
    "OSAAS-IAM-015": {"cis_oracle_saas": "1.3.2", "nist_800_53": "CM-8",             "iso_27001": "A.8.9",  "soc2": "CC6.1"},
    "OSAAS-IAM-016": {"cis_oracle_saas": "1.4.1", "nist_800_53": "AC-6(5)",          "iso_27001": "A.8.2",  "soc2": "CC6.1, CC6.3"},
    "OSAAS-IAM-017": {"cis_oracle_saas": "1.4.2", "nist_800_53": "AC-6(5)",          "iso_27001": "A.8.2",  "soc2": "CC6.1, CC6.3"},
    "OSAAS-IAM-018": {"cis_oracle_saas": "1.5.1", "nist_800_53": "AC-2(3)",          "iso_27001": "A.5.18", "soc2": "CC6.1, CC6.2"},
    "OSAAS-IAM-019": {"cis_oracle_saas": "1.5.2", "nist_800_53": "AC-2(3), AC-2(4)", "iso_27001": "A.5.18", "soc2": "CC6.1, CC6.2"},
    "OSAAS-IAM-020": {"cis_oracle_saas": "1.6.1", "nist_800_53": "AC-2(5), SC-7",    "iso_27001": "A.8.3",  "soc2": "CC6.1"},
    "OSAAS-IAM-021": {"cis_oracle_saas": "1.6.2", "nist_800_53": "AC-2",             "iso_27001": "A.5.16", "soc2": "CC6.1"},
    "OSAAS-IAM-022": {"cis_oracle_saas": "1.2.4", "nist_800_53": "IA-2(1)",          "iso_27001": "A.8.5",  "soc2": "CC6.1, CC6.2"},
    # ── Section 2: Configuration Management ──
    "OSAAS-CFG-001": {"cis_oracle_saas": "2.1.1", "nist_800_53": "CM-3, SI-4",       "iso_27001": "A.8.9",  "soc2": "CC8.1"},
    "OSAAS-CFG-002": {"cis_oracle_saas": "2.1.2", "nist_800_53": "AC-6, CM-8",       "iso_27001": "A.8.2",  "soc2": "CC6.1"},
    "OSAAS-CFG-003": {"cis_oracle_saas": "2.1.3", "nist_800_53": "AC-6(5)",          "iso_27001": "A.8.2",  "soc2": "CC6.1, CC6.3"},
    "OSAAS-CFG-004": {"cis_oracle_saas": "2.2.1", "nist_800_53": "CM-3(2)",          "iso_27001": "A.8.32", "soc2": "CC8.1"},
    "OSAAS-CFG-005": {"cis_oracle_saas": "2.2.2", "nist_800_53": "CM-3(2)",          "iso_27001": "A.8.32", "soc2": "CC8.1"},
    "OSAAS-CFG-006": {"cis_oracle_saas": "2.3.1", "nist_800_53": "AC-3",             "iso_27001": "A.8.3",  "soc2": "CC6.1"},
    "OSAAS-CFG-007": {"cis_oracle_saas": "2.3.2", "nist_800_53": "AC-3, AC-6",       "iso_27001": "A.8.3",  "soc2": "CC6.1, CC6.3"},
    "OSAAS-CFG-008": {"cis_oracle_saas": "2.3.3", "nist_800_53": "AC-6(5)",          "iso_27001": "A.8.2",  "soc2": "CC6.1, CC6.3"},
    "OSAAS-CFG-009": {"cis_oracle_saas": "2.4.1", "nist_800_53": "CM-3, CM-6",       "iso_27001": "A.8.9",  "soc2": "CC8.1"},
    "OSAAS-CFG-010": {"cis_oracle_saas": "2.4.2", "nist_800_53": "CM-3",             "iso_27001": "A.8.9",  "soc2": "CC8.1"},
    "OSAAS-CFG-011": {"cis_oracle_saas": "2.5.1", "nist_800_53": "AC-6(5), CM-7",    "iso_27001": "A.8.2",  "soc2": "CC6.1, CC6.3"},
    "OSAAS-CFG-012": {"cis_oracle_saas": "2.5.2", "nist_800_53": "AC-6(5)",          "iso_27001": "A.8.2",  "soc2": "CC6.1, CC6.3"},
    "OSAAS-CFG-013": {"cis_oracle_saas": "2.5.3", "nist_800_53": "CM-3, CM-6",       "iso_27001": "A.8.9",  "soc2": "CC8.1"},
    # ── Section 3: Networking ──
    "OSAAS-NET-001": {"cis_oracle_saas": "3.1.1", "nist_800_53": "AC-2(5), SC-7",    "iso_27001": "A.8.3",  "soc2": "CC6.1, CC6.6"},
    "OSAAS-NET-002": {"cis_oracle_saas": "3.1.2", "nist_800_53": "SC-7",             "iso_27001": "A.8.3",  "soc2": "CC6.6"},
    "OSAAS-NET-003": {"cis_oracle_saas": "3.1.3", "nist_800_53": "AC-2(5), SC-7",    "iso_27001": "A.8.3",  "soc2": "CC6.1"},
    "OSAAS-NET-004": {"cis_oracle_saas": "3.2.1", "nist_800_53": "SC-7, SI-3",       "iso_27001": "A.8.7",  "soc2": "CC6.6, CC6.8"},
    "OSAAS-NET-005": {"cis_oracle_saas": "3.2.2", "nist_800_53": "SC-7",             "iso_27001": "A.8.12", "soc2": "CC6.6"},
    "OSAAS-NET-006": {"cis_oracle_saas": "3.3.1", "nist_800_53": "SC-7, AC-3",       "iso_27001": "A.8.3",  "soc2": "CC6.1, CC6.6"},
    "OSAAS-NET-007": {"cis_oracle_saas": "3.3.2", "nist_800_53": "SC-7",             "iso_27001": "A.8.3",  "soc2": "CC6.6"},
    "OSAAS-NET-008": {"cis_oracle_saas": "3.4.1", "nist_800_53": "AC-12, SC-23",     "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "OSAAS-NET-009": {"cis_oracle_saas": "3.4.2", "nist_800_53": "AC-12",            "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "OSAAS-NET-010": {"cis_oracle_saas": "3.1.4", "nist_800_53": "SC-7",             "iso_27001": "A.8.3",  "soc2": "CC6.6"},
    # ── Section 4: Logging and Monitoring ──
    "OSAAS-LOG-001": {"cis_oracle_saas": "4.1.1", "nist_800_53": "AU-2, AU-3",       "iso_27001": "A.8.15", "soc2": "CC7.1, CC7.2"},
    "OSAAS-LOG-002": {"cis_oracle_saas": "4.1.2", "nist_800_53": "AU-2, AU-3",       "iso_27001": "A.8.15", "soc2": "CC7.1, CC7.2"},
    "OSAAS-LOG-003": {"cis_oracle_saas": "4.1.3", "nist_800_53": "AU-2, AU-12",      "iso_27001": "A.8.15", "soc2": "CC7.1, CC7.2"},
    "OSAAS-LOG-004": {"cis_oracle_saas": "4.2.1", "nist_800_53": "AC-5, AU-6",       "iso_27001": "A.5.3",  "soc2": "CC6.1, CC6.3"},
    "OSAAS-LOG-005": {"cis_oracle_saas": "4.2.2", "nist_800_53": "AU-11, AU-4",      "iso_27001": "A.8.15", "soc2": "CC7.1, A1.2"},
    "OSAAS-LOG-006": {"cis_oracle_saas": "4.3.1", "nist_800_53": "SI-4, IR-6",       "iso_27001": "A.5.24", "soc2": "CC7.2, CC7.3"},
    "OSAAS-LOG-007": {"cis_oracle_saas": "4.3.2", "nist_800_53": "SI-4, AC-7",       "iso_27001": "A.8.16", "soc2": "CC7.2"},
    "OSAAS-LOG-008": {"cis_oracle_saas": "4.3.3", "nist_800_53": "AU-2, AU-12",      "iso_27001": "A.8.15", "soc2": "CC7.1"},
    "OSAAS-LOG-009": {"cis_oracle_saas": "4.4.1", "nist_800_53": "AU-6(1), SI-4",    "iso_27001": "A.8.15", "soc2": "CC7.1, CC7.2"},
    "OSAAS-LOG-010": {"cis_oracle_saas": "4.4.2", "nist_800_53": "AU-12",            "iso_27001": "A.8.15", "soc2": "CC7.1"},
}


# ============================================================
# Finding data class  (identical schema to all other scanners)
# ============================================================
class Finding:
    __slots__ = (
        "rule_id", "name", "category", "severity",
        "file_path", "line_num", "line_content",
        "description", "recommendation", "cwe", "cve",
        "compliance",
    )

    def __init__(self, rule_id, name, category, severity,
                 file_path, line_num, line_content,
                 description, recommendation, cwe=None, cve=None):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.file_path = file_path       # repurposed: API endpoint / entity
        self.line_num = line_num         # always None for API checks
        self.line_content = line_content # repurposed: setting = current value
        self.description = description
        self.recommendation = recommendation
        self.cwe = cwe or ""
        self.cve = cve or ""
        self.compliance = COMPLIANCE_MAP.get(rule_id, {})

    def to_dict(self):
        d = {
            "id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "file": self.file_path,
            "line": self.line_num,
            "code": self.line_content,
            "description": self.description,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "cve": self.cve,
        }
        if self.compliance:
            d["compliance"] = self.compliance
        return d


# ============================================================
# Oracle SaaS SSPM Scanner
# ============================================================
class OracleSaaSScanner:

    SEVERITY_ORDER = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    SEVERITY_COLOR = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[94m",
        "LOW":      "\033[92m",
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    def __init__(self, idcs_url: str, fusion_url: str = "",
                 client_id: str = "", client_secret: str = "",
                 username: str = "", password: str = "",
                 verbose: bool = False):
        self.idcs_url     = idcs_url.rstrip("/")
        self.fusion_url   = fusion_url.rstrip("/") if fusion_url else ""
        self.client_id    = client_id
        self.client_secret = client_secret
        self.username     = username
        self.password     = password
        self.verbose      = verbose
        self.findings: list = []
        self._token: str  = ""
        self._token_expiry: datetime = datetime.now(timezone.utc)
        self._auth_mode: str = ""
        self._domain_name: str = ""

    # ----------------------------------------------------------
    # Entry point
    # ----------------------------------------------------------
    def scan(self):
        print(f"[*] Oracle SaaS Cloud SSPM Scanner v{VERSION}")
        print("[*] Authenticating \u2026")
        try:
            self._authenticate()
        except Exception as e:
            print(f"[!] Authentication failed: {e}", file=sys.stderr)
            sys.exit(1)
        print("[*] Running checks \u2026\n")

        # ── Section 1: Identity and Access Management ──
        self._check_password_policies()
        self._check_mfa_enforcement()
        self._check_sso_configuration()
        self._check_oauth_clients()
        self._check_privileged_roles_idcs()
        self._check_privileged_roles_fusion()
        self._check_user_lifecycle()
        self._check_admin_access_restrictions()

        # ── Section 2: Configuration Management ──
        if self.fusion_url:
            self._check_config_change_monitoring()
            self._check_custom_roles()
            self._check_data_security_policies()
            self._check_scheduled_processes()
            self._check_implementation_projects()
        else:
            print("  [skip] Fusion URL not provided \u2014 skipping Configuration Management checks")

        # ── Section 3: Networking ──
        self._check_network_perimeters()
        self._check_sign_on_policy_network()
        self._check_waf_configuration()
        self._check_session_settings()

        # ── Section 4: Logging and Monitoring ──
        self._check_audit_configuration()
        self._check_sod_monitoring()
        self._check_alerting_configuration()
        self._check_logging_integration()

    # ----------------------------------------------------------
    # Authentication
    # ----------------------------------------------------------
    def _authenticate(self):
        """OAuth 2.0 Client Credentials (primary) or Basic Auth (fallback)."""
        # --- OAuth 2.0 ---
        if self.client_id and self.client_secret:
            url = f"{self.idcs_url}{IDCS_TOKEN_EP}"
            resp = requests.post(url, data={
                "grant_type": "client_credentials",
                "scope": IDCS_SCOPE,
            }, auth=(self.client_id, self.client_secret), timeout=30)

            if resp.status_code == 200:
                body = resp.json()
                self._token = body["access_token"]
                expires_in = int(body.get("expires_in", 3600))
                self._token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)
                self._auth_mode = "oauth"
                me = self._idcs_get_single("Me")
                ext = me.get("urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User", {})
                self._domain_name = ext.get("domainName", self.idcs_url)
                print(f"[*] Identity Domain : {self._domain_name}")
                print(f"[*] Auth mode       : OAuth 2.0 Client Credentials")
                if self.fusion_url:
                    print(f"[*] Fusion Cloud    : {self.fusion_url}")
                return
            err_body = resp.json() if "json" in resp.headers.get("Content-Type", "") else {}
            err_msg = err_body.get("error_description") or resp.text[:300]
            if self.username and self.password:
                self._warn(f"OAuth failed ({err_msg}), falling back to Basic Auth")
            else:
                raise RuntimeError(f"OAuth 2.0 authentication failed: {err_msg}")

        # --- Basic Auth fallback ---
        if self.username and self.password:
            resp = requests.get(
                f"{self.idcs_url}{IDCS_ADMIN_V1}/Me",
                auth=(self.username, self.password),
                timeout=30,
            )
            if resp.status_code == 200:
                self._auth_mode = "basic"
                me = resp.json()
                ext = me.get("urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User", {})
                self._domain_name = ext.get("domainName", self.idcs_url)
                print(f"[*] Identity Domain : {self._domain_name}")
                print(f"[*] Auth mode       : Basic Authentication (fallback)")
                if self.fusion_url:
                    print(f"[*] Fusion Cloud    : {self.fusion_url}")
                return
            raise RuntimeError(f"Basic Auth failed: HTTP {resp.status_code}")

        raise RuntimeError(
            "No valid credentials provided. "
            "Supply --client-id/--client-secret or --username/--password"
        )

    def _ensure_token(self):
        """Re-authenticate if the OAuth token is about to expire."""
        if self._auth_mode != "oauth":
            return
        if datetime.now(timezone.utc) >= self._token_expiry:
            self._vprint("  [auth] Token expired, re-authenticating \u2026")
            self._authenticate()

    def _headers(self) -> dict:
        self._ensure_token()
        if self._auth_mode == "oauth":
            return {
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _basic_auth(self):
        """Return Basic Auth tuple for requests, or None."""
        if self._auth_mode == "basic":
            return (self.username, self.password)
        return None

    # ----------------------------------------------------------
    # IDCS REST API helpers (SCIM pagination)
    # ----------------------------------------------------------
    def _idcs_get(self, path: str, params: dict = None,
                  page_size: int = 100) -> list:
        """Paginated GET against IDCS /admin/v1/{path}. Returns list of Resources."""
        url = f"{self.idcs_url}{IDCS_ADMIN_V1}/{path.lstrip('/')}"
        results = []
        start_index = 1

        while True:
            p = {"startIndex": start_index, "count": page_size}
            if params:
                p.update(params)
            try:
                resp = requests.get(
                    url, headers=self._headers(),
                    auth=self._basic_auth(), params=p, timeout=30,
                )
            except requests.exceptions.ConnectionError as e:
                self._warn(f"Cannot reach IDCS: {e}")
                return []
            except requests.exceptions.Timeout:
                self._warn(f"Timeout fetching IDCS {path}")
                return []

            if resp.status_code == 401:
                self._warn("IDCS token expired or invalid.")
                return []
            if resp.status_code == 403:
                self._warn(
                    f"Permission denied for IDCS '{path}'. "
                    "Ensure required IDCS scopes are granted."
                )
                return []
            if resp.status_code == 404:
                self._vprint(f"  [skip] IDCS '{path}' not found (may not be available in this domain).")
                return []
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "5"))
                self._vprint(f"  [rate] Rate limited on '{path}', waiting {retry_after}s")
                time.sleep(retry_after)
                continue
            if resp.status_code != 200:
                self._warn(f"IDCS HTTP {resp.status_code} for '{path}': {resp.text[:200]}")
                return []

            try:
                body = resp.json()
            except ValueError:
                self._warn(f"Non-JSON response from IDCS '{path}'")
                return []

            resources = body.get("Resources", [])
            if isinstance(resources, list):
                results.extend(resources)

            total = int(body.get("totalResults", 0))
            if start_index + len(resources) > total or not resources:
                break
            start_index += len(resources)

        self._vprint(f"  [api] IDCS {path}: {len(results)} item(s)")
        return results

    def _idcs_get_single(self, path: str, params: dict = None) -> dict:
        """Return single resource from IDCS (no pagination)."""
        url = f"{self.idcs_url}{IDCS_ADMIN_V1}/{path.lstrip('/')}"
        try:
            resp = requests.get(
                url, headers=self._headers(),
                auth=self._basic_auth(), params=params, timeout=30,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return {}

        if resp.status_code != 200:
            if resp.status_code not in (403, 404):
                self._warn(f"IDCS HTTP {resp.status_code} for '{path}'")
            elif resp.status_code == 403:
                self._warn(f"Permission denied for IDCS '{path}'")
            else:
                self._vprint(f"  [skip] IDCS '{path}' not found")
            return {}
        try:
            return resp.json()
        except ValueError:
            return {}

    # ----------------------------------------------------------
    # Fusion REST API helpers (offset/limit pagination)
    # ----------------------------------------------------------
    def _fusion_get(self, path: str, params: dict = None,
                    limit: int = 500) -> list:
        """Paginated GET against Fusion REST API. Returns list of items."""
        if not self.fusion_url:
            return []
        url = f"{self.fusion_url}/{path.lstrip('/')}"
        results = []
        offset = 0

        while True:
            p = {"offset": offset, "limit": limit}
            if params:
                p.update(params)
            try:
                resp = requests.get(
                    url, headers=self._headers(),
                    auth=self._basic_auth(), params=p, timeout=30,
                )
            except requests.exceptions.ConnectionError as e:
                self._warn(f"Cannot reach Fusion: {e}")
                return []
            except requests.exceptions.Timeout:
                self._warn(f"Timeout fetching Fusion {path}")
                return []

            if resp.status_code == 401:
                self._warn("Fusion: token expired or not authorized.")
                return []
            if resp.status_code == 403:
                self._warn(
                    f"Permission denied for Fusion '{path}'. "
                    "Ensure IT Security Manager role is assigned."
                )
                return []
            if resp.status_code == 404:
                self._vprint(f"  [skip] Fusion '{path}' not found.")
                return []
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "5"))
                self._vprint(f"  [rate] Rate limited on Fusion '{path}', waiting {retry_after}s")
                time.sleep(retry_after)
                continue
            if resp.status_code != 200:
                self._warn(f"Fusion HTTP {resp.status_code} for '{path}': {resp.text[:200]}")
                return []

            try:
                body = resp.json()
            except ValueError:
                self._warn(f"Non-JSON response from Fusion '{path}'")
                return []

            items = body.get("items", [])
            if isinstance(items, list):
                results.extend(items)
            elif isinstance(body, list):
                results.extend(body)
                break

            if not body.get("hasMore", False) or not items:
                break
            offset += len(items)

        self._vprint(f"  [api] Fusion {path}: {len(results)} item(s)")
        return results

    def _fusion_get_single(self, path: str, params: dict = None) -> dict:
        """Return a single object from Fusion REST."""
        items = self._fusion_get(path, params=params, limit=1)
        return items[0] if items else {}

    # ==============================================================
    # Section 1: Identity and Access Management  (22 checks)
    # ==============================================================

    # ----------------------------------------------------------
    # 1.1 Password Policies  (OSAAS-IAM-001 .. 009)
    # ----------------------------------------------------------
    def _check_password_policies(self):
        self._vprint("  [check] Password policies \u2026")
        policies = self._idcs_get("PasswordPolicies")
        if not policies:
            self._add(Finding(
                rule_id="OSAAS-IAM-001",
                name="Unable to retrieve password policy from IDCS",
                category="Password Policy",
                severity="HIGH",
                file_path="IDCS /admin/v1/PasswordPolicies",
                line_num=None,
                line_content="No password policy data returned",
                description=(
                    "The scanner could not retrieve password policy configuration from the "
                    "IDCS Identity Domain. This may indicate insufficient permissions or "
                    "the endpoint is not available."
                ),
                recommendation="Ensure the scanner has urn:opc:idm:t.security.client scope.",
                cwe="CWE-521",
            ))
            return

        for pol in policies:
            name = pol.get("name", pol.get("displayName", "Default"))
            min_len = int(pol.get("minLength", 0))
            min_upper = int(pol.get("minUpperCase", 0))
            min_lower = int(pol.get("minLowerCase", 0))
            min_numeric = int(pol.get("minNumerals", 0))
            min_special = int(pol.get("minSpecialChars", 0))
            expires_after = int(pol.get("passwordExpiresAfter", 0))
            history = int(pol.get("numPasswordsInHistory", 0))
            lockout_threshold = int(pol.get("maxIncorrectAttempts", 0))
            lockout_duration = int(pol.get("lockoutDuration", 0))

            # IAM-001: Min length < 8
            if min_len < 8:
                self._add(Finding(
                    rule_id="OSAAS-IAM-001",
                    name=f"Password minimum length below 8 characters (policy: {name})",
                    category="Password Policy",
                    severity="HIGH",
                    file_path="IDCS /admin/v1/PasswordPolicies",
                    line_num=None,
                    line_content=f"minLength = {min_len}",
                    description=(
                        f"Password policy '{name}' requires only {min_len} characters. "
                        "Passwords shorter than 8 characters are significantly easier to "
                        "brute-force. NIST SP 800-63B recommends a minimum of 8 characters."
                    ),
                    recommendation="Set minLength to at least 12 characters (8 minimum per CIS).",
                    cwe="CWE-521",
                ))

            # IAM-002: No uppercase required
            if min_upper < 1:
                self._add(Finding(
                    rule_id="OSAAS-IAM-002",
                    name=f"Password uppercase characters not required (policy: {name})",
                    category="Password Policy",
                    severity="MEDIUM",
                    file_path="IDCS /admin/v1/PasswordPolicies",
                    line_num=None,
                    line_content=f"minUpperCase = {min_upper}",
                    description=(
                        f"Password policy '{name}' does not require uppercase characters. "
                        "Complexity requirements increase the search space for brute-force attacks."
                    ),
                    recommendation="Set minUpperCase to at least 1.",
                    cwe="CWE-521",
                ))

            # IAM-003: No lowercase required
            if min_lower < 1:
                self._add(Finding(
                    rule_id="OSAAS-IAM-003",
                    name=f"Password lowercase characters not required (policy: {name})",
                    category="Password Policy",
                    severity="MEDIUM",
                    file_path="IDCS /admin/v1/PasswordPolicies",
                    line_num=None,
                    line_content=f"minLowerCase = {min_lower}",
                    description=(
                        f"Password policy '{name}' does not require lowercase characters."
                    ),
                    recommendation="Set minLowerCase to at least 1.",
                    cwe="CWE-521",
                ))

            # IAM-004: No numeric required
            if min_numeric < 1:
                self._add(Finding(
                    rule_id="OSAAS-IAM-004",
                    name=f"Password numeric characters not required (policy: {name})",
                    category="Password Policy",
                    severity="MEDIUM",
                    file_path="IDCS /admin/v1/PasswordPolicies",
                    line_num=None,
                    line_content=f"minNumerals = {min_numeric}",
                    description=(
                        f"Password policy '{name}' does not require numeric characters."
                    ),
                    recommendation="Set minNumerals to at least 1.",
                    cwe="CWE-521",
                ))

            # IAM-005: No special chars required
            if min_special < 1:
                self._add(Finding(
                    rule_id="OSAAS-IAM-005",
                    name=f"Password special characters not required (policy: {name})",
                    category="Password Policy",
                    severity="MEDIUM",
                    file_path="IDCS /admin/v1/PasswordPolicies",
                    line_num=None,
                    line_content=f"minSpecialChars = {min_special}",
                    description=(
                        f"Password policy '{name}' does not require special characters."
                    ),
                    recommendation="Set minSpecialChars to at least 1.",
                    cwe="CWE-521",
                ))

            # IAM-006: Expiry disabled or > 90 days
            if expires_after == 0 or expires_after > 90:
                label = "disabled" if expires_after == 0 else f"{expires_after} days"
                self._add(Finding(
                    rule_id="OSAAS-IAM-006",
                    name=f"Password expiration {label} (policy: {name})",
                    category="Password Policy",
                    severity="MEDIUM",
                    file_path="IDCS /admin/v1/PasswordPolicies",
                    line_num=None,
                    line_content=f"passwordExpiresAfter = {expires_after}",
                    description=(
                        f"Password policy '{name}' has password expiration set to {label}. "
                        "Long-lived passwords increase the window of opportunity for compromised "
                        "credentials to be exploited."
                    ),
                    recommendation="Set passwordExpiresAfter to 90 days or less.",
                    cwe="CWE-262",
                ))

            # IAM-007: History < 5
            if history < 5:
                self._add(Finding(
                    rule_id="OSAAS-IAM-007",
                    name=f"Password history too short: {history} (policy: {name})",
                    category="Password Policy",
                    severity="LOW",
                    file_path="IDCS /admin/v1/PasswordPolicies",
                    line_num=None,
                    line_content=f"numPasswordsInHistory = {history}",
                    description=(
                        f"Password policy '{name}' remembers only {history} previous passwords. "
                        "Users may cycle back to a recently used (potentially compromised) password."
                    ),
                    recommendation="Set numPasswordsInHistory to at least 5.",
                    cwe="CWE-521",
                ))

            # IAM-008: Lockout threshold > 10
            if lockout_threshold == 0 or lockout_threshold > 10:
                label = "disabled" if lockout_threshold == 0 else str(lockout_threshold)
                self._add(Finding(
                    rule_id="OSAAS-IAM-008",
                    name=f"Account lockout threshold too high: {label} (policy: {name})",
                    category="Password Policy",
                    severity="HIGH",
                    file_path="IDCS /admin/v1/PasswordPolicies",
                    line_num=None,
                    line_content=f"maxIncorrectAttempts = {lockout_threshold}",
                    description=(
                        f"Password policy '{name}' allows {label} failed login attempts "
                        "before lockout. This makes brute-force attacks feasible."
                    ),
                    recommendation="Set maxIncorrectAttempts to 10 or fewer (5 recommended).",
                    cwe="CWE-307",
                ))

            # IAM-009: Lockout duration < 30 min
            if lockout_threshold > 0 and lockout_duration < 30:
                self._add(Finding(
                    rule_id="OSAAS-IAM-009",
                    name=f"Account lockout duration too short: {lockout_duration} min (policy: {name})",
                    category="Password Policy",
                    severity="MEDIUM",
                    file_path="IDCS /admin/v1/PasswordPolicies",
                    line_num=None,
                    line_content=f"lockoutDuration = {lockout_duration}",
                    description=(
                        f"Password policy '{name}' locks accounts for only {lockout_duration} "
                        "minutes. Short lockout durations allow rapid retry of brute-force attacks."
                    ),
                    recommendation="Set lockoutDuration to at least 30 minutes.",
                    cwe="CWE-307",
                ))

    # ----------------------------------------------------------
    # 1.2 MFA Enforcement  (OSAAS-IAM-010 .. 012, 022)
    # ----------------------------------------------------------
    def _check_mfa_enforcement(self):
        self._vprint("  [check] MFA enforcement \u2026")
        policies = self._idcs_get("SignOnPolicies")
        factor_settings = self._idcs_get_single("AuthenticationFactorSettings")

        if not policies:
            self._add(Finding(
                rule_id="OSAAS-IAM-010",
                name="No Sign-On Policies found \u2014 MFA status unknown",
                category="Multi-Factor Authentication",
                severity="CRITICAL",
                file_path="IDCS /admin/v1/SignOnPolicies",
                line_num=None,
                line_content="No sign-on policies returned",
                description=(
                    "The scanner could not retrieve any Sign-On Policies from IDCS. "
                    "Without sign-on policies, MFA cannot be enforced at the platform level."
                ),
                recommendation=(
                    "Create a Sign-On Policy in IDCS that enforces MFA for all users. "
                    "Navigate to Identity Domain > Security > Sign-On Policies."
                ),
                cwe="CWE-308",
            ))
            return

        has_global_mfa = False
        has_admin_mfa = False
        has_bypass_rule = False

        for pol in policies:
            pol_name = pol.get("name", pol.get("displayName", ""))
            status = pol.get("status", "").lower()
            if status != "active":
                continue

            rules = pol.get("rules", pol.get("signOnPolicyRules", []))
            for rule in rules:
                rule_status = rule.get("status", "active").lower()
                if rule_status != "active":
                    continue

                action = rule.get("action", rule.get("signOnAction", {}))
                factor_mandatory = action.get("factorMandatory", False)
                condition = rule.get("condition", rule.get("signOnCondition", {}))
                groups = condition.get("groups", condition.get("memberOfGroups", []))

                # Check if this is a bypass rule (MFA not required)
                if not factor_mandatory:
                    has_bypass_rule = True

                # Check for global MFA (no group restriction)
                if factor_mandatory and not groups:
                    has_global_mfa = True

                # Check for admin-specific MFA
                if factor_mandatory and groups:
                    group_names = []
                    for g in groups:
                        if isinstance(g, dict):
                            group_names.append(g.get("value", g.get("display", "")))
                        elif isinstance(g, str):
                            group_names.append(g)
                    if any(
                        n.lower() in ("identity domain administrators", "administrators",
                                      "security administrators", "cloud account administrators")
                        for n in group_names
                    ):
                        has_admin_mfa = True

        # IAM-010: No global MFA
        if not has_global_mfa:
            self._add(Finding(
                rule_id="OSAAS-IAM-010",
                name="MFA not enforced for all users via Sign-On Policy",
                category="Multi-Factor Authentication",
                severity="CRITICAL",
                file_path="IDCS /admin/v1/SignOnPolicies",
                line_num=None,
                line_content="factorMandatory = false (global scope)",
                description=(
                    "No Sign-On Policy rule enforces MFA for all users without group "
                    "restrictions. Without universal MFA, any compromised credential "
                    "grants immediate access to Oracle SaaS applications."
                ),
                recommendation=(
                    "Create a default Sign-On Policy rule with factorMandatory=true "
                    "and no group condition, ensuring all users must complete MFA."
                ),
                cwe="CWE-308",
            ))

        # IAM-011: No admin MFA
        if not has_admin_mfa and not has_global_mfa:
            self._add(Finding(
                rule_id="OSAAS-IAM-011",
                name="MFA not explicitly enforced for administrator roles",
                category="Multi-Factor Authentication",
                severity="CRITICAL",
                file_path="IDCS /admin/v1/SignOnPolicies",
                line_num=None,
                line_content="No admin-scoped MFA rule found",
                description=(
                    "No Sign-On Policy rule specifically enforces MFA for Identity Domain "
                    "Administrators or Security Administrators. Privileged accounts are the "
                    "highest-value targets and must have the strongest authentication controls."
                ),
                recommendation=(
                    "Create a Sign-On Policy rule scoped to administrator groups with "
                    "factorMandatory=true and restrict to phishing-resistant factors."
                ),
                cwe="CWE-308",
            ))

        # IAM-012: Weak MFA factors
        if factor_settings:
            allowed_factors = []
            for key in ("smsEnabled", "emailEnabled", "totpEnabled",
                        "pushEnabled", "bypassCodeEnabled",
                        "securityQuestionsEnabled", "fidoAuthenticatorEnabled",
                        "phoneCallEnabled"):
                if factor_settings.get(key, False):
                    allowed_factors.append(key.replace("Enabled", ""))

            weak_only = all(
                f in ("sms", "email", "phoneCall", "securityQuestions", "bypassCode")
                for f in allowed_factors
            ) if allowed_factors else True

            if weak_only and allowed_factors:
                self._add(Finding(
                    rule_id="OSAAS-IAM-012",
                    name=f"Only weak MFA factors enabled: {', '.join(allowed_factors)}",
                    category="Multi-Factor Authentication",
                    severity="MEDIUM",
                    file_path="IDCS /admin/v1/AuthenticationFactorSettings",
                    line_num=None,
                    line_content=f"Enabled factors: {', '.join(allowed_factors)}",
                    description=(
                        "Only weak MFA factors (SMS, Email, Phone Call, Security Questions) "
                        "are enabled. These factors are vulnerable to SIM swapping, email "
                        "compromise, and social engineering attacks."
                    ),
                    recommendation=(
                        "Enable phishing-resistant MFA factors: TOTP (authenticator app), "
                        "Push notifications, or FIDO2 security keys."
                    ),
                    cwe="CWE-308",
                ))

        # IAM-022: Bypass MFA rules
        if has_bypass_rule:
            self._add(Finding(
                rule_id="OSAAS-IAM-022",
                name="Sign-On Policy contains MFA bypass rules",
                category="Multi-Factor Authentication",
                severity="CRITICAL",
                file_path="IDCS /admin/v1/SignOnPolicies",
                line_num=None,
                line_content="factorMandatory = false in active rule(s)",
                description=(
                    "One or more active Sign-On Policy rules have factorMandatory set to "
                    "false, allowing users matching those rules to skip MFA entirely. "
                    "Attackers may exploit these bypass rules to avoid second-factor "
                    "authentication."
                ),
                recommendation=(
                    "Review all Sign-On Policy rules and remove or restrict MFA bypass "
                    "conditions. If bypass is needed for service accounts, restrict by "
                    "IP network perimeter."
                ),
                cwe="CWE-308",
            ))

    # ----------------------------------------------------------
    # 1.3 SSO Configuration  (OSAAS-IAM-013)
    # ----------------------------------------------------------
    def _check_sso_configuration(self):
        self._vprint("  [check] SSO configuration \u2026")
        idps = self._idcs_get("IdentityProviders")

        has_saml = False
        has_oidc = False
        for idp in idps:
            idp_type = (idp.get("type", "") or idp.get("protocol", "")).upper()
            enabled = idp.get("enabled", idp.get("active", True))
            if not enabled:
                continue
            if "SAML" in idp_type:
                has_saml = True
            if "OIDC" in idp_type or "OPENID" in idp_type:
                has_oidc = True

        if not has_saml and not has_oidc:
            self._add(Finding(
                rule_id="OSAAS-IAM-013",
                name="SSO/SAML federation not configured for Identity Domain",
                category="Single Sign-On",
                severity="HIGH",
                file_path="IDCS /admin/v1/IdentityProviders",
                line_num=None,
                line_content=f"Federated IdPs found: SAML={has_saml}, OIDC={has_oidc}",
                description=(
                    "No SAML or OIDC Identity Provider is configured for this Identity "
                    "Domain. Without federation, users authenticate directly against "
                    "IDCS local credentials, bypassing your corporate identity provider's "
                    "security controls (MFA, conditional access, session management)."
                ),
                recommendation=(
                    "Configure SAML 2.0 or OIDC federation with your corporate identity "
                    "provider (e.g., Microsoft Entra ID, Okta, Ping Identity). "
                    "Navigate to Identity Domain > Security > Identity Providers."
                ),
                cwe="CWE-287",
            ))

    # ----------------------------------------------------------
    # 1.3.2 OAuth Clients  (OSAAS-IAM-014, 015)
    # ----------------------------------------------------------
    def _check_oauth_clients(self):
        self._vprint("  [check] OAuth clients \u2026")
        apps = self._idcs_get("Apps", params={
            "filter": 'isOAuthClient eq true',
            "attributes": "displayName,active,allowedScopes,grantedAppRoles,"
                          "isUnmanagedApp,meta",
        })

        if not apps:
            return

        excessive_scope_apps = []
        stale_apps = []
        now = datetime.now(timezone.utc)
        stale_threshold = now - timedelta(days=180)

        for app in apps:
            app_name = app.get("displayName", app.get("name", "Unknown"))
            active = app.get("active", True)
            if not active:
                continue

            # Check for excessive scopes
            scopes = app.get("allowedScopes", [])
            granted_roles = app.get("grantedAppRoles", [])
            scope_values = set()
            for s in scopes:
                if isinstance(s, dict):
                    scope_values.add(s.get("fqs", s.get("value", "")))
                elif isinstance(s, str):
                    scope_values.add(s)
            for r in granted_roles:
                if isinstance(r, dict):
                    scope_values.add(r.get("value", ""))

            risky = scope_values & HIGH_RISK_SCOPES
            if risky:
                excessive_scope_apps.append(f"{app_name} ({', '.join(risky)})")

            # Check for staleness
            meta = app.get("meta", {})
            last_modified = meta.get("lastModified", meta.get("created", ""))
            if last_modified:
                try:
                    mod_dt = datetime.fromisoformat(last_modified.replace("Z", "+00:00"))
                    if mod_dt < stale_threshold:
                        stale_apps.append(app_name)
                except (ValueError, TypeError):
                    pass

        # IAM-014: Excessive scopes
        if excessive_scope_apps:
            self._add(Finding(
                rule_id="OSAAS-IAM-014",
                name=f"OAuth clients with excessive admin scopes ({len(excessive_scope_apps)})",
                category="OAuth Security",
                severity="HIGH",
                file_path="IDCS /admin/v1/Apps",
                line_num=None,
                line_content=f"Risky apps: {'; '.join(excessive_scope_apps[:5])}",
                description=(
                    f"{len(excessive_scope_apps)} OAuth client application(s) have been "
                    "granted admin-level IDCS scopes (e.g., user.admin, group.admin, "
                    "security.admin). Compromised OAuth clients with these scopes can "
                    "perform full domain takeover."
                ),
                recommendation=(
                    "Review each OAuth client and reduce scopes to the minimum required. "
                    "Replace admin scopes with read-only equivalents where possible. "
                    "Regularly audit OAuth client permissions."
                ),
                cwe="CWE-250",
            ))

        # IAM-015: Stale clients
        if stale_apps:
            self._add(Finding(
                rule_id="OSAAS-IAM-015",
                name=f"Stale OAuth clients not modified in 180+ days ({len(stale_apps)})",
                category="OAuth Security",
                severity="MEDIUM",
                file_path="IDCS /admin/v1/Apps",
                line_num=None,
                line_content=f"Stale apps: {'; '.join(stale_apps[:5])}",
                description=(
                    f"{len(stale_apps)} active OAuth client(s) have not been modified in "
                    "over 180 days. Stale applications may have outdated permissions, "
                    "unrotated secrets, or may no longer be in use."
                ),
                recommendation=(
                    "Review stale OAuth clients: deactivate unused ones, rotate secrets "
                    "for active ones, and reduce scopes where possible."
                ),
                cwe="CWE-262",
            ))

    # ----------------------------------------------------------
    # 1.4 Privileged Roles — IDCS  (OSAAS-IAM-016)
    # ----------------------------------------------------------
    def _check_privileged_roles_idcs(self):
        self._vprint("  [check] Privileged IDCS groups \u2026")
        oversized_groups = []

        for group_name in PRIVILEGED_IDCS_GROUPS:
            groups = self._idcs_get("Groups", params={
                "filter": f'displayName eq "{group_name}"',
                "attributes": "displayName,members",
            })
            for g in groups:
                members = g.get("members", [])
                if len(members) > 5:
                    oversized_groups.append(
                        f"{g.get('displayName', group_name)} ({len(members)} members)"
                    )

        if oversized_groups:
            self._add(Finding(
                rule_id="OSAAS-IAM-016",
                name=f"IDCS privileged groups have excessive members ({len(oversized_groups)} groups)",
                category="Privileged Access",
                severity="HIGH",
                file_path="IDCS /admin/v1/Groups",
                line_num=None,
                line_content=f"Oversized groups: {'; '.join(oversized_groups)}",
                description=(
                    f"{len(oversized_groups)} privileged Identity Domain group(s) have more "
                    "than 5 members. Over-provisioning admin access increases the attack "
                    "surface and violates the principle of least privilege."
                ),
                recommendation=(
                    "Review privileged group memberships. Remove users who do not require "
                    "admin access. Limit Identity Domain Administrators to 3-5 trusted "
                    "administrators. Use break-glass accounts for emergency access."
                ),
                cwe="CWE-250",
            ))

    # ----------------------------------------------------------
    # 1.4.2 Privileged Roles — Fusion  (OSAAS-IAM-017)
    # ----------------------------------------------------------
    def _check_privileged_roles_fusion(self):
        if not self.fusion_url:
            return
        self._vprint("  [check] Privileged Fusion roles \u2026")

        oversized_roles = []
        for role_code, role_name in PRIVILEGED_FUSION_ROLES.items():
            # Try Fusion Security Console or HCM role membership API
            users = self._fusion_get(
                f"{FUSION_HCM}/userRoleAssignments",
                params={"q": f"RoleCode='{role_code}'"},
            )
            if len(users) > 5:
                oversized_roles.append(f"{role_name} ({len(users)} users)")

        if oversized_roles:
            self._add(Finding(
                rule_id="OSAAS-IAM-017",
                name=f"Fusion Cloud privileged roles over-provisioned ({len(oversized_roles)} roles)",
                category="Privileged Access",
                severity="HIGH",
                file_path=f"Fusion {FUSION_HCM}/userRoleAssignments",
                line_num=None,
                line_content=f"Oversized roles: {'; '.join(oversized_roles)}",
                description=(
                    f"{len(oversized_roles)} privileged Fusion Cloud role(s) have more than "
                    "5 assigned users. Over-provisioned IT Security Manager, Application "
                    "Administrator, or System Administrator roles grant excessive access "
                    "to configuration and security settings."
                ),
                recommendation=(
                    "Review Fusion Cloud role assignments via Security Console. "
                    "Remove users who do not require elevated privileges. "
                    "Implement role-based access control with custom duty roles."
                ),
                cwe="CWE-250",
            ))

    # ----------------------------------------------------------
    # 1.5 User Lifecycle  (OSAAS-IAM-018, 019)
    # ----------------------------------------------------------
    def _check_user_lifecycle(self):
        self._vprint("  [check] User lifecycle \u2026")
        users = self._idcs_get("Users", params={
            "filter": "active eq true",
            "attributes": "userName,displayName,active,"
                          "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User,"
                          "meta,lastSuccessfulLoginDate",
        })

        if not users:
            return

        now = datetime.now(timezone.utc)
        inactive_cutoff = now - timedelta(days=90)
        inactive_users = []
        terminated_active = []

        for u in users:
            uname = u.get("userName", u.get("displayName", "unknown"))
            ext = u.get("urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User", {})

            # Check last login
            last_login = u.get("lastSuccessfulLoginDate") or ext.get("lastSuccessfulLoginDate", "")
            if last_login:
                try:
                    login_dt = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                    if login_dt < inactive_cutoff:
                        days_inactive = (now - login_dt).days
                        inactive_users.append(f"{uname} ({days_inactive}d)")
                except (ValueError, TypeError):
                    pass
            else:
                # Never logged in — check creation date
                meta = u.get("meta", {})
                created = meta.get("created", "")
                if created:
                    try:
                        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        if created_dt < inactive_cutoff:
                            days_since = (now - created_dt).days
                            inactive_users.append(f"{uname} (never logged in, {days_since}d)")
                    except (ValueError, TypeError):
                        pass

            # Check for terminated/deprovisioned status
            emp_status = ext.get("employeeStatus", ext.get("status", ""))
            if emp_status and emp_status.lower() in ("terminated", "inactive",
                                                      "deprovisioned", "suspended"):
                terminated_active.append(f"{uname} (status: {emp_status})")

        # IAM-018: Inactive users
        if inactive_users:
            sev = "HIGH" if len(inactive_users) > 10 else "MEDIUM"
            self._add(Finding(
                rule_id="OSAAS-IAM-018",
                name=f"Active users not logged in for 90+ days ({len(inactive_users)})",
                category="User Lifecycle",
                severity=sev,
                file_path="IDCS /admin/v1/Users",
                line_num=None,
                line_content=f"Inactive: {'; '.join(inactive_users[:5])}"
                             + (f" (+{len(inactive_users)-5} more)" if len(inactive_users) > 5 else ""),
                description=(
                    f"{len(inactive_users)} active user account(s) have not logged in for over "
                    "90 days. Dormant accounts are prime targets for credential-based attacks "
                    "because unauthorized access may go undetected for extended periods."
                ),
                recommendation=(
                    "Review inactive accounts: disable accounts inactive for 90+ days, "
                    "implement automated lifecycle policies to deactivate dormant accounts, "
                    "and notify managers of inactive team members."
                ),
                cwe="CWE-613",
            ))

        # IAM-019: Terminated but active
        if terminated_active:
            self._add(Finding(
                rule_id="OSAAS-IAM-019",
                name=f"Terminated/deprovisioned users still active in IDCS ({len(terminated_active)})",
                category="User Lifecycle",
                severity="HIGH",
                file_path="IDCS /admin/v1/Users",
                line_num=None,
                line_content=f"Terminated-active: {'; '.join(terminated_active[:5])}",
                description=(
                    f"{len(terminated_active)} user account(s) have an employment status of "
                    "'terminated' or 'deprovisioned' but are still active in IDCS. These "
                    "accounts represent unauthorized access risk from former employees."
                ),
                recommendation=(
                    "Immediately deactivate all terminated user accounts. Implement automated "
                    "provisioning/deprovisioning via HR feed integration (SCIM, LDAP, or "
                    "Oracle Identity Governance)."
                ),
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # 1.6 Admin Access Restrictions  (OSAAS-IAM-020, 021)
    # ----------------------------------------------------------
    def _check_admin_access_restrictions(self):
        self._vprint("  [check] Admin access restrictions \u2026")

        # IAM-020: Check if admin sign-on policy has IP restriction
        policies = self._idcs_get("SignOnPolicies")
        admin_has_ip = False
        for pol in policies:
            status = pol.get("status", "").lower()
            if status != "active":
                continue
            rules = pol.get("rules", pol.get("signOnPolicyRules", []))
            for rule in rules:
                rule_status = rule.get("status", "active").lower()
                if rule_status != "active":
                    continue
                condition = rule.get("condition", rule.get("signOnCondition", {}))
                groups = condition.get("groups", condition.get("memberOfGroups", []))
                perimeters = condition.get("networkPerimeters",
                                          condition.get("clientIpAddress", []))
                # Check if this rule targets admin groups AND has network conditions
                group_names = []
                for g in groups:
                    if isinstance(g, dict):
                        group_names.append(g.get("value", g.get("display", "")).lower())
                    elif isinstance(g, str):
                        group_names.append(g.lower())
                is_admin_rule = any(
                    n in ("identity domain administrators", "administrators",
                          "security administrators")
                    for n in group_names
                )
                if is_admin_rule and perimeters:
                    admin_has_ip = True

        if not admin_has_ip:
            self._add(Finding(
                rule_id="OSAAS-IAM-020",
                name="No IP-based access restriction for administrator Sign-On Policy",
                category="Access Restrictions",
                severity="HIGH",
                file_path="IDCS /admin/v1/SignOnPolicies",
                line_num=None,
                line_content="No networkPerimeter condition on admin rules",
                description=(
                    "No Sign-On Policy rule restricts administrator access to specific "
                    "IP addresses or network perimeters. Administrators can sign in from "
                    "any location, including untrusted networks."
                ),
                recommendation=(
                    "Create a Sign-On Policy rule scoped to administrator groups with a "
                    "networkPerimeters condition limiting access to corporate IP ranges. "
                    "Navigate to Identity Domain > Security > Sign-On Policies."
                ),
                cwe="CWE-284",
            ))

        # IAM-021: Self-registration enabled
        settings = self._idcs_get_single("Settings/Settings")
        if settings:
            self_reg = settings.get("selfRegistrationEnabled",
                                    settings.get("isSelfRegistrationEnabled", False))
            if self_reg:
                self._add(Finding(
                    rule_id="OSAAS-IAM-021",
                    name="Self-registration enabled in Identity Domain",
                    category="Access Restrictions",
                    severity="MEDIUM",
                    file_path="IDCS /admin/v1/Settings",
                    line_num=None,
                    line_content="selfRegistrationEnabled = true",
                    description=(
                        "Self-registration is enabled, allowing anyone to create an account "
                        "in this Identity Domain without administrator approval. This can "
                        "lead to unauthorized access to Oracle SaaS applications."
                    ),
                    recommendation=(
                        "Disable self-registration unless explicitly required. Use "
                        "administrator-managed or HR-feed-based provisioning instead."
                    ),
                    cwe="CWE-284",
                ))

    # ==============================================================
    # Section 2: Configuration Management  (13 checks)
    # ==============================================================

    # ----------------------------------------------------------
    # 2.1 Config Change Monitoring  (OSAAS-CFG-001, 004, 005)
    # ----------------------------------------------------------
    def _check_config_change_monitoring(self):
        self._vprint("  [check] Configuration change monitoring \u2026")

        # CFG-001: Audit policies for high-risk changes
        audit_policies = self._fusion_get(
            f"{FUSION_FSCM}/setupMaintenanceAuditPolicies"
        )
        if not audit_policies:
            self._add(Finding(
                rule_id="OSAAS-CFG-001",
                name="High-risk configuration change monitoring not enabled",
                category="Configuration Management",
                severity="HIGH",
                file_path=f"Fusion {FUSION_FSCM}/setupMaintenanceAuditPolicies",
                line_num=None,
                line_content="No audit policies configured or accessible",
                description=(
                    "No Setup and Maintenance audit policies were found. Without monitoring, "
                    "high-risk configuration changes (security settings, integration endpoints, "
                    "role assignments) may go undetected."
                ),
                recommendation=(
                    "Enable audit policies for Setup and Maintenance tasks in Fusion Cloud. "
                    "Navigate to Setup and Maintenance > Manage Audit Policies."
                ),
                cwe="CWE-778",
            ))

        # CFG-004: Change approval workflow
        tasks = self._fusion_get(
            f"{FUSION_FSCM}/setupAndMaintenance/tasksAndFlows",
        )
        has_approval = False
        for task in tasks:
            task_name = (task.get("Name", "") or task.get("name", "")).lower()
            if "approval" in task_name or "workflow" in task_name:
                has_approval = True
                break

        if not has_approval and tasks:
            self._add(Finding(
                rule_id="OSAAS-CFG-004",
                name="Configuration change approval workflow not detected",
                category="Configuration Management",
                severity="HIGH",
                file_path=f"Fusion {FUSION_FSCM}/setupAndMaintenance/tasksAndFlows",
                line_num=None,
                line_content="No approval workflow tasks found",
                description=(
                    "No configuration change approval workflow was detected in Setup and "
                    "Maintenance. Without approval workflows, security-critical configuration "
                    "changes can be applied without peer review."
                ),
                recommendation=(
                    "Implement approval workflows for high-risk Setup and Maintenance tasks "
                    "using Oracle BPM or Approval Management."
                ),
                cwe="CWE-284",
            ))

        # CFG-005: Sandbox promotion without approval
        sandboxes = self._fusion_get(
            f"{FUSION_FSCM}/setupAndMaintenance/sandboxes",
        )
        uncontrolled = []
        for sb in sandboxes:
            sb_name = sb.get("Name", sb.get("name", "Unknown"))
            sb_status = (sb.get("Status", sb.get("status", "")) or "").lower()
            if sb_status in ("published", "promoting") and not sb.get("ApprovalRequired", False):
                uncontrolled.append(sb_name)

        if uncontrolled:
            self._add(Finding(
                rule_id="OSAAS-CFG-005",
                name=f"Sandbox promoted without approval ({len(uncontrolled)})",
                category="Configuration Management",
                severity="MEDIUM",
                file_path=f"Fusion {FUSION_FSCM}/setupAndMaintenance/sandboxes",
                line_num=None,
                line_content=f"Uncontrolled promotions: {'; '.join(uncontrolled[:5])}",
                description=(
                    f"{len(uncontrolled)} sandbox environment(s) were promoted without "
                    "requiring approval. Sandbox changes can include security-sensitive "
                    "configurations that should be peer-reviewed before production promotion."
                ),
                recommendation=(
                    "Enable approval requirements for sandbox promotions in "
                    "Setup and Maintenance > Manage Sandboxes."
                ),
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # 2.1.2-3 Custom Roles  (OSAAS-CFG-002, 003)
    # ----------------------------------------------------------
    def _check_custom_roles(self):
        self._vprint("  [check] Custom roles \u2026")
        roles = self._fusion_get(
            f"{FUSION_HCM}/roles",
            params={"q": "RoleCategory='CUSTOM'"},
        )
        if not roles:
            return

        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(days=180)
        unused_roles = []
        excessive_roles = []

        for role in roles:
            role_name = role.get("RoleName", role.get("displayName", "Unknown"))
            role_code = role.get("RoleCode", "")
            members_count = int(role.get("MembersCount", role.get("membersCount", 0)))
            created = role.get("CreationDate", role.get("meta", {}).get("created", ""))

            # CFG-002: Unused custom roles
            if members_count == 0 and created:
                try:
                    created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    if created_dt < stale_cutoff:
                        unused_roles.append(f"{role_name} ({role_code})")
                except (ValueError, TypeError):
                    unused_roles.append(f"{role_name} ({role_code})")

            # CFG-003: Roles with admin-level grants
            privileges = role.get("Privileges", role.get("privileges", []))
            for priv in privileges:
                priv_name = (priv.get("PrivilegeName", priv.get("name", "")) or "").lower()
                if any(kw in priv_name for kw in ("admin", "manage_all", "full_control",
                                                   "security_manager", "system_admin")):
                    excessive_roles.append(f"{role_name}: {priv_name}")
                    break

        if unused_roles:
            self._add(Finding(
                rule_id="OSAAS-CFG-002",
                name=f"Unused custom roles with no members ({len(unused_roles)})",
                category="Configuration Management",
                severity="MEDIUM",
                file_path=f"Fusion {FUSION_HCM}/roles",
                line_num=None,
                line_content=f"Unused roles: {'; '.join(unused_roles[:5])}",
                description=(
                    f"{len(unused_roles)} custom role(s) have no assigned members and are "
                    "older than 180 days. Unused roles add complexity and may be accidentally "
                    "assigned, granting unintended permissions."
                ),
                recommendation=(
                    "Review and delete unused custom roles. Implement a periodic role "
                    "certification process to clean up stale roles."
                ),
                cwe="CWE-284",
            ))

        if excessive_roles:
            self._add(Finding(
                rule_id="OSAAS-CFG-003",
                name=f"Custom roles with admin-level privileges ({len(excessive_roles)})",
                category="Configuration Management",
                severity="HIGH",
                file_path=f"Fusion {FUSION_HCM}/roles",
                line_num=None,
                line_content=f"Excessive roles: {'; '.join(excessive_roles[:5])}",
                description=(
                    f"{len(excessive_roles)} custom role(s) have admin-equivalent privileges "
                    "granted. Custom roles should follow least privilege and use specific "
                    "duty roles rather than broad admin grants."
                ),
                recommendation=(
                    "Review custom roles with admin privileges. Replace broad grants with "
                    "specific duty roles. Use Oracle Security Console to analyze role hierarchy."
                ),
                cwe="CWE-250",
            ))

    # ----------------------------------------------------------
    # 2.3 Data Security Policies  (OSAAS-CFG-006, 007, 008)
    # ----------------------------------------------------------
    def _check_data_security_policies(self):
        self._vprint("  [check] Data security policies \u2026")

        # CFG-006: Flexfield security
        flexfields = self._fusion_get(
            f"{FUSION_FSCM}/descriptiveFlexfields",
        )
        unsecured_flex = []
        for ff in flexfields:
            ff_name = ff.get("DescriptiveFlexfieldName", ff.get("name", ""))
            protected = ff.get("Protected", ff.get("securityEnabled", False))
            if not protected:
                unsecured_flex.append(ff_name)

        if unsecured_flex and len(unsecured_flex) > len(flexfields) * 0.5:
            self._add(Finding(
                rule_id="OSAAS-CFG-006",
                name=f"Flexfield-level security not enforced ({len(unsecured_flex)} unprotected)",
                category="Data Security",
                severity="MEDIUM",
                file_path=f"Fusion {FUSION_FSCM}/descriptiveFlexfields",
                line_num=None,
                line_content=f"Unprotected flexfields: {'; '.join(unsecured_flex[:5])}",
                description=(
                    f"{len(unsecured_flex)} descriptive flexfield(s) do not have security "
                    "protection enabled. Flexfields often contain sensitive business data "
                    "that should be access-controlled."
                ),
                recommendation=(
                    "Enable security on descriptive flexfields containing sensitive data. "
                    "Use data security policies to restrict access by role."
                ),
                cwe="CWE-284",
            ))

        # CFG-007: Unrestricted data roles
        data_roles = self._fusion_get(
            f"{FUSION_HCM}/dataSecurityPolicies",
        )
        unrestricted = []
        for dr in data_roles:
            dr_name = dr.get("DataSecurityPolicyName", dr.get("name", ""))
            condition = dr.get("Condition", dr.get("condition", ""))
            if not condition or condition.lower() in ("1=1", "true", "all"):
                unrestricted.append(dr_name)

        if unrestricted:
            self._add(Finding(
                rule_id="OSAAS-CFG-007",
                name=f"Data role assignments with unrestricted data scope ({len(unrestricted)})",
                category="Data Security",
                severity="HIGH",
                file_path=f"Fusion {FUSION_HCM}/dataSecurityPolicies",
                line_num=None,
                line_content=f"Unrestricted policies: {'; '.join(unrestricted[:5])}",
                description=(
                    f"{len(unrestricted)} data security policy/policies have unrestricted "
                    "conditions (e.g., 1=1). This grants access to all data instances "
                    "for the associated role, violating least privilege."
                ),
                recommendation=(
                    "Review data security policies with unrestricted conditions. "
                    "Replace with scoped conditions (by business unit, department, etc.)."
                ),
                cwe="CWE-284",
            ))

        # CFG-008: Security profiles with admin-equivalent access
        sec_profiles = self._fusion_get(
            f"{FUSION_HCM}/securityProfiles",
        )
        admin_profiles = []
        for sp in sec_profiles:
            sp_name = sp.get("SecurityProfileName", sp.get("name", ""))
            sp_type = (sp.get("ViewAllFlag", sp.get("viewAll", "")) or "").lower()
            if sp_type in ("y", "yes", "true", "1"):
                admin_profiles.append(sp_name)

        if admin_profiles:
            self._add(Finding(
                rule_id="OSAAS-CFG-008",
                name=f"Security profiles with view-all access ({len(admin_profiles)})",
                category="Data Security",
                severity="HIGH",
                file_path=f"Fusion {FUSION_HCM}/securityProfiles",
                line_num=None,
                line_content=f"Admin profiles: {'; '.join(admin_profiles[:5])}",
                description=(
                    f"{len(admin_profiles)} security profile(s) have 'View All' enabled, "
                    "granting access to all records. These profiles bypass data security "
                    "policies and should be tightly controlled."
                ),
                recommendation=(
                    "Replace 'View All' security profiles with scoped profiles. "
                    "Limit view-all access to break-glass admin accounts only."
                ),
                cwe="CWE-250",
            ))

    # ----------------------------------------------------------
    # 2.4-2.5 Scheduled Processes & Integration  (OSAAS-CFG-009..013)
    # ----------------------------------------------------------
    def _check_scheduled_processes(self):
        self._vprint("  [check] Scheduled processes and integration users \u2026")

        # CFG-009: EPM maintenance config drift
        epm_snapshots = self._fusion_get(f"{EPM_BASE}/applicationsnapshots")
        if not epm_snapshots:
            self._add(Finding(
                rule_id="OSAAS-CFG-009",
                name="EPM Cloud configuration snapshots not found or accessible",
                category="Configuration Management",
                severity="MEDIUM",
                file_path=f"Fusion {EPM_BASE}/applicationsnapshots",
                line_num=None,
                line_content="No EPM snapshots returned",
                description=(
                    "EPM Cloud application snapshots could not be retrieved. Without "
                    "snapshots, configuration drift cannot be detected and rollback "
                    "is difficult after unauthorized changes."
                ),
                recommendation=(
                    "Enable scheduled configuration snapshots in EPM Cloud. "
                    "Configure regular backup artifacts for all EPM applications."
                ),
                cwe="CWE-778",
            ))

        # CFG-011: Scheduled processes with elevated privileges
        processes = self._fusion_get(
            f"{FUSION_FSCM}/erpintegrations",
        )
        elevated_procs = []
        for proc in processes:
            proc_name = proc.get("Name", proc.get("name", "Unknown"))
            run_as = (proc.get("RunAs", proc.get("runAs", "")) or "").lower()
            if any(kw in run_as for kw in ("admin", "sysadmin", "system",
                                            "it_security", "integration_specialist")):
                elevated_procs.append(f"{proc_name} (runAs: {run_as})")

        if elevated_procs:
            self._add(Finding(
                rule_id="OSAAS-CFG-011",
                name=f"Scheduled processes running with elevated privileges ({len(elevated_procs)})",
                category="Configuration Management",
                severity="HIGH",
                file_path=f"Fusion {FUSION_FSCM}/erpintegrations",
                line_num=None,
                line_content=f"Elevated procs: {'; '.join(elevated_procs[:5])}",
                description=(
                    f"{len(elevated_procs)} scheduled process(es) run under elevated "
                    "admin-level accounts. If these processes are compromised, the "
                    "attacker inherits admin privileges."
                ),
                recommendation=(
                    "Review scheduled processes and assign dedicated service accounts "
                    "with minimal required roles instead of admin accounts."
                ),
                cwe="CWE-250",
            ))

        # CFG-012: Integration users with admin roles
        integration_users = self._fusion_get(
            f"{FUSION_HCM}/users",
            params={"q": "PersonType='Integration'"},
        )
        admin_integrations = []
        for iu in integration_users:
            iu_name = iu.get("Username", iu.get("userName", "Unknown"))
            roles = iu.get("roles", iu.get("Roles", []))
            for r in roles:
                role_name = r.get("RoleName", r.get("name", "")) if isinstance(r, dict) else str(r)
                if any(kw in role_name.lower() for kw in ("admin", "security_manager",
                                                           "system_admin")):
                    admin_integrations.append(f"{iu_name}: {role_name}")
                    break

        if admin_integrations:
            self._add(Finding(
                rule_id="OSAAS-CFG-012",
                name=f"Integration user accounts with admin roles ({len(admin_integrations)})",
                category="Configuration Management",
                severity="HIGH",
                file_path=f"Fusion {FUSION_HCM}/users",
                line_num=None,
                line_content=f"Admin integrations: {'; '.join(admin_integrations[:5])}",
                description=(
                    f"{len(admin_integrations)} integration user account(s) have admin-level "
                    "roles assigned. Integration accounts should follow least privilege "
                    "and only have roles required for their specific integration tasks."
                ),
                recommendation=(
                    "Review integration user role assignments. Create custom duty roles "
                    "with minimal permissions for each integration use case."
                ),
                cwe="CWE-250",
            ))

        # CFG-013: Excessive customizations
        customizations = self._fusion_get(
            f"{FUSION_FSCM}/setupAndMaintenance/sandboxes",
        )
        active_personalizations = [
            sb for sb in customizations
            if (sb.get("Status", sb.get("status", "")) or "").lower() in ("active", "open")
        ]
        if len(active_personalizations) > 50:
            self._add(Finding(
                rule_id="OSAAS-CFG-013",
                name=f"Excessive active customizations ({len(active_personalizations)} sandboxes)",
                category="Configuration Management",
                severity="LOW",
                file_path=f"Fusion {FUSION_FSCM}/setupAndMaintenance/sandboxes",
                line_num=None,
                line_content=f"Active sandboxes/personalizations: {len(active_personalizations)}",
                description=(
                    f"{len(active_personalizations)} active sandbox/personalization environments "
                    "detected. High customization counts increase upgrade complexity and "
                    "security review burden."
                ),
                recommendation=(
                    "Review and consolidate active sandboxes. Promote or delete stale "
                    "sandboxes. Establish a governance process for customization management."
                ),
                cwe="CWE-1104",
            ))

    # ----------------------------------------------------------
    # 2.4.2 Implementation Projects  (OSAAS-CFG-010)
    # ----------------------------------------------------------
    def _check_implementation_projects(self):
        self._vprint("  [check] Implementation projects \u2026")
        projects = self._fusion_get(
            f"{FUSION_FSCM}/setupAndMaintenance/implementationProjects",
        )

        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(days=90)
        stale_projects = []

        for proj in projects:
            proj_name = proj.get("Name", proj.get("name", "Unknown"))
            proj_status = (proj.get("Status", proj.get("status", "")) or "").lower()
            created = proj.get("CreationDate", proj.get("meta", {}).get("created", ""))

            if proj_status in ("in_progress", "open", "active") and created:
                try:
                    created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    if created_dt < stale_cutoff:
                        days_open = (now - created_dt).days
                        stale_projects.append(f"{proj_name} ({days_open}d)")
                except (ValueError, TypeError):
                    pass

        if stale_projects:
            self._add(Finding(
                rule_id="OSAAS-CFG-010",
                name=f"Implementation projects open > 90 days ({len(stale_projects)})",
                category="Configuration Management",
                severity="LOW",
                file_path=f"Fusion {FUSION_FSCM}/setupAndMaintenance/implementationProjects",
                line_num=None,
                line_content=f"Stale projects: {'; '.join(stale_projects[:5])}",
                description=(
                    f"{len(stale_projects)} implementation project(s) have been in open state "
                    "for over 90 days. Long-running projects may contain uncommitted security "
                    "configurations that should be reviewed and finalized."
                ),
                recommendation=(
                    "Review stale implementation projects: complete and close finished "
                    "projects, archive abandoned ones."
                ),
                cwe="CWE-1104",
            ))

    # ==============================================================
    # Section 3: Networking  (10 checks)
    # ==============================================================

    # ----------------------------------------------------------
    # 3.1 Network Perimeters  (OSAAS-NET-001, 002, 010)
    # ----------------------------------------------------------
    def _check_network_perimeters(self):
        self._vprint("  [check] Network perimeters \u2026")
        perimeters = self._idcs_get("NetworkPerimeters")

        # NET-001: No network perimeters configured
        if not perimeters:
            self._add(Finding(
                rule_id="OSAAS-NET-001",
                name="Location-Based Access Control (LBAC) not configured",
                category="Network Security",
                severity="HIGH",
                file_path="IDCS /admin/v1/NetworkPerimeters",
                line_num=None,
                line_content="No network perimeters defined",
                description=(
                    "No network perimeters are configured in the Identity Domain. Without "
                    "Location-Based Access Control (LBAC), users can access Oracle SaaS "
                    "applications from any IP address worldwide."
                ),
                recommendation=(
                    "Configure network perimeters with your corporate IP ranges. "
                    "Navigate to Identity Domain > Security > Network Perimeters. "
                    "Use these perimeters in Sign-On Policy rules."
                ),
                cwe="CWE-284",
            ))
            return

        # Analyze CIDR ranges in perimeters
        overly_broad = []
        rfc1918_ranges = []

        for perim in perimeters:
            perim_name = perim.get("name", perim.get("displayName", "Unknown"))
            ip_addresses = perim.get("ipAddresses", [])
            for entry in ip_addresses:
                cidr = entry if isinstance(entry, str) else entry.get("value", "")
                if not cidr:
                    continue
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    # NET-002: Overly broad CIDR
                    if net.version == 4 and net.prefixlen < 16:
                        overly_broad.append(f"{perim_name}: {cidr} (/{net.prefixlen})")
                    elif net.version == 6 and net.prefixlen < 48:
                        overly_broad.append(f"{perim_name}: {cidr} (/{net.prefixlen})")

                    # NET-010: RFC1918 private ranges
                    private_nets = [
                        ipaddress.ip_network("10.0.0.0/8"),
                        ipaddress.ip_network("172.16.0.0/12"),
                        ipaddress.ip_network("192.168.0.0/16"),
                    ]
                    if net.version == 4 and any(net.overlaps(p) for p in private_nets):
                        rfc1918_ranges.append(f"{perim_name}: {cidr}")
                except ValueError:
                    pass

        if overly_broad:
            self._add(Finding(
                rule_id="OSAAS-NET-002",
                name=f"Network perimeters with overly broad CIDR ranges ({len(overly_broad)})",
                category="Network Security",
                severity="MEDIUM",
                file_path="IDCS /admin/v1/NetworkPerimeters",
                line_num=None,
                line_content=f"Broad CIDRs: {'; '.join(overly_broad[:5])}",
                description=(
                    f"{len(overly_broad)} network perimeter entry/entries use CIDR ranges "
                    "broader than /16 (IPv4) or /48 (IPv6). Overly broad ranges defeat "
                    "the purpose of IP-based access control."
                ),
                recommendation=(
                    "Narrow CIDR ranges to match actual corporate network allocations. "
                    "Use /24 or /16 ranges at most for IPv4."
                ),
                cwe="CWE-284",
            ))

        if rfc1918_ranges:
            self._add(Finding(
                rule_id="OSAAS-NET-010",
                name=f"Network perimeters include RFC1918 private ranges ({len(rfc1918_ranges)})",
                category="Network Security",
                severity="LOW",
                file_path="IDCS /admin/v1/NetworkPerimeters",
                line_num=None,
                line_content=f"Private ranges: {'; '.join(rfc1918_ranges[:5])}",
                description=(
                    f"{len(rfc1918_ranges)} network perimeter entry/entries include RFC1918 "
                    "private IP ranges (10.x, 172.16.x, 192.168.x). These ranges are not "
                    "routable on the internet and may not provide meaningful access control "
                    "for a cloud SaaS service."
                ),
                recommendation=(
                    "Review private IP ranges in network perimeters. If using VPN or "
                    "NAT, ensure the perimeter uses the public egress IP instead."
                ),
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # 3.1.3 Sign-On Policy Network  (OSAAS-NET-003, 007)
    # ----------------------------------------------------------
    def _check_sign_on_policy_network(self):
        self._vprint("  [check] Sign-on policy network restrictions \u2026")
        policies = self._idcs_get("SignOnPolicies")
        perimeters = self._idcs_get("NetworkPerimeters")

        has_admin_perimeter = False
        has_token_ip = False

        for pol in policies:
            status = pol.get("status", "").lower()
            if status != "active":
                continue
            rules = pol.get("rules", pol.get("signOnPolicyRules", []))
            for rule in rules:
                rule_status = rule.get("status", "active").lower()
                if rule_status != "active":
                    continue
                condition = rule.get("condition", rule.get("signOnCondition", {}))
                net_perim = condition.get("networkPerimeters",
                                         condition.get("clientIpAddress", []))
                groups = condition.get("groups", condition.get("memberOfGroups", []))

                group_names = []
                for g in groups:
                    if isinstance(g, dict):
                        group_names.append(g.get("value", g.get("display", "")).lower())
                    elif isinstance(g, str):
                        group_names.append(g.lower())

                is_admin = any(
                    n in ("identity domain administrators", "administrators",
                          "security administrators")
                    for n in group_names
                )

                if is_admin and net_perim:
                    has_admin_perimeter = True
                if net_perim and not groups:
                    has_token_ip = True

        # NET-003: No perimeter on admin sign-on
        if not has_admin_perimeter and perimeters:
            self._add(Finding(
                rule_id="OSAAS-NET-003",
                name="No network perimeter assigned to admin Sign-On Policy rules",
                category="Network Security",
                severity="HIGH",
                file_path="IDCS /admin/v1/SignOnPolicies",
                line_num=None,
                line_content="Admin rules have no networkPerimeters condition",
                description=(
                    "Network perimeters exist but are not referenced in Sign-On Policy "
                    "rules for administrator groups. Administrators can sign in from any "
                    "IP address."
                ),
                recommendation=(
                    "Add networkPerimeters conditions to admin-scoped Sign-On Policy rules "
                    "to restrict admin access to corporate IP ranges."
                ),
                cwe="CWE-284",
            ))

        # NET-007: Token endpoint not IP-restricted
        if not has_token_ip and perimeters:
            self._add(Finding(
                rule_id="OSAAS-NET-007",
                name="Token endpoint accessible without IP restriction",
                category="Network Security",
                severity="MEDIUM",
                file_path="IDCS /admin/v1/SignOnPolicies",
                line_num=None,
                line_content="No global IP restriction on token issuance",
                description=(
                    "Network perimeters exist but no Sign-On Policy rule applies IP "
                    "restrictions globally (without group scoping). OAuth token requests "
                    "can originate from any IP address."
                ),
                recommendation=(
                    "Create a default Sign-On Policy rule with networkPerimeters "
                    "condition to restrict authentication to known IP ranges."
                ),
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # 3.2 WAF & CORS  (OSAAS-NET-004, 005, 006)
    # ----------------------------------------------------------
    def _check_waf_configuration(self):
        self._vprint("  [check] WAF and CORS configuration \u2026")

        settings = self._idcs_get_single("Settings/Settings")
        if not settings:
            return

        # NET-004: WAF not configured (check for custom domains / CDN)
        custom_domains = settings.get("customBranding", settings.get("customEndpointUrl", ""))
        waf_enabled = settings.get("wafEnabled", settings.get("webApplicationFirewallEnabled", False))
        if not waf_enabled and not custom_domains:
            self._add(Finding(
                rule_id="OSAAS-NET-004",
                name="WAF not configured for Identity Domain endpoints",
                category="Network Security",
                severity="HIGH",
                file_path="IDCS /admin/v1/Settings",
                line_num=None,
                line_content="wafEnabled = false",
                description=(
                    "Web Application Firewall (WAF) is not enabled for the Identity Domain. "
                    "Without WAF, the IDCS login page and API endpoints are directly exposed "
                    "to automated attacks, credential stuffing, and DDoS."
                ),
                recommendation=(
                    "Enable OCI WAF in front of the Identity Domain. Configure WAF policies "
                    "with bot management, rate limiting, and OWASP protection rules."
                ),
                cwe="CWE-693",
            ))

        # NET-005: Permissive CORS
        allowed_origins = settings.get("allowedOrigins",
                                       settings.get("corsSettings", {}).get("allowedOrigins", []))
        if isinstance(allowed_origins, list):
            wildcard_origins = [o for o in allowed_origins if o in ("*", "http://*", "https://*")]
        elif isinstance(allowed_origins, str):
            wildcard_origins = ["*"] if "*" in allowed_origins else []
        else:
            wildcard_origins = []

        if wildcard_origins:
            self._add(Finding(
                rule_id="OSAAS-NET-005",
                name="CORS allows wildcard origins",
                category="Network Security",
                severity="MEDIUM",
                file_path="IDCS /admin/v1/Settings",
                line_num=None,
                line_content=f"allowedOrigins includes: {', '.join(wildcard_origins)}",
                description=(
                    "The Identity Domain allows cross-origin requests from wildcard (*) "
                    "origins. This permits any website to make authenticated API calls, "
                    "enabling cross-site data theft."
                ),
                recommendation=(
                    "Replace wildcard CORS origins with specific trusted domain names."
                ),
                cwe="CWE-942",
            ))

        # NET-006: IP filtering not enabled
        ip_filtering = settings.get("ipFilteringEnabled",
                                    settings.get("enableIPFiltering", False))
        if not ip_filtering:
            self._add(Finding(
                rule_id="OSAAS-NET-006",
                name="Identity Domain IP filtering not enabled",
                category="Network Security",
                severity="HIGH",
                file_path="IDCS /admin/v1/Settings",
                line_num=None,
                line_content="ipFilteringEnabled = false",
                description=(
                    "IP filtering is not enabled at the Identity Domain level. Without "
                    "IP filtering, all IP addresses can reach the authentication endpoints."
                ),
                recommendation=(
                    "Enable IP filtering in the Identity Domain settings and configure "
                    "allowed IP ranges via Network Perimeters."
                ),
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # 3.4 Session Settings  (OSAAS-NET-008, 009)
    # ----------------------------------------------------------
    def _check_session_settings(self):
        self._vprint("  [check] Session settings \u2026")
        settings = self._idcs_get_single("Settings/Settings")
        if not settings:
            return

        # NET-008: Session timeout too long
        session_duration = int(settings.get("sessionDuration",
                                            settings.get("maxSessionDurationInMinutes", 480)))
        if session_duration > 480:
            self._add(Finding(
                rule_id="OSAAS-NET-008",
                name=f"Session timeout too long: {session_duration} minutes",
                category="Session Security",
                severity="MEDIUM",
                file_path="IDCS /admin/v1/Settings",
                line_num=None,
                line_content=f"sessionDuration = {session_duration}",
                description=(
                    f"The Identity Domain session timeout is set to {session_duration} "
                    "minutes (> 8 hours). Long sessions increase the risk of session "
                    "hijacking and unattended terminal exploitation."
                ),
                recommendation=(
                    "Set session duration to 480 minutes (8 hours) or less. "
                    "Consider shorter durations for privileged users."
                ),
                cwe="CWE-613",
            ))

        # NET-009: Persistent sessions
        persistent = settings.get("persistentSessionEnabled",
                                  settings.get("enablePersistentSession", False))
        if persistent:
            self._add(Finding(
                rule_id="OSAAS-NET-009",
                name="Persistent sessions enabled (no re-authentication required)",
                category="Session Security",
                severity="HIGH",
                file_path="IDCS /admin/v1/Settings",
                line_num=None,
                line_content="persistentSessionEnabled = true",
                description=(
                    "Persistent sessions are enabled, allowing users to maintain "
                    "authenticated sessions across browser restarts without "
                    "re-authentication. This increases the risk of unauthorized access "
                    "from shared or compromised devices."
                ),
                recommendation=(
                    "Disable persistent sessions. Require re-authentication after "
                    "browser restart, especially for privileged users."
                ),
                cwe="CWE-613",
            ))

    # ==============================================================
    # Section 4: Logging and Monitoring  (10 checks)
    # ==============================================================

    # ----------------------------------------------------------
    # 4.1 Audit Configuration  (OSAAS-LOG-001..003, 005)
    # ----------------------------------------------------------
    def _check_audit_configuration(self):
        self._vprint("  [check] Audit configuration \u2026")

        # LOG-001: Fusion audit data export
        if self.fusion_url:
            audit_policies = self._fusion_get(
                f"{FUSION_FSCM}/auditPolicies",
            )
            if not audit_policies:
                self._add(Finding(
                    rule_id="OSAAS-LOG-001",
                    name="Fusion Cloud audit data export not configured",
                    category="Audit & Logging",
                    severity="HIGH",
                    file_path=f"Fusion {FUSION_FSCM}/auditPolicies",
                    line_num=None,
                    line_content="No audit policies found",
                    description=(
                        "No Fusion Cloud audit policies were found. Without audit policies, "
                        "security-relevant events (user access, configuration changes, data "
                        "modifications) are not being tracked."
                    ),
                    recommendation=(
                        "Configure audit policies in Fusion Cloud for critical business "
                        "objects. Navigate to Setup and Maintenance > Manage Audit Policies."
                    ),
                    cwe="CWE-778",
                ))

        # LOG-002: EPM audit
        if self.fusion_url:
            epm_audit = self._fusion_get(f"{EPM_BASE}/auditlog")
            if not epm_audit:
                self._add(Finding(
                    rule_id="OSAAS-LOG-002",
                    name="EPM Cloud audit data export not configured or accessible",
                    category="Audit & Logging",
                    severity="HIGH",
                    file_path=f"Fusion {EPM_BASE}/auditlog",
                    line_num=None,
                    line_content="No EPM audit logs returned",
                    description=(
                        "EPM Cloud audit logs could not be retrieved. EPM processes "
                        "sensitive financial data (budgets, forecasts, consolidations) "
                        "that requires comprehensive audit trails."
                    ),
                    recommendation=(
                        "Enable audit logging in EPM Cloud and configure data export "
                        "to OCI Object Storage or SIEM."
                    ),
                    cwe="CWE-778",
                ))

        # LOG-003: IDCS audit events
        settings = self._idcs_get_single("Settings/Settings")
        if settings:
            audit_enabled = settings.get("auditEnabled",
                                         settings.get("isAuditEnabled", True))
            if not audit_enabled:
                self._add(Finding(
                    rule_id="OSAAS-LOG-003",
                    name="IDCS audit events not enabled",
                    category="Audit & Logging",
                    severity="HIGH",
                    file_path="IDCS /admin/v1/Settings",
                    line_num=None,
                    line_content="auditEnabled = false",
                    description=(
                        "IDCS audit event logging is disabled. Authentication events, "
                        "user management operations, and security configuration changes "
                        "are not being recorded."
                    ),
                    recommendation=(
                        "Enable audit logging in the Identity Domain settings. "
                        "Ensure all event types are captured."
                    ),
                    cwe="CWE-778",
                ))

            # LOG-005: Audit retention period
            retention = int(settings.get("auditRetentionPeriod",
                                         settings.get("auditRetentionDays", 90)))
            if retention < 90:
                self._add(Finding(
                    rule_id="OSAAS-LOG-005",
                    name=f"Audit log retention period too short: {retention} days",
                    category="Audit & Logging",
                    severity="MEDIUM",
                    file_path="IDCS /admin/v1/Settings",
                    line_num=None,
                    line_content=f"auditRetentionPeriod = {retention}",
                    description=(
                        f"IDCS audit log retention is set to {retention} days, which is "
                        "below the recommended 90-day minimum. Short retention periods "
                        "may result in loss of forensic evidence during incident response."
                    ),
                    recommendation=(
                        "Set audit retention to at least 90 days. For compliance, "
                        "consider 365 days. Export logs to OCI Object Storage or "
                        "SIEM for long-term retention."
                    ),
                    cwe="CWE-778",
                ))

    # ----------------------------------------------------------
    # 4.2 SoD Monitoring  (OSAAS-LOG-004)
    # ----------------------------------------------------------
    def _check_sod_monitoring(self):
        self._vprint("  [check] Separation of Duties monitoring \u2026")
        if not self.fusion_url:
            return

        # Check for access certifications / SoD policies
        sod_policies = self._fusion_get(
            f"{FUSION_FSCM}/accessCertifications",
        )
        if not sod_policies:
            # Try alternative endpoint
            sod_policies = self._fusion_get(
                f"{FUSION_HCM}/segregationOfDutiesPolicies",
            )

        if not sod_policies:
            self._add(Finding(
                rule_id="OSAAS-LOG-004",
                name="No Separation of Duties (SoD) violation monitoring",
                category="Audit & Logging",
                severity="CRITICAL",
                file_path=f"Fusion {FUSION_FSCM}/accessCertifications",
                line_num=None,
                line_content="No SoD policies or access certifications found",
                description=(
                    "No Separation of Duties policies or access certification campaigns "
                    "were found. Without SoD monitoring, users may accumulate conflicting "
                    "roles (e.g., ability to create and approve payments) without detection, "
                    "enabling fraud."
                ),
                recommendation=(
                    "Configure SoD policies in Oracle Access Governance or Fusion Security "
                    "Console. Set up regular access certification campaigns to review "
                    "role assignments. Prioritize financial and procurement roles."
                ),
                cwe="CWE-284",
            ))

    # ----------------------------------------------------------
    # 4.3 Alerting  (OSAAS-LOG-006, 007, 008)
    # ----------------------------------------------------------
    def _check_alerting_configuration(self):
        self._vprint("  [check] Alerting configuration \u2026")

        settings = self._idcs_get_single("Settings/Settings")
        if not settings:
            return

        # LOG-006: Privileged operation alerts
        notification_enabled = settings.get("notificationsEnabled",
                                            settings.get("enableNotifications", False))
        admin_alert = settings.get("adminNotifications",
                                   settings.get("adminAlertEnabled", False))

        if not notification_enabled or not admin_alert:
            self._add(Finding(
                rule_id="OSAAS-LOG-006",
                name="No real-time alerting for privileged operations",
                category="Audit & Logging",
                severity="HIGH",
                file_path="IDCS /admin/v1/Settings",
                line_num=None,
                line_content=f"notificationsEnabled={notification_enabled}, adminNotifications={admin_alert}",
                description=(
                    "Real-time alerting for privileged operations (role changes, policy "
                    "modifications, user deactivation) is not fully enabled. Security "
                    "teams will not be notified of critical changes in real time."
                ),
                recommendation=(
                    "Enable notifications in Identity Domain settings. Configure admin "
                    "notification channels for security events. Integrate with your "
                    "SIEM or incident management platform."
                ),
                cwe="CWE-778",
            ))

        # LOG-007: Login failure monitoring
        login_fail_notify = settings.get("loginFailureNotificationEnabled",
                                         settings.get("enableLoginFailureNotification", False))
        if not login_fail_notify:
            self._add(Finding(
                rule_id="OSAAS-LOG-007",
                name="Login failure event monitoring not enabled",
                category="Audit & Logging",
                severity="HIGH",
                file_path="IDCS /admin/v1/Settings",
                line_num=None,
                line_content="loginFailureNotificationEnabled = false",
                description=(
                    "Login failure notifications are not enabled. Without monitoring "
                    "failed login attempts, brute-force and credential stuffing attacks "
                    "may go undetected."
                ),
                recommendation=(
                    "Enable login failure notifications and configure alerting thresholds. "
                    "Route alerts to your SOC or SIEM platform."
                ),
                cwe="CWE-778",
            ))

        # LOG-008: Security console audit trail (Fusion)
        if self.fusion_url:
            audit_trail = self._fusion_get(
                f"{FUSION_FSCM}/securityConsole/auditTrail",
            )
            if not audit_trail:
                self._add(Finding(
                    rule_id="OSAAS-LOG-008",
                    name="Security Console audit trail not enabled or accessible",
                    category="Audit & Logging",
                    severity="MEDIUM",
                    file_path=f"Fusion {FUSION_FSCM}/securityConsole/auditTrail",
                    line_num=None,
                    line_content="No audit trail data returned",
                    description=(
                        "Fusion Security Console audit trail could not be retrieved. "
                        "The Security Console tracks role assignments, user provisioning, "
                        "and data security changes."
                    ),
                    recommendation=(
                        "Ensure the Security Console audit trail is enabled and accessible "
                        "to the scanner's service account."
                    ),
                    cwe="CWE-778",
                ))

    # ----------------------------------------------------------
    # 4.4 Logging Integration  (OSAAS-LOG-009, 010)
    # ----------------------------------------------------------
    def _check_logging_integration(self):
        self._vprint("  [check] Logging integration \u2026")

        settings = self._idcs_get_single("Settings/Settings")
        if not settings:
            return

        # LOG-009: SIEM integration
        streaming_enabled = settings.get("auditStreamingEnabled",
                                         settings.get("enableAuditStreaming", False))
        webhook_url = settings.get("auditWebhookUrl",
                                   settings.get("webhookUrl", ""))

        if not streaming_enabled and not webhook_url:
            self._add(Finding(
                rule_id="OSAAS-LOG-009",
                name="No SIEM/OCI Logging integration for IDCS events",
                category="Audit & Logging",
                severity="MEDIUM",
                file_path="IDCS /admin/v1/Settings",
                line_num=None,
                line_content="auditStreamingEnabled = false, webhookUrl = (empty)",
                description=(
                    "IDCS audit events are not being streamed to an external SIEM or "
                    "OCI Logging Analytics. Without centralized logging, security events "
                    "across Oracle SaaS applications cannot be correlated with events "
                    "from other systems for threat detection."
                ),
                recommendation=(
                    "Configure IDCS audit event streaming to OCI Logging or your "
                    "enterprise SIEM. Use OCI Service Connector Hub to route events "
                    "to Splunk, Sentinel, or Chronicle."
                ),
                cwe="CWE-778",
            ))

        # LOG-010: Diagnostic logging level
        diag_level = (settings.get("diagnosticLevel",
                                   settings.get("logLevel", "WARNING")) or "WARNING").upper()
        log_levels = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
        if log_levels.get(diag_level, 2) > 2:
            self._add(Finding(
                rule_id="OSAAS-LOG-010",
                name=f"Diagnostic logging level set to {diag_level}",
                category="Audit & Logging",
                severity="LOW",
                file_path="IDCS /admin/v1/Settings",
                line_num=None,
                line_content=f"diagnosticLevel = {diag_level}",
                description=(
                    f"Diagnostic logging level is set to {diag_level}, which may miss "
                    "important warning-level events. A higher logging level reduces "
                    "visibility into operational and security issues."
                ),
                recommendation=(
                    "Set diagnostic logging level to WARNING or INFO for adequate "
                    "visibility during security monitoring."
                ),
                cwe="CWE-778",
            ))

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------
    def _add(self, finding: Finding):
        self.findings.append(finding)

    def _vprint(self, msg: str):
        if self.verbose:
            print(msg)

    def _warn(self, msg: str):
        print(f"  [!] {msg}", file=sys.stderr)

    # ----------------------------------------------------------
    # Reporting
    # ----------------------------------------------------------
    def summary(self) -> dict:
        counts = {s: 0 for s in self.SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_severity: str):
        threshold = self.SEVERITY_ORDER.get(min_severity, 4)
        self.findings = [
            f for f in self.findings
            if self.SEVERITY_ORDER.get(f.severity, 4) <= threshold
        ]

    def print_report(self):
        B, R = self.BOLD, self.RESET
        print(f"\n{B}{'='*72}{R}")
        print(f"{B}  Oracle SaaS Cloud SSPM Scanner v{VERSION}  --  Scan Report{R}")
        print(f"  Generated       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Identity Domain : {self._domain_name}")
        if self.fusion_url:
            print(f"  Fusion Cloud    : {self.fusion_url}")
        print(f"  Findings        : {len(self.findings)}")
        print(f"{B}{'='*72}{R}\n")

        if not self.findings:
            print("  [+] No issues found.\n")
            return

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.category, f.rule_id),
        )

        for f in sorted_findings:
            sev_color = self.SEVERITY_COLOR.get(f.severity, "")
            print(f"{sev_color}{B}[{f.severity}]{R}  {f.rule_id}  {f.name}")
            print(f"  Endpoint : {f.file_path}")
            print(f"  Context  : {f.line_content}")
            if f.cwe:
                print(f"  CWE      : {f.cwe}")
            if f.compliance:
                c = f.compliance
                parts = []
                if c.get("cis_oracle_saas"):
                    parts.append(f"CIS Oracle SaaS {c['cis_oracle_saas']}")
                if c.get("nist_800_53"):
                    parts.append(f"NIST {c['nist_800_53']}")
                if c.get("iso_27001"):
                    parts.append(f"ISO {c['iso_27001']}")
                if c.get("soc2"):
                    parts.append(f"SOC2 {c['soc2']}")
                print(f"  Compliance: {' | '.join(parts)}")
            print(f"  Issue    : {f.description}")
            print(f"  Fix      : {f.recommendation}")
            print()

        counts = self.summary()
        print(f"{B}{'='*72}{R}")
        print(f"{B}  SUMMARY{R}")
        print("=" * 72)
        for sev, _ in sorted(self.SEVERITY_ORDER.items(), key=lambda x: x[1]):
            color = self.SEVERITY_COLOR.get(sev, "")
            print(f"  {color}{sev:<10}{R}  {counts.get(sev, 0)}")
        print("=" * 72)

    def save_json(self, path: str):
        report = {
            "scanner": "oracle_saas_scanner",
            "version": VERSION,
            "generated": datetime.now().isoformat(),
            "idcs_url": self.idcs_url,
            "fusion_url": self.fusion_url,
            "domain_name": self._domain_name,
            "findings_count": len(self.findings),
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n[+] JSON report saved to: {os.path.abspath(path)}")

    def save_html(self, path: str):
        esc = html_mod.escape
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        counts = self.summary()

        sev_style = {
            "CRITICAL": "background:#c0392b;color:#fff",
            "HIGH":     "background:#e67e22;color:#fff",
            "MEDIUM":   "background:#2980b9;color:#fff",
            "LOW":      "background:#27ae60;color:#fff",
        }
        row_style = {
            "CRITICAL": "border-left:4px solid #c0392b",
            "HIGH":     "border-left:4px solid #e67e22",
            "MEDIUM":   "border-left:4px solid #2980b9",
            "LOW":      "border-left:4px solid #27ae60",
        }

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.category, f.rule_id),
        )

        chip_html = ""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            c = counts.get(sev, 0)
            st = sev_style[sev]
            chip_html += (
                f'<span style="{st};padding:4px 14px;border-radius:12px;'
                f'font-weight:bold;font-size:0.9em;margin:0 6px">'
                f'{esc(sev)}: {c}</span>'
            )

        rows_html = ""
        for i, f in enumerate(sorted_findings):
            bg = "#1e1e2e" if i % 2 == 0 else "#252535"
            rs = row_style.get(f.severity, "")
            st = sev_style.get(f.severity, "")
            rows_html += (
                f'<tr style="background:{bg};{rs}" '
                f'data-severity="{esc(f.severity)}" data-category="{esc(f.category)}">'
                f'<td style="padding:10px 14px">'
                f'<span style="{st};padding:3px 10px;border-radius:10px;'
                f'font-size:0.8em;font-weight:bold">{esc(f.severity)}</span></td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.9em">'
                f'{esc(f.rule_id)}</td>'
                f'<td style="padding:10px 14px;color:#a9b1d6">{esc(f.category)}</td>'
                f'<td style="padding:10px 14px;font-weight:bold;color:#cdd6f4">'
                f'{esc(f.name)}</td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.85em;'
                f'color:#89b4fa">{esc(f.file_path)}</td>'
                f'<td style="padding:10px 14px;font-family:monospace;font-size:0.82em;'
                f'color:#a6e3a1">{esc(f.line_content or "")}</td>'
                f'<td style="padding:10px 14px;color:#cdd6f4">{esc(f.cwe)}</td>'
                f'<td style="padding:10px 14px;font-size:0.82em;color:#f9e2af">'
                f'{esc(f.compliance.get("cis_oracle_saas", ""))}</td>'
                f'</tr>'
                f'<tr style="background:{bg}" data-severity="{esc(f.severity)}" '
                f'data-category="{esc(f.category)}">'
                f'<td colspan="8" style="padding:6px 14px 14px 14px">'
                f'<div style="color:#bac2de;font-size:0.88em;margin-bottom:4px">'
                f'<b>Issue:</b> {esc(f.description)}</div>'
                f'<div style="color:#89dceb;font-size:0.88em;margin-bottom:4px">'
                f'<b>Fix:</b> {esc(f.recommendation)}</div>'
                f'{"<div style=&quot;font-size:0.82em;color:#a6adc8&quot;><b>Compliance:</b> " + " &nbsp;|&nbsp; ".join(f"<span style=&quot;color:#f9e2af&quot;>{esc(k.upper().replace(chr(95),chr(32)))}</span>: {esc(v)}" for k,v in f.compliance.items()) + "</div>" if f.compliance else ""}'
                f'</td></tr>'
            )

        categories = sorted({f.category for f in self.findings})
        cat_options = "".join(
            f'<option value="{esc(c)}">{esc(c)}</option>' for c in categories
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Oracle SaaS Cloud SSPM Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1b2e; color: #cdd6f4; }}
  header {{ background: linear-gradient(135deg,#C74634 0%,#1a1b2e 100%);
            padding: 28px 36px; border-bottom: 2px solid #313244; }}
  header h1 {{ font-size: 1.7em; font-weight: 700; color: #fff; margin-bottom: 8px; }}
  header .meta {{ color: #f0d0ca; font-size: 0.95em; margin: 3px 0; }}
  .chips {{ padding: 20px 36px; background: #181825;
            border-bottom: 1px solid #313244;
            display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }}
  .chips label {{ color: #a6adc8; font-size: 0.9em; margin-right: 6px; }}
  .filters {{ padding: 16px 36px; background: #1e1e2e;
              display: flex; gap: 12px; flex-wrap: wrap;
              border-bottom: 1px solid #313244; }}
  .filters select, .filters input {{
    background: #313244; color: #cdd6f4;
    border: 1px solid #45475a; border-radius: 6px;
    padding: 6px 12px; font-size: 0.9em; }}
  .container {{ padding: 20px 36px 40px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.92em; }}
  th {{ background: #C74634; color: #fff; padding: 12px 14px;
        text-align: left; font-weight: 600; position: sticky; top: 0; }}
  tr:hover td {{ filter: brightness(1.1); }}
  td {{ vertical-align: top; }}
  .no-findings {{ text-align: center; padding: 60px;
                 color: #a6e3a1; font-size: 1.2em; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:10px;
            font-size:0.78em; font-weight:bold; margin-right:4px; }}
</style>
</head>
<body>
<header>
  <h1>Oracle SaaS Cloud SSPM Scan Report</h1>
  <p class="meta">Scanner: Oracle SaaS SSPM Scanner v{esc(VERSION)}</p>
  <p class="meta">Identity Domain: {esc(self._domain_name)}</p>
  {"<p class='meta'>Fusion Cloud: " + esc(self.fusion_url) + "</p>" if self.fusion_url else ""}
  <p class="meta">Generated: {esc(now)}</p>
  <p class="meta">Total Findings: <strong>{len(self.findings)}</strong></p>
</header>
<div class="chips">
  <label>Severity:</label>
  {chip_html}
</div>
<div class="filters">
  <select id="sevFilter" onchange="applyFilters()">
    <option value="">All Severities</option>
    <option>CRITICAL</option><option>HIGH</option>
    <option>MEDIUM</option><option>LOW</option>
  </select>
  <select id="catFilter" onchange="applyFilters()">
    <option value="">All Categories</option>
    {cat_options}
  </select>
  <input type="text" id="txtFilter" placeholder="Search \u2026"
         oninput="applyFilters()" style="flex:1;min-width:200px">
</div>
<div class="container">
{"<div class='no-findings'>No findings \u2014 tenant is clean!</div>" if not self.findings else f'''
<table id="ft">
<thead><tr>
  <th>Severity</th><th>Rule ID</th><th>Category</th><th>Finding</th>
  <th>Endpoint</th><th>Context</th><th>CWE</th><th>CIS Oracle SaaS</th>
</tr></thead>
<tbody>{rows_html}</tbody>
</table>'''}
</div>
<script>
function applyFilters(){{
  var sv=document.getElementById('sevFilter').value.toUpperCase();
  var ca=document.getElementById('catFilter').value.toLowerCase();
  var tx=document.getElementById('txtFilter').value.toLowerCase();
  document.querySelectorAll('#ft tbody tr').forEach(function(r){{
    var rs=(r.getAttribute('data-severity')||'').toUpperCase();
    var rc=(r.getAttribute('data-category')||'').toLowerCase();
    var rt=r.textContent.toLowerCase();
    r.style.display=(!sv||rs===sv)&&(!ca||rc.includes(ca))&&(!tx||rt.includes(tx))?'':'none';
  }});
}}
</script>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"\n[+] HTML report saved to: {os.path.abspath(path)}")


# ============================================================
# CLI entry point
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        prog="oracle_saas_scanner",
        description=(
            f"Oracle SaaS Cloud SSPM Scanner v{VERSION} \u2014 "
            "SaaS Security Posture Management for Oracle Fusion Cloud, "
            "EPM Cloud & IDCS / OCI IAM Identity Domains"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Authentication:\n"
            "  Primary:  OAuth 2.0 Client Credentials\n"
            "            --idcs-url, --client-id, --client-secret\n"
            "  Fallback: Basic Auth\n"
            "            --idcs-url, --username, --password\n\n"
            "Required IDCS Application Scopes (read-only):\n"
            "  urn:opc:idm:t.security.client   urn:opc:idm:t.users\n"
            "  urn:opc:idm:t.groups             urn:opc:idm:t.app.catalog\n"
            "  urn:opc:idm:t.user.me\n\n"
            "Required Fusion Cloud Role (read-only):\n"
            "  IT Security Manager (ORA_FND_IT_SECURITY_MANAGER_JOB)\n\n"
            "Environment variables:\n"
            "  ORACLE_IDCS_URL  ORACLE_FUSION_URL  ORACLE_CLIENT_ID\n"
            "  ORACLE_CLIENT_SECRET  ORACLE_USERNAME  ORACLE_PASSWORD"
        ),
    )

    # -- Connection --
    parser.add_argument(
        "--idcs-url",
        default=os.environ.get("ORACLE_IDCS_URL", ""),
        metavar="URL",
        help=(
            "IDCS / OCI IAM Identity Domain URL "
            "(e.g. https://idcs-abc123.identity.oraclecloud.com). "
            "Env: ORACLE_IDCS_URL"
        ),
    )
    parser.add_argument(
        "--fusion-url",
        default=os.environ.get("ORACLE_FUSION_URL", ""),
        metavar="URL",
        help=(
            "Oracle Fusion Cloud URL "
            "(e.g. https://myco.fa.us2.oraclecloud.com). "
            "Env: ORACLE_FUSION_URL  [optional — skip Fusion checks if omitted]"
        ),
    )

    # -- OAuth 2.0 --
    parser.add_argument(
        "--client-id",
        default=os.environ.get("ORACLE_CLIENT_ID", ""),
        metavar="ID",
        help="IDCS OAuth Client ID. Env: ORACLE_CLIENT_ID",
    )
    parser.add_argument(
        "--client-secret",
        default=os.environ.get("ORACLE_CLIENT_SECRET", ""),
        metavar="SECRET",
        help="IDCS OAuth Client Secret. Env: ORACLE_CLIENT_SECRET",
    )

    # -- Basic Auth fallback --
    parser.add_argument(
        "--username", "-u",
        default=os.environ.get("ORACLE_USERNAME", ""),
        metavar="USER",
        help="Username for Basic Auth (fallback). Env: ORACLE_USERNAME",
    )
    parser.add_argument(
        "--password", "-p",
        default=os.environ.get("ORACLE_PASSWORD", ""),
        metavar="PASS",
        help="Password for Basic Auth (fallback). Env: ORACLE_PASSWORD",
    )

    # -- Output --
    parser.add_argument(
        "--severity",
        default="LOW",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Minimum severity to report (default: LOW)",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save findings as JSON to FILE",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Save findings as self-contained HTML report to FILE",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output (API calls, skipped endpoints, etc.)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"oracle_saas_scanner v{VERSION}",
    )

    args = parser.parse_args()

    if not HAS_REQUESTS:
        parser.error(
            "The 'requests' library is required.\n"
            "  Install with:  pip install requests"
        )

    # Validation
    if not args.idcs_url:
        parser.error("--idcs-url is required (or set ORACLE_IDCS_URL env var)")

    has_oauth = args.client_id and args.client_secret
    has_basic = args.username and args.password
    if not has_oauth and not has_basic:
        parser.error(
            "Authentication required. Provide one of:\n"
            "  --client-id + --client-secret  (OAuth 2.0)\n"
            "  --username + --password        (Basic Auth)"
        )

    scanner = OracleSaaSScanner(
        idcs_url=args.idcs_url,
        fusion_url=args.fusion_url,
        client_id=args.client_id,
        client_secret=args.client_secret,
        username=args.username,
        password=args.password,
        verbose=args.verbose,
    )

    scanner.scan()
    scanner.filter_severity(args.severity)
    scanner.print_report()

    if args.json:
        scanner.save_json(args.json)
    if args.html:
        scanner.save_html(args.html)

    has_critical_high = any(
        f.severity in ("CRITICAL", "HIGH") for f in scanner.findings
    )
    sys.exit(1 if has_critical_high else 0)


if __name__ == "__main__":
    main()

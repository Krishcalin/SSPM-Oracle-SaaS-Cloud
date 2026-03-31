#!/usr/bin/env python3
"""Generate synthetic Oracle SaaS Cloud SSPM reports without live API connections."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oracle_saas_scanner import OracleSaaSScanner, Finding

def main():
    # Create scanner instance bypassing __init__
    scanner = OracleSaaSScanner.__new__(OracleSaaSScanner)
    scanner.idcs_url = "https://idcs-demo123.identity.oraclecloud.com"
    scanner.fusion_url = "https://demo-corp.fa.us2.oraclecloud.com"
    scanner.client_id = "demo-client-id"
    scanner.client_secret = "***"
    scanner.username = ""
    scanner.password = ""
    scanner.verbose = False
    scanner.findings = []
    scanner._token = ""
    scanner._token_expiry = None
    scanner._auth_mode = "demo"
    scanner._domain_name = "demo-corp-domain"
    scanner._api_errors = []

    # Inject synthetic findings across Oracle SaaS SSPM categories
    synthetic_findings = [
        # IDCS Password Policy
        Finding("ORA-PWD-001", "Password minimum length below 12 characters",
                "IDCS Password Policy", "HIGH",
                "/admin/v1/PasswordPolicies", None,
                "MinPasswordLength = 8 (recommended: >= 12)",
                "Weak password length requirement increases susceptibility to brute force attacks.",
                "Set minimum password length to 12 or more characters in IDCS password policy."),
        Finding("ORA-PWD-002", "Password complexity not requiring special characters",
                "IDCS Password Policy", "MEDIUM",
                "/admin/v1/PasswordPolicies", None,
                "RequiresSpecialChar = false",
                "Passwords without special characters are easier to crack.",
                "Enable special character requirement in IDCS password policy."),
        Finding("ORA-PWD-003", "Password history check insufficient",
                "IDCS Password Policy", "MEDIUM",
                "/admin/v1/PasswordPolicies", None,
                "PasswordHistoryCount = 3 (recommended: >= 12)",
                "Low password history allows users to cycle back to previously compromised passwords.",
                "Set password history to at least 12 previous passwords."),

        # MFA
        Finding("ORA-MFA-001", "MFA not enforced for all users",
                "Multi-Factor Authentication", "CRITICAL",
                "/admin/v1/SignOnPolicies", None,
                "MFA enforcement = Optional for 65% of users",
                "Without mandatory MFA, user accounts are vulnerable to credential-based attacks.",
                "Configure sign-on policy to require MFA for all users. Use TOTP or FIDO2."),
        Finding("ORA-MFA-002", "Admins without MFA enrollment",
                "Multi-Factor Authentication", "CRITICAL",
                "/admin/v1/Users?filter=groups.value eq \"Administrators\"", None,
                "Admins without MFA: admin.user@corp.com, security.admin@corp.com",
                "Privileged administrators without MFA are the highest-risk accounts.",
                "Enforce MFA enrollment for all admin accounts immediately."),
        Finding("ORA-MFA-003", "SMS as MFA factor allowed",
                "Multi-Factor Authentication", "MEDIUM",
                "/admin/v1/AuthenticationFactors", None,
                "SMS factor = Enabled",
                "SMS-based MFA is vulnerable to SIM swapping and interception attacks.",
                "Disable SMS as an MFA factor. Use TOTP, push notifications, or FIDO2 keys."),

        # SSO / SAML
        Finding("ORA-SSO-001", "No federated SSO configured",
                "SSO & Federation", "HIGH",
                "/admin/v1/IdentityProviders", None,
                "Federated IdPs = 0",
                "Without SSO federation, users rely on local IDCS passwords with no centralized authentication.",
                "Configure SAML/OIDC federation with your corporate identity provider."),
        Finding("ORA-SSO-002", "SAML response signature verification relaxed",
                "SSO & Federation", "HIGH",
                "/admin/v1/IdentityProviders", None,
                "ResponseSignatureRequired = false",
                "Not requiring signed SAML responses allows assertion manipulation.",
                "Enable SAML response signature verification for all federated IdPs."),

        # Sign-On Policies
        Finding("ORA-SOP-001", "No IP-based sign-on restrictions",
                "Sign-On Policies", "HIGH",
                "/admin/v1/NetworkPerimeters", None,
                "Network perimeters = 0",
                "No IP restrictions mean accounts can be accessed from any location.",
                "Configure network perimeters to restrict sign-on to corporate IPs or VPN ranges."),
        Finding("ORA-SOP-002", "No risk-based sign-on policy",
                "Sign-On Policies", "MEDIUM",
                "/admin/v1/SignOnPolicies", None,
                "RiskBasedPolicy = Not configured",
                "Without adaptive risk-based policies, anomalous sign-ins are not challenged.",
                "Enable adaptive authentication with risk scoring in sign-on policies."),

        # OAuth Clients
        Finding("ORA-OAUTH-001", "OAuth clients with overly broad scopes",
                "OAuth Client Security", "HIGH",
                "/admin/v1/Apps?filter=isOAuthClient eq true", None,
                "Clients with admin scopes: 3 (DataExport-App, LegacySync, TestApp)",
                "OAuth clients with admin-level scopes can perform privileged operations.",
                "Review OAuth client scopes. Apply least-privilege scoping."),
        Finding("ORA-OAUTH-002", "OAuth client secrets older than 90 days",
                "OAuth Client Security", "MEDIUM",
                "/admin/v1/Apps", None,
                "Stale client secrets: 5 apps with secrets > 90 days old",
                "Long-lived client secrets increase risk of credential compromise.",
                "Rotate OAuth client secrets every 90 days. Implement automated rotation."),

        # Privileged Groups
        Finding("ORA-PRIV-001", "Excessive Identity Domain Administrators",
                "Privileged Access", "HIGH",
                "/admin/v1/Groups?filter=displayName eq \"Identity Domain Administrators\"", None,
                "Identity Domain Admins: 12 members (recommended: <= 5)",
                "Excessive privileged group membership increases the blast radius of compromised accounts.",
                "Reduce Identity Domain Administrator members. Use role-specific groups."),
        Finding("ORA-PRIV-002", "Service accounts in privileged groups",
                "Privileged Access", "MEDIUM",
                "/admin/v1/Groups", None,
                "Service accounts in admin groups: svc_integration, svc_bi_export",
                "Service accounts in admin groups have excessive persistent privileges.",
                "Create dedicated service roles with minimum required permissions."),

        # User Lifecycle
        Finding("ORA-USER-001", "Stale user accounts (no login > 90 days)",
                "User Lifecycle", "MEDIUM",
                "/admin/v1/Users", None,
                "Stale users: 23 accounts with last login > 90 days ago",
                "Stale accounts are prime targets for credential-based attacks.",
                "Implement automated user lifecycle management. Disable accounts after 90 days of inactivity."),
        Finding("ORA-USER-002", "Deactivated users with active sessions",
                "User Lifecycle", "HIGH",
                "/admin/v1/UserStatusChanger", None,
                "Deactivated users with tokens: 3",
                "Deactivated users may retain active OAuth tokens allowing continued access.",
                "Revoke all tokens when deactivating users. Implement token lifecycle management."),

        # Session Settings
        Finding("ORA-SESS-001", "Session timeout exceeds 30 minutes",
                "Session Management", "MEDIUM",
                "/admin/v1/Settings/SessionSettings", None,
                "SessionTimeout = 120 minutes (recommended: <= 30)",
                "Long session timeouts increase risk of session hijacking on shared devices.",
                "Set session timeout to 30 minutes or less."),

        # Audit
        Finding("ORA-AUDIT-001", "Audit event export not configured",
                "Audit & Monitoring", "HIGH",
                "/admin/v1/AuditEvents", None,
                "Audit export = Not configured",
                "Without audit log export, forensic investigation and compliance monitoring are limited.",
                "Configure audit event streaming to a SIEM (Splunk, QRadar, Sentinel)."),
        Finding("ORA-AUDIT-002", "Admin audit trail not reviewed in 30+ days",
                "Audit & Monitoring", "MEDIUM",
                "/admin/v1/AuditEvents?filter=eventType eq \"AdminAction\"", None,
                "Last admin audit review: 45 days ago",
                "Infrequent audit review delays detection of unauthorized administrative actions.",
                "Establish weekly admin audit review process with automated alerting."),

        # Fusion Cloud
        Finding("ORA-FUSION-001", "Custom roles with excessive privileges",
                "Fusion Cloud Security", "HIGH",
                "/fscmRestApi/resources/latest/roles", None,
                "Over-privileged custom roles: 4 with > 50 privileges each",
                "Custom roles with excessive privileges violate least-privilege principles.",
                "Review and reduce privileges in custom roles to minimum required."),
        Finding("ORA-FUSION-002", "Implementation project still active in production",
                "Fusion Cloud Security", "MEDIUM",
                "/fscmRestApi/resources/latest/setupConfigurations", None,
                "Active implementation projects in PROD: 2",
                "Active implementation projects in production may expose configuration changes to unvetted users.",
                "Close or archive implementation projects after go-live."),

        # Network Perimeters
        Finding("ORA-NET-001", "No IP allowlist for admin console",
                "Network Security", "HIGH",
                "/admin/v1/NetworkPerimeters", None,
                "Admin console IP restriction = None",
                "The admin console is accessible from any IP address.",
                "Configure network perimeters to restrict admin console access to corporate IPs."),
    ]

    scanner.findings = synthetic_findings

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(out_dir, exist_ok=True)

    json_path = os.path.join(out_dir, "oracle_saas_sspm_report.json")
    html_path = os.path.join(out_dir, "oracle_saas_sspm_report.html")

    scanner.print_report()
    scanner.save_json(json_path)
    scanner.save_html(html_path)

    print(f"\n[+] Total findings: {len(scanner.findings)}")
    counts = scanner.summary()
    for sev, count in counts.items():
        print(f"    {sev}: {count}")

if __name__ == "__main__":
    main()

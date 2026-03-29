# CLAUDE.md -- Oracle SaaS Cloud SSPM Scanner

## Project Overview

A Python-based SaaS Security Posture Management (SSPM) scanner for Oracle Fusion Cloud, EPM Cloud, and Oracle IDCS / OCI IAM Identity Domains. Performs live REST API security assessment against the **CIS Oracle Cloud Infrastructure SaaS Cloud Applications Benchmark v1.0.0**, with mapping to NIST 800-53 Rev 5, ISO 27001:2022, and SOC 2 Type II.

**Repository**: https://github.com/Krishcalin/SSPM-Oracle-SaaS-Cloud
**License**: MIT
**Python**: 3.8+ (requires `requests`)
**Version**: 1.0.0

## Repository Structure

```
SSPM-Oracle-SaaS-Cloud/
├── oracle_saas_scanner.py    # Main scanner (single file, 2,872 lines)
├── requirements.txt          # requests>=2.28.0
├── docs/
│   └── banner.svg            # Project banner
├── LICENSE
├── CLAUDE.md
└── README.md
```

## Architecture

```
oracle_saas_scanner.py
  ├─ VERSION, COMPLIANCE_MAP (55 entries)
  ├─ Finding class (__slots__)
  ├─ OracleSaaSScanner class
  │    ├─ __init__(idcs_url, fusion_url, client_id, client_secret, ...)
  │    ├─ scan()                        # Entry point, calls all check groups
  │    ├─ _authenticate()               # OAuth 2.0 + Basic Auth fallback
  │    ├─ _idcs_get/single()            # SCIM pagination
  │    ├─ _fusion_get/single()          # REST offset/limit pagination
  │    ├─ Section 1: 8 check methods    # 22 IAM findings
  │    ├─ Section 2: 5 check methods    # 13 CFG findings
  │    ├─ Section 3: 4 check methods    # 10 NET findings
  │    ├─ Section 4: 4 check methods    # 10 LOG findings
  │    ├─ _add(), _vprint(), _warn()    # Helpers
  │    ├─ summary(), filter_severity()
  │    ├─ print_report()                # ANSI console
  │    ├─ save_json()                   # JSON export
  │    └─ save_html()                   # HTML dashboard (#C74634)
  └─ main()                             # argparse CLI

Total: 55 checks, 21 check methods, 4 CIS sections
```

## API Endpoints Used

### IDCS / OCI IAM Identity Domains (`/admin/v1/`)

| Endpoint | Check Methods | Findings |
|----------|--------------|----------|
| `PasswordPolicies` | `_check_password_policies` | IAM-001..009 |
| `SignOnPolicies` | `_check_mfa_enforcement`, `_check_admin_access_restrictions`, `_check_sign_on_policy_network` | IAM-010..012, 020, 022, NET-003, 007 |
| `AuthenticationFactorSettings` | `_check_mfa_enforcement` | IAM-012 |
| `IdentityProviders` | `_check_sso_configuration` | IAM-013 |
| `Apps` | `_check_oauth_clients` | IAM-014, 015 |
| `Groups` | `_check_privileged_roles_idcs` | IAM-016 |
| `Users` | `_check_user_lifecycle` | IAM-018, 019 |
| `NetworkPerimeters` | `_check_network_perimeters` | NET-001, 002, 010 |
| `Settings/Settings` | `_check_admin_access_restrictions`, `_check_waf_configuration`, `_check_session_settings`, `_check_audit_configuration`, `_check_alerting_configuration`, `_check_logging_integration` | IAM-021, NET-004..009, LOG-003, 005..010 |

### Oracle Fusion Cloud REST APIs

| Endpoint | Check Methods | Findings |
|----------|--------------|----------|
| `fscmRestApi/.../setupMaintenanceAuditPolicies` | `_check_config_change_monitoring` | CFG-001 |
| `fscmRestApi/.../tasksAndFlows` | `_check_config_change_monitoring` | CFG-004 |
| `fscmRestApi/.../sandboxes` | `_check_config_change_monitoring`, `_check_scheduled_processes` | CFG-005, 013 |
| `hcmRestApi/.../roles` | `_check_custom_roles` | CFG-002, 003 |
| `hcmRestApi/.../dataSecurityPolicies` | `_check_data_security_policies` | CFG-007 |
| `hcmRestApi/.../securityProfiles` | `_check_data_security_policies` | CFG-008 |
| `fscmRestApi/.../descriptiveFlexfields` | `_check_data_security_policies` | CFG-006 |
| `fscmRestApi/.../erpintegrations` | `_check_scheduled_processes` | CFG-011 |
| `hcmRestApi/.../users` | `_check_scheduled_processes` | CFG-012 |
| `fscmRestApi/.../implementationProjects` | `_check_implementation_projects` | CFG-010 |
| `hcmRestApi/.../userRoleAssignments` | `_check_privileged_roles_fusion` | IAM-017 |
| `fscmRestApi/.../auditPolicies` | `_check_audit_configuration` | LOG-001 |
| `fscmRestApi/.../accessCertifications` | `_check_sod_monitoring` | LOG-004 |
| `fscmRestApi/.../securityConsole/auditTrail` | `_check_alerting_configuration` | LOG-008 |
| `interop/rest/v3/applicationsnapshots` | `_check_scheduled_processes` | CFG-009 |
| `interop/rest/v3/auditlog` | `_check_audit_configuration` | LOG-002 |

## Check Inventory (55 checks across 4 CIS sections)

| Section | Category | Check IDs | Count |
|---------|----------|-----------|-------|
| 1 | Password Policy | OSAAS-IAM-001..009 | 9 |
| 1 | MFA | OSAAS-IAM-010..012, 022 | 4 |
| 1 | SSO | OSAAS-IAM-013 | 1 |
| 1 | OAuth | OSAAS-IAM-014..015 | 2 |
| 1 | Privileged Access | OSAAS-IAM-016..017 | 2 |
| 1 | User Lifecycle | OSAAS-IAM-018..019 | 2 |
| 1 | Access Restrictions | OSAAS-IAM-020..021 | 2 |
| 2 | Config Management | OSAAS-CFG-001..013 | 13 |
| 3 | Network Security | OSAAS-NET-001..010 | 10 |
| 4 | Audit & Logging | OSAAS-LOG-001..010 | 10 |

## Key Classes

### Finding

```python
class Finding:
    __slots__ = ("rule_id", "name", "category", "severity",
                 "file_path", "line_num", "line_content",
                 "description", "recommendation", "cwe", "cve",
                 "compliance")
```

- `file_path` is repurposed as the API endpoint
- `line_content` is repurposed as the setting value context
- `compliance` is auto-populated from `COMPLIANCE_MAP`

### OracleSaaSScanner

- `__init__(idcs_url, fusion_url, client_id, client_secret, username, password, verbose)`
- `scan()` — entry point, calls authenticate then all check groups
- `filter_severity(min_severity)` — filters findings list
- `print_report()` — ANSI colored console output
- `save_json(path)` — JSON report with metadata
- `save_html(path)` — Self-contained HTML with Oracle #C74634 branding

## Conventions

### Authentication
- OAuth 2.0 Client Credentials via IDCS token endpoint (`/oauth2/v1/token`)
- Scope: `urn:opc:idm:__myscopes__` (grants all admin-configured scopes)
- Token auto-refresh on expiry via `_ensure_token()`
- Basic Auth fallback using `requests.auth.HTTPBasicAuth`

### IDCS SCIM Pagination
- Uses `startIndex` (1-based), `count`, `totalResults`
- Response: `{"Resources": [...], "totalResults": N}`

### Fusion REST Pagination
- Uses `offset`, `limit`, `hasMore`
- Response: `{"items": [...], "hasMore": bool}`

### Graceful Degradation
- IDCS-only mode when `--fusion-url` not provided (skips all CFG checks)
- Per-endpoint graceful failure: 403/404 logs warning and continues
- Rate limiting: handles HTTP 429 with Retry-After header

### Severity Levels
- **CRITICAL** — immediate risk, MFA bypass, SoD gaps
- **HIGH** — significant risk, missing SSO/WAF, excessive privileges
- **MEDIUM** — moderate risk, weak passwords, stale accounts
- **LOW** — informational, RFC1918 ranges, stale projects

### Rule ID Format
- `OSAAS-{SECTION}-{NNN}` where SECTION is IAM, CFG, NET, or LOG

### HTML Report
- Oracle red `#C74634` header gradient and table headers
- Catppuccin Mocha dark theme (`#1a1b2e` bg)
- Client-side severity/category/text filtering via JavaScript
- Self-contained (no external CSS/JS dependencies)

## CLI Reference

```bash
# IDCS-only mode
python oracle_saas_scanner.py --idcs-url URL --client-id ID --client-secret SECRET

# Full mode (IDCS + Fusion)
python oracle_saas_scanner.py --idcs-url URL --fusion-url URL --client-id ID --client-secret SECRET

# With reports
python oracle_saas_scanner.py --idcs-url URL --client-id ID --client-secret SECRET \
    --html report.html --json report.json --severity HIGH

# Basic Auth fallback
python oracle_saas_scanner.py --idcs-url URL --username USER --password PASS
```

## Development Guidelines

### Adding a New Check

1. Add the rule ID to `COMPLIANCE_MAP` with all four framework mappings
2. Add check logic in the appropriate `_check_*` method
3. Use `self._add(Finding(...))` to emit findings
4. Follow the rule ID pattern: `OSAAS-{SECTION}-{NNN}`
5. Include: `rule_id`, `name`, `category`, `severity`, `file_path` (API endpoint), `line_content` (context), `description`, `recommendation`, `cwe`

### Adding a New API Endpoint

1. Use `self._idcs_get(path)` for IDCS endpoints (SCIM pagination)
2. Use `self._fusion_get(path)` for Fusion endpoints (offset/limit)
3. Handle 403/404 gracefully (log warning, continue)
4. Handle 429 with rate limit retry

## Related Projects

| Project | Repo |
|---------|------|
| OCI CNAPP Security Scanner | [OCI-CNAPP-Security-Scanner](https://github.com/Krishcalin/OCI-CNAPP-Security-Scanner) |
| Microsoft 365 SSPM | [SSPM-O365](https://github.com/Krishcalin/SSPM-O365) |
| ServiceNow SSPM | [SSPM-ServiceNow](https://github.com/Krishcalin/SSPM-ServiceNow) |
| SAP SuccessFactors SSPM | [SAP-SuccessFactors](https://github.com/Krishcalin/SAP-SuccessFactors) |
| Oracle EBS Security Audit | [Oracle-EBS-Security-Audit](https://github.com/Krishcalin/Oracle-EBS-Security-Audit) |

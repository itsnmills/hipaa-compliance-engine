# Evidence File Templates

These templates show the exact JSON/CSV formats the HIPAA Compliance Engine expects for each check module. Copy the relevant template, fill in your organization's data, and point `config.yaml` to the file.

## How to Use

1. Copy the template file for the check you want to configure
2. Replace placeholder values with your organization's real data
3. Save the file somewhere on your machine
4. Update `config.yaml` with the file path under the `evidence:` section

## Template Files

| Template | Config Key | Description |
|----------|-----------|-------------|
| `mfa_config_template.json` | `mfa_config` | MFA enforcement status from your identity provider |
| `encryption_status_template.json` | `encryption_status` | Encryption status across endpoints, databases, and TLS |
| `vulnerability_scans_template.json` | `vulnerability_scans` | Vulnerability scan results (Nessus/Qualys/OpenVAS format) |
| `pentest_report_template.json` | `pentest_reports` | Penetration test findings and remediation status |
| `network_topology_template.json` | `network_topology` | Network segments, firewall rules, and lateral movement risks |
| `access_controls_template.json` | `access_controls` | User accounts, roles, shared accounts, and RBAC config |
| `audit_logs_template.json` | `audit_logs` | SIEM configuration, log sources, and retention status |
| `ir_plan_template.json` | `ir_plan` | Incident response plan details and test history |
| `backup_status_template.json` | `backup_status` | Backup jobs, DR plan, and restore test results |
| `asset_inventory_template.json` | `asset_inventory` | Technology asset inventory with ePHI classification |
| `asset_inventory_template.csv` | `asset_inventory` | CSV alternative for asset inventory |
| `ba_agreements_template.json` | `ba_agreements` | Business associate agreement tracking |
| `workforce_roster_template.json` | `workforce_roster` | Staff roster, training records, and termination procedures |
| `workforce_roster_template.csv` | `workforce_roster` | CSV alternative for workforce roster |
| `policy_documents_template.json` | `policies_dir` | Policy document manifest (or point to a directory of files) |
| `patch_status_template.json` | `patch_status` | Patch compliance status per system |

## CSV Format Notes

For `asset_inventory` and `workforce_roster`, you can provide either JSON or CSV. CSV files must include a header row with the column names shown in the template.

## Directory Mode (Policy Documents)

Instead of creating a JSON manifest, you can point `policies_dir` in `config.yaml` to a directory containing your actual policy documents (`.pdf`, `.docx`, `.doc`, `.md`, `.txt`). The engine will scan the directory for expected policy filenames and check modification dates for recency.

Expected policy filenames (any supported extension):
- `risk_analysis.*` or `risk_management.*`
- `access_control.*`
- `security_awareness_training.*`
- `incident_response.*` or `ir_plan.*`
- `contingency_plan.*` or `disaster_recovery.*`
- `business_associate.*` or `baa_management.*`
- `encryption.*`
- `audit_log.*` or `audit_controls.*`
- `physical_security.*` or `facility_access.*`
- `sanction.*` or `sanctions.*`
- `workforce_security.*`
- `media_disposal.*` or `device_media.*`
- `patch_management.*`
- `network_segmentation.*`

## Getting Data from Your Tools

### Nessus
Export scan results as JSON from Nessus Professional or Nessus Essentials. The engine parses the standard Nessus JSON export format.

### Azure AD / Entra ID
Export user and MFA status via Microsoft Graph API or the Entra admin portal. Include conditional access policy status.

### SIEM (Wazuh, Splunk, etc.)
Export agent status and log source configuration. The engine checks agent connectivity and log retention settings.

### Backup Tools (Veeam, Datto, etc.)
Export backup job status including last run time, success/failure, and size. Include DR test results.

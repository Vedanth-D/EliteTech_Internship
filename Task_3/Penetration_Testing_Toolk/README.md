# NetAudit: Modular Security Audit & Asset Inventory Framework

NetAudit is a Python-based security posture and network asset auditing framework designed around an **Asset & Vulnerability Graph architecture**.

## Key Features

- **Graph-Based Context Engine**: Maintains an internal graph model linking targets, open TCP services, protocol versions, and vulnerability findings into a unified context.
- **ScopeGuard Protection**: Built-in IP/CIDR authorization filter to prevent out-of-scope auditing.
- **Modular Plugin Architecture**: Clean plugin interfaces for Discovery, Auditing, and Reporting.
- **Auditors Included**:
  - `HostSweepCollector`: Active subnet discovery & service port inspection.
  - `ServiceBannerAuditor`: Software header inspection & information disclosure auditing.
  - `TLSCipherAuditor`: SSL/TLS version, certificate validity, and weak cipher suite evaluation.
  - `SSHPolicyAuditor`: SSH protocol baseline and configuration compliance check.
- **Executive Reporting**: Automated output of structured Markdown reports and self-contained HTML dashboards.

## Installation & Setup

1. Clone or navigate to the repository directory.
2. Install optional requirements (for enhanced CLI formatting):
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Run Security Audit Against Authorized Target IPs / CIDRs
```bash
python main.py -t 127.0.0.1 192.168.1.0/24 --md-report audit.md --html-report audit.html
```

### Options
- `-t`, `--target`: Space-separated target IP addresses or CIDR blocks authorized for scanning (e.g. `127.0.0.1 10.0.0.0/24`).
- `-p`, `--ports`: Optional custom list of TCP ports (e.g., `-p 80 443 22 8080`).
- `--md-report`: Output file path for Markdown executive report (default: `audit_report.md`).
- `--html-report`: Output file path for HTML dashboard (default: `audit_report.html`).
- `-v`, `--verbose`: Enable debug logging.

## Running Unit Tests

```bash
python -m unittest discover -s tests
```

## Extending NetAudit (Writing Custom Plugins)

Create a custom module subclassing `BaseModule`:

```python
from netaudit.modules.base import BaseModule
from netaudit.core.graph import AssetGraph
from netaudit.core.models import Finding, RiskLevel

class CustomHeaderAuditor(BaseModule):
    name = "custom_header_auditor"
    category = "audit"

    def run(self, graph: AssetGraph) -> None:
        for ip, host in graph.hosts.items():
            # Module logic here
            pass
```

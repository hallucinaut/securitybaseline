# securitybaseline - Security Baseline Compliance Engine

[![Go](https://img.shields.io/badge/Go-1.21-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Automated security baseline compliance checking and reporting.**

Validate configurations against industry security baselines (CIS, NIST, DISA, PCI-DSS).

## 🚀 Features

- **Multiple Frameworks**: Support for CIS Benchmarks, NIST 800-53, CIS Controls, DISA STIG
- **Automated Checks**: Run baseline compliance checks
- **Compliance Reporting**: Generate detailed compliance reports
- **Cross-Framework Mapping**: Map controls across frameworks
- **Score Tracking**: Calculate compliance scores

## 📦 Installation

### Build from Source

```bash
git clone https://github.com/hallucinaut/securitybaseline.git
cd securitybaseline
go build -o securitybaseline ./cmd/securitybaseline
sudo mv securitybaseline /usr/local/bin/
```

### Install via Go

```bash
go install github.com/hallucinaut/securitybaseline/cmd/securitybaseline@latest
```

## 🎯 Usage

### List Baselines

```bash
# List available security baselines
securitybaseline list
```

### Run Checks

```bash
# Run baseline compliance checks
securitybaseline check
```

### Check Compliance

```bash
# Check compliance status
securitybaseline compliance
```

### Generate Report

```bash
# Generate compliance report
securitybaseline report
```

### Programmatic Usage

```go
package main

import (
    "fmt"
    "github.com/hallucinaut/securitybaseline/pkg/baseline"
    "github.com/hallucinaut/securitybaseline/pkg/compliance"
)

func main() {
    // Create baseline engine
    engine := baseline.NewBaselineEngine()
    
    // Add baselines
    commonBaselines := baseline.CreateCommonBaselines()
    for _, base := range commonBaselines {
        engine.AddBaseline(base)
    }
    
    // Get baselines by framework
    cisBaselines := engine.GetBaselinesByBaseline(baseline.CISBenchmark)
    fmt.Printf("CIS Baselines: %d\n", len(cisBaselines))
    
    // Run checks
    check := baseline.BaselineCheck{
        ID:       "chk-001",
        ControlID: "cis-win-1.1",
        Expected: "compliant",
        Actual:   "compliant",
    }
    result := engine.RunCheck(check)
    fmt.Printf("Check Status: %s\n", result.Status)
    
    // Check compliance
    checker := compliance.NewComplianceChecker()
    report := checker.CreateReport("CIS Benchmarks", "8.0")
    checker.AddCheck(report.ID, compliance.ComplianceCheck{
        ID:        "chk-001",
        Name:      "Password Policy",
        Requirement: "Passwords must be 14+ characters",
        Status:    compliance.StatusCompliant,
    })
    
    fmt.Printf("Compliance Score: %.1f%%\n", report.Score)
}
```

## 📚 Supported Frameworks

### CIS Benchmarks
- Windows 10/11
- Linux (Ubuntu, RHEL, CentOS)
- AWS
- Azure
- Kubernetes
- SQL Server

### NIST Standards
- NIST SP 800-53 (Rev 5)
- NIST SP 800-171
- NIST CSF

### CIS Controls v8
- Inventory and Control
- Asset Management
- Access Control
- Audit and Monitoring

### DISA STIGs
- Windows Server
- RHEL
- Security technical implementation guides

### PCI-DSS
- Network security
- Data protection
- Access control

## 🧪 Baseline Structure

Each baseline includes:
- **Controls**: Specific security requirements
- **Categories**: Network, Host, Application, Data, Identity
- **Severity**: Critical, High, Medium, Low
- **Remediation**: How to fix non-compliance
- **References**: Documentation links
- **Cross-References**: Map to other frameworks

## 🏗️ Architecture

```
securitybaseline/
├── cmd/
│   └── securitybaseline/
│       └── main.go          # CLI entry point
├── pkg/
│   ├── baseline/
│   │   ├── baseline.go     # Baseline definitions
│   │   └── baseline_test.go # Unit tests
│   └── compliance/
│       ├── compliance.go   # Compliance checking
│       └── compliance_test.go # Unit tests
└── README.md
```

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test -v ./pkg/baseline -run TestCreateCommonBaselines
```

## 📋 Example Output

```
$ securitybaseline list

Security Baselines
==================

Total Active Baselines: 3

Available Baselines:

[1] CIS Benchmarks
    ID: base-001
    Framework: cis
    Version: 8.0
    Target Systems: [Windows Linux AWS Azure Kubernetes]
    Controls: 3
    Compliance: [NIST-800-53 PCI-DSS]

[2] NIST 800-53 Controls
    ID: base-002
    Framework: nist_800_53
    Version: Rev 5
    Target Systems: [Cloud On-Premises Hybrid]
    Controls: 2
    Compliance: [FedRAMP FISMA]
```

## 🔒 Security Use Cases

- **Compliance Audits**: Check compliance with security frameworks
- **Security Assessments**: Evaluate security posture
- **Baseline Configuration**: Establish security baselines
- **Continuous Monitoring**: Ongoing compliance tracking
- **Audit Preparation**: Generate compliance evidence

## 🛡️ Best Practices

1. **Baseline your environment** - Establish baseline security configuration
2. **Automate compliance checks** - Run regularly
3. **Track compliance scores** - Monitor over time
4. **Prioritize critical controls** - Focus on high-risk areas
5. **Document exceptions** - Justify deviations
6. **Regular reviews** - Update baselines regularly

## 📄 License

MIT License

## 🙏 Acknowledgments

- CIS (Center for Internet Security)
- NIST (National Institute of Standards and Technology)
- DISA (Defense Information Systems Agency)
- Security compliance community

## 🔗 Resources

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [CIS Controls](https://www.cisecurity.org/controls)
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [DISA STIGs](https://siem.disa.mil/stigs/)
- [PCI-DSS](https://www.pcisecuritystandards.org/)

---

**build with GPU by [hallucinaut](https://github.com/hallucinaut)**
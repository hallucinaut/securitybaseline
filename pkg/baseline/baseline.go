// Package baseline provides security baseline management.
package baseline

import (
	"fmt"
	"time"
)

// BaselineFramework represents a security baseline framework.
type BaselineFramework string

const (
	CISBenchmark    BaselineFramework = "cis"
	CISControls     BaselineFramework = "cis_controls"
	NIST80053       BaselineFramework = "nist_800_53"
	NIST800171      BaselineFramework = "nist_800_171"
	DISA            BaselineFramework = "disa"
	PCI_DSS         BaselineFramework = "pci_dss"
	ISO27001        BaselineFramework = "iso_27001"
	SOC2            BaselineFramework = "soc2"
)

// ControlCategory represents a control category.
type ControlCategory string

const (
	CategoryNetwork    ControlCategory = "network"
	CategoryHost       ControlCategory = "host"
	CategoryApplication ControlCategory = "application"
	CategoryData       ControlCategory = "data"
	CategoryIdentity   ControlCategory = "identity"
)

// SecurityBaseline represents a security baseline.
type SecurityBaseline struct {
	ID              string
	Name            string
	Source          BaselineFramework
	Version         string
	Description     string
	Controls        []BaselineControl
	TargetSystems   []string
	Compliance      []string
	LastUpdated     time.Time
	Active          bool
}

// BaselineControl represents a control in the baseline.
type BaselineControl struct {
	ID            string
	Name          string
	Description   string
	Category      ControlCategory
	Severity      string
	Status        string // PASS, FAIL, WARN, N/A
	RiskLevel     string
	Remediation   string
	References    []string
	CrossReference []string
}

// BaselineEngine manages security baselines.
type BaselineEngine struct {
	baselines []SecurityBaseline
	checks    []BaselineCheck
	results   []CheckResult
}

// BaselineCheck represents a baseline check.
type BaselineCheck struct {
	ID           string
	ControlID    string
	BaselineID   string
	CheckType    string
	Command      string
	Expected     string
	Actual       string
	Status       string
	Message      string
}

// CheckResult represents a check result.
type CheckResult struct {
	CheckID     string
	ControlID   string
	ControlName string
	Status      string
	Score       float64
	Message     string
	CheckedAt   time.Time
}

// NewBaselineEngine creates a new baseline engine.
func NewBaselineEngine() *BaselineEngine {
	return &BaselineEngine{
		baselines: make([]SecurityBaseline, 0),
		checks:    make([]BaselineCheck, 0),
		results:   make([]CheckResult, 0),
	}
}

// AddBaseline adds a security baseline.
func (e *BaselineEngine) AddBaseline(baseline SecurityBaseline) {
	baseline.LastUpdated = time.Now()
	e.baselines = append(e.baselines, baseline)
}

// GetBaselines returns all baselines.
func (e *BaselineEngine) GetBaselines() []SecurityBaseline {
	return e.baselines
}

// GetBaseline returns a specific baseline.
func (e *BaselineEngine) GetBaseline(id string) *SecurityBaseline {
	for i := range e.baselines {
		if e.baselines[i].ID == id {
			return &e.baselines[i]
		}
	}
	return nil
}

// GetBaselinesByFramework returns baselines by framework.
func (e *BaselineEngine) GetBaselinesByFramework(framework BaselineFramework) []SecurityBaseline {
	var result []SecurityBaseline
	for _, baseline := range e.baselines {
		if baseline.Source == framework {
			result = append(result, baseline)
		}
	}
	return result
}

// GetActiveBaselines returns active baselines.
func (e *BaselineEngine) GetActiveBaselines() []SecurityBaseline {
	var result []SecurityBaseline
	for _, baseline := range e.baselines {
		if baseline.Active {
			result = append(result, baseline)
		}
	}
	return result
}

// RunCheck runs a baseline check.
func (e *BaselineEngine) RunCheck(check BaselineCheck) *CheckResult {
	result := &CheckResult{
		CheckID:   check.ID,
		ControlID: check.ControlID,
		Status:    "PASS",
		Score:     100.0,
		Message:   "Check passed",
		CheckedAt: time.Now(),
	}

	// In production: execute the check
	// For demo: simulate result
	if check.Expected == check.Actual {
		result.Status = "PASS"
		result.Score = 100.0
		result.Message = "Configuration matches baseline"
	} else {
		result.Status = "FAIL"
		result.Score = 0.0
		result.Message = "Configuration does not match baseline"
	}

	e.results = append(e.results, *result)
	return result
}

// GetChecks returns all baseline checks.
func (e *BaselineEngine) GetChecks() []BaselineCheck {
	return e.checks
}

// GetResults returns all check results.
func (e *BaselineEngine) GetResults() []CheckResult {
	return e.results
}

// GetResultsByControl returns results for a specific control.
func (e *BaselineEngine) GetResultsByControl(controlID string) []CheckResult {
	var result []CheckResult
	for _, res := range e.results {
		if res.ControlID == controlID {
			result = append(result, res)
		}
	}
	return result
}

// CalculateComplianceScore calculates compliance score.
func (e *BaselineEngine) CalculateComplianceScore() float64 {
	if len(e.results) == 0 {
		return 0.0
	}

	var totalScore float64
	for _, result := range e.results {
		totalScore += result.Score
	}

	return totalScore / float64(len(e.results))
}

// CreateCommonBaselines creates common security baselines.
func CreateCommonBaselines() []SecurityBaseline {
	return []SecurityBaseline{
		{
			ID:          "base-001",
			Name:        "CIS Benchmarks",
			Source:      CISBenchmark,
			Version:     "8.0",
			Description: "CIS security configuration benchmarks",
			TargetSystems: []string{"Windows", "Linux", "AWS", "Azure", "Kubernetes"},
			Compliance:  []string{"NIST-800-53", "PCI-DSS"},
			Active:      true,
			LastUpdated: time.Now(),
			Controls: []BaselineControl{
				{
					ID:        "cis-win-1.1",
					Name:      "Ensure Admin Password Policy",
					Description: "Configure password policy for administrative accounts",
					Category:  CategoryHost,
					Severity:  "HIGH",
					Status:    "PASS",
					RiskLevel: "MEDIUM",
					Remediation: "Configure password policy via Group Policy",
					References: []string{"https://www.cisecurity.org/benchmark/microsoft_windows_10"},
				},
				{
					ID:        "cis-win-1.2",
					Name:      "Ensure Account Lockout Threshold",
					Description: "Configure account lockout threshold",
					Category:  CategoryIdentity,
					Severity:  "HIGH",
					Status:    "PASS",
					RiskLevel: "MEDIUM",
					Remediation: "Set account lockout threshold to 5 or less",
					References: []string{"https://www.cisecurity.org/benchmark/microsoft_windows_10"},
				},
				{
					ID:        "cis-linux-1.1",
					Name:      "Ensure SSH Protocol Version",
					Description: "Configure SSH to use version 2 only",
					Category:  CategoryHost,
					Severity:  "CRITICAL",
					Status:    "FAIL",
					RiskLevel: "HIGH",
					Remediation: "Set SSHProtocol to 2 in sshd_config",
					References: []string{"https://www.cisecurity.org/benchmark/ubuntu_linux"},
				},
			},
		},
		{
			ID:          "base-002",
			Name:        "NIST 800-53 Controls",
			Source:      NIST80053,
			Version:     "Rev 5",
			Description: "NIST security and privacy controls",
			TargetSystems: []string{"Cloud", "On-Premises", "Hybrid"},
			Compliance:  []string{"FedRAMP", "FISMA"},
			Active:      true,
			LastUpdated: time.Now(),
			Controls: []BaselineControl{
				{
					ID:        "ac-2",
					Name:      "Account Management",
					Description: "Manage information system accounts",
					Category:  CategoryIdentity,
					Severity:  "HIGH",
					Status:    "PASS",
					RiskLevel: "MEDIUM",
					Remediation: "Implement account management procedures",
					References: []string{"https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"},
				},
				{
					ID:        "ac-3",
					Name:      "Access Enforcement",
					Description: "Enforce approved access control policies",
					Category:  CategoryIdentity,
					Severity:  "HIGH",
					Status:    "PASS",
					RiskLevel: "MEDIUM",
					Remediation: "Implement access control mechanisms",
					References: []string{"https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"},
				},
			},
		},
		{
			ID:          "base-003",
			Name:        "CIS Controls v8",
			Source:      CISControls,
			Version:     "8.0",
			Description: "CIS critical security controls",
			TargetSystems: []string{"All"},
			Compliance:  []string{"NIST-800-53", "PCI-DSS"},
			Active:      true,
			LastUpdated: time.Now(),
			Controls: []BaselineControl{
				{
					ID:        "cis-1",
					Name:      "Inventory and Control of Software Assets",
					Description: "Maintain inventory of organizational software",
					Category:  CategoryApplication,
					Severity:  "HIGH",
					Status:    "PASS",
					RiskLevel: "MEDIUM",
					Remediation: "Implement software asset inventory",
					References: []string{"https://www.cisecurity.org/controls"},
				},
				{
					ID:        "cis-2",
					Name:      "Inventory and Control of Hardware Assets",
					Description: "Maintain inventory of hardware assets",
					Category:  CategoryHost,
					Severity:  "HIGH",
					Status:    "PASS",
					RiskLevel: "MEDIUM",
					Remediation: "Implement hardware asset inventory",
					References: []string{"https://www.cisecurity.org/controls"},
				},
			},
		},
	}
}

// GenerateReport generates baseline report.
func (e *BaselineEngine) GenerateReport() string {
	var report string

	report += "=== Security Baseline Report ===\n\n"

	// Summary
	report += "Total Baselines: " + string(rune(len(e.baselines)+48)) + "\n"
	report += "Active Baselines: " + string(rune(len(e.GetActiveBaselines())+48)) + "\n"
	report += "Checks Performed: " + string(rune(len(e.results)+48)) + "\n"
	report += "Compliance Score: " + fmt.Sprintf("%.1f%%", e.CalculateComplianceScore()) + "\n\n"

	// Baselines by framework
	report += "Baselines by Framework:\n"
	frameworkCounts := make(map[BaselineFramework]int)
	for _, baseline := range e.baselines {
		frameworkCounts[baseline.Source]++
	}

	for framework, count := range frameworkCounts {
		report += "  • " + string(framework) + ": " + string(rune(count+48)) + " baselines\n"
	}

	// Results summary
	if len(e.results) > 0 {
		report += "\nCheck Results:\n"
		passed := 0
		failed := 0
		for _, result := range e.results {
			if result.Status == "PASS" {
				passed++
			} else {
				failed++
			}
		}

		report += "  Passed: " + fmt.Sprintf("%d", passed) + "\n"
		report += "  Failed: " + fmt.Sprintf("%d", failed) + "\n\n"

		// Recent results
		report += "Recent Checks:\n"
		for i, result := range e.results {
			if i >= 10 {
				break
			}
			status := "✓"
			if result.Status != "PASS" {
				status = "✗"
			}
			report += "  [" + string(rune(i+49)) + "] " + status + " " + result.ControlName + "\n"
			report += "      Status: " + result.Status + "\n"
			report += "      Score: " + fmt.Sprintf("%.1f%%", result.Score) + "\n\n"
		}
	}

	return report
}

// GetBaseline returns baseline.
func GetBaseline(engine *BaselineEngine, id string) *SecurityBaseline {
	return engine.GetBaseline(id)
}

// GetCheckResult returns check result.
func GetCheckResult(result *CheckResult) *CheckResult {
	return result
}
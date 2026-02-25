package main

import (
	"fmt"
	"os"
	"time"

	"github.com/hallucinaut/securitybaseline/pkg/baseline"
	"github.com/hallucinaut/securitybaseline/pkg/compliance"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "list":
		listBaselines()
	case "check":
		checkBaseline()
	case "compliance":
		checkCompliance()
	case "report":
		generateReport()
	case "help", "--help", "-h":
		printUsage()
	case "version":
		fmt.Printf("securitybaseline version %s\n", version)
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Print(`securitybaseline - Security Baseline Compliance Engine

Usage:
  securitybaseline <command> [options]

Commands:
  list        List available security baselines
  check       Run baseline checks
  compliance  Check compliance status
  report      Generate compliance report
  help        Show this help message
  version     Show version information

Examples:
  securitybaseline list
  securitybaseline check
  securitybaseline compliance
`, "securitybaseline")
}

func listBaselines() {
	fmt.Println("Security Baselines")
	fmt.Println("==================")
	fmt.Println()

	engine := baseline.NewBaselineEngine()

	// Add common baselines
	commonBaselines := baseline.CreateCommonBaselines()
	for _, base := range commonBaselines {
		engine.AddBaseline(base)
	}

	baselines := engine.GetActiveBaselines()

	fmt.Printf("Total Active Baselines: %d\n\n", len(baselines))

	fmt.Println("Available Baselines:")
	for i, base := range baselines {
		fmt.Printf("\n[%d] %s\n", i+1, base.Name)
		fmt.Printf("    ID: %s\n", base.ID)
		fmt.Printf("    Framework: %s\n", base.Source)
		fmt.Printf("    Version: %s\n", base.Version)
		fmt.Printf("    Target Systems: %v\n", base.TargetSystems)
		fmt.Printf("    Controls: %d\n", len(base.Controls))
		fmt.Printf("    Compliance: %v\n", base.Compliance)
	}
}

func checkBaseline() {
	fmt.Println("Running Baseline Checks")
	fmt.Println("=======================")
	fmt.Println()

	engine := baseline.NewBaselineEngine()
	commonBaselines := baseline.CreateCommonBaselines()
	for _, base := range commonBaselines {
		engine.AddBaseline(base)
	}

	// Get first baseline
	if len(commonBaselines) == 0 {
		fmt.Println("No baselines available")
		return
	}

	base := commonBaselines[0]
	fmt.Printf("Baseline: %s (%s v%s)\n", base.Name, base.Source, base.Version)
	fmt.Printf("Controls: %d\n\n", len(base.Controls))

	fmt.Println("Running checks...")
	fmt.Println()

	for i, control := range base.Controls {
		// Simulate check
		check := baseline.BaselineCheck{
			ID:          "chk-" + fmt.Sprintf("%d", i+1),
			ControlID:   control.ID,
			BaselineID:  base.ID,
			CheckType:   "configuration",
			Expected:    "compliant",
			Actual:      control.Status,
			Status:      "COMPLETED",
			Message:     "Check completed",
		}

		result := engine.RunCheck(check)
		status := "✓"
		if result.Status != "PASS" {
			status = "✗"
		}

		fmt.Printf("[%d] %s %s\n", i+1, status, control.Name)
		fmt.Printf("    Status: %s\n", result.Status)
		fmt.Printf("    Score: %.1f%%\n", result.Score)
		fmt.Printf("    Message: %s\n\n", result.Message)
	}

	fmt.Println(engine.GenerateReport())
}

func checkCompliance() {
	fmt.Println("Checking Compliance")
	fmt.Println("===================")
	fmt.Println()

	checker := compliance.NewComplianceChecker()

	// Create report
	report := checker.CreateReport("CIS Benchmarks", "8.0")

	// Add compliance checks
	checks := []compliance.ComplianceCheck{
		{
			ID:          "chk-001",
			Name:        "Password Policy",
			Description: "Password complexity requirements",
			Requirement: "Passwords must be 14+ characters with complexity",
			Status:      compliance.StatusCompliant,
			Evidence:    []string{"gpo-password-policy.json"},
			LastChecked: time.Now(),
			Owner:       "IT Security",
		},
		{
			ID:          "chk-002",
			Name:        "Multi-Factor Authentication",
			Description: "MFA for all privileged access",
			Requirement: "MFA required for all admin access",
			Status:      compliance.StatusPartialCompliant,
			Evidence:    []string{"mfa-config.json"},
			LastChecked: time.Now(),
			Owner:       "IT Security",
		},
		{
			ID:          "chk-003",
			Name:        "Encryption at Rest",
			Description: "Data encryption requirements",
			Requirement: "All sensitive data encrypted at rest",
			Status:      compliance.StatusCompliant,
			Evidence:    []string{"encryption-policy.json"},
			LastChecked: time.Now(),
			Owner:       "Data Protection",
		},
		{
			ID:          "chk-004",
			Name:        "Network Segmentation",
			Description: "Network segmentation controls",
			Requirement: "Critical systems isolated in separate network",
			Status:      compliance.StatusNonCompliant,
			Evidence:    []string{"network-config.json"},
			LastChecked: time.Now(),
			Owner:       "Network Team",
		},
	}

	for _, check := range checks {
		checker.AddCheck(report.ID, check)
	}

	// Add recommendations
	report.Recommendations = []string{
		"Implement MFA for remaining privileged accounts",
		"Improve network segmentation for critical systems",
		"Schedule quarterly compliance review",
	}

	fmt.Println(checker.GenerateReport())
}

func generateReport() {
	engine := baseline.NewBaselineEngine()
	checker := compliance.NewComplianceChecker()

	// Add baselines
	commonBaselines := baseline.CreateCommonBaselines()
	for _, base := range commonBaselines {
		engine.AddBaseline(base)
	}

	// Run some checks
	for _, base := range commonBaselines {
		for i, control := range base.Controls {
			check := baseline.BaselineCheck{
				ID:          "chk-" + fmt.Sprintf("%d", i+1),
				ControlID:   control.ID,
				BaselineID:  base.ID,
				CheckType:   "configuration",
				Expected:    "compliant",
				Actual:      control.Status,
				Status:      "COMPLETED",
				Message:     "Check completed",
			}
			engine.RunCheck(check)
		}
	}

	// Create compliance report
	report := checker.CreateReport("CIS Benchmarks", "8.0")
	checker.AddCheck(report.ID, compliance.ComplianceCheck{
		ID:        "chk-001",
		Name:      "Password Policy",
		Requirement: "Passwords must be 14+ characters",
		Status:    compliance.StatusCompliant,
		Evidence:  []string{"gpo-config.json"},
	})

	fmt.Println("=== Baseline Report ===")
	fmt.Println(engine.GenerateReport())
	fmt.Println("=== Compliance Report ===")
	fmt.Println(compliance.GenerateReport(checker))
}
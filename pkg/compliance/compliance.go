// Package compliance provides compliance checking capabilities.
package compliance

import (
	"fmt"
	"time"
)

// ComplianceStatus represents compliance status.
type ComplianceStatus string

const (
	StatusCompliant      ComplianceStatus = "compliant"
	StatusNonCompliant   ComplianceStatus = "non_compliant"
	StatusPartialCompliant ComplianceStatus = "partial_compliant"
	StatusNotApplicable  ComplianceStatus = "not_applicable"
)

// ComplianceCheck represents a compliance check.
type ComplianceCheck struct {
	ID              string
	Name            string
	Description     string
	Requirement     string
	Status          ComplianceStatus
	Evidence        []string
	LastChecked     time.Time
	NextReview      time.Time
	Owner           string
}

// ComplianceReport represents a compliance report.
type ComplianceReport struct {
	ID            string
	Framework     string
	Version       string
	GeneratedAt   time.Time
	Checks        []ComplianceCheck
	Score         float64
	Status        ComplianceStatus
	Recommendations []string
}

// ComplianceChecker checks compliance against baselines.
type ComplianceChecker struct {
	reports []ComplianceReport
}

// NewComplianceChecker creates a new compliance checker.
func NewComplianceChecker() *ComplianceChecker {
	return &ComplianceChecker{
		reports: make([]ComplianceReport, 0),
	}
}

// CreateReport creates a new compliance report.
func (c *ComplianceChecker) CreateReport(framework, version string) *ComplianceReport {
	report := &ComplianceReport{
		ID:          "cr-" + time.Now().Format("20060102150405"),
		Framework:   framework,
		Version:     version,
		GeneratedAt: time.Now(),
		Checks:      make([]ComplianceCheck, 0),
		Score:       0.0,
		Status:      StatusNotApplicable,
		Recommendations: make([]string, 0),
	}

	c.reports = append(c.reports, *report)
	return report
}

// AddCheck adds a compliance check to report.
func (c *ComplianceChecker) AddCheck(reportID string, check ComplianceCheck) {
	for i := range c.reports {
		if c.reports[i].ID == reportID {
			c.reports[i].Checks = append(c.reports[i].Checks, check)
			c.reports[i].Score = c.calculateScore(c.reports[i])
			c.reports[i].Status = determineStatus(c.reports[i].Score)
			break
		}
	}
}

// GetReports returns all compliance reports.
func (c *ComplianceChecker) GetReports() []ComplianceReport {
	return c.reports
}

// GetReport returns a specific report.
func (c *ComplianceChecker) GetReport(id string) *ComplianceReport {
	for i := range c.reports {
		if c.reports[i].ID == id {
			return &c.reports[i]
		}
	}
	return nil
}

// calculateScore calculates compliance score.
func (c *ComplianceChecker) calculateScore(report ComplianceReport) float64 {
	if len(report.Checks) == 0 {
		return 0.0
	}

	var compliant int
	for _, check := range report.Checks {
		if check.Status == StatusCompliant {
			compliant++
		}
	}

	return float64(compliant) / float64(len(report.Checks)) * 100.0
}

// determineStatus determines compliance status from score.
func determineStatus(score float64) ComplianceStatus {
	if score >= 90 {
		return StatusCompliant
	} else if score >= 70 {
		return StatusPartialCompliant
	} else if score > 0 {
		return StatusNonCompliant
	}
	return StatusNotApplicable
}

// GenerateReport generates compliance report.
func (c *ComplianceChecker) GenerateReport() string {
	var report string

	report += "=== Compliance Report ===\n\n"

	reports := c.GetReports()
	if len(reports) == 0 {
		report += "No compliance reports available\n"
		return report
	}

	for i, rep := range reports {
		report += "Report [" + fmt.Sprintf("%d", i+1) + "]: " + rep.Framework + " v" + rep.Version + "\n"
		report += "Generated: " + rep.GeneratedAt.Format("2006-01-02 15:04:05") + "\n"
		report += "Score: " + fmt.Sprintf("%.1f%%", rep.Score) + "\n"
		report += "Status: " + string(rep.Status) + "\n\n"

		report += "Checks:\n"
		for j, check := range rep.Checks {
			status := "✓"
			if check.Status != StatusCompliant {
				status = "✗"
			}
			report += "  [" + fmt.Sprintf("%d", j+1) + "] " + status + " " + check.Name + "\n"
			report += "      Status: " + string(check.Status) + "\n"
			report += "      Requirement: " + check.Requirement + "\n"

			if len(check.Evidence) > 0 {
				report += "      Evidence:\n"
				for _, evidence := range check.Evidence {
					report += "        - " + evidence + "\n"
				}
			}

			report += "\n"
		}

		if len(rep.Recommendations) > 0 {
			report += "Recommendations:\n"
			for j, rec := range rep.Recommendations {
				report += "  [" + fmt.Sprintf("%d", j+1) + "] " + rec + "\n"
			}
			report += "\n"
		}
	}

	return report
}

// GenerateReport generates compliance report.
func GenerateReport(checker *ComplianceChecker) string {
	return checker.GenerateReport()
}

// GetComplianceCheck returns compliance check.
func GetComplianceCheck(check *ComplianceCheck) *ComplianceCheck {
	return check
}

// GetComplianceReport returns compliance report.
func GetComplianceReport(report *ComplianceReport) *ComplianceReport {
	return report
}
package conform

import (
	"encoding/json"
	"fmt"
	"io"
)

// Outcome is one check's reported result.
type Outcome struct {
	ID      string `json:"id"`
	Section string `json:"section"`
	Level   string `json:"level"`
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Detail  string `json:"detail,omitempty"`
}

// Report is a full conformance run.
type Report struct {
	Target     string    `json:"target"`
	Version    string    `json:"harness_version"`
	Checks     []Outcome `json:"checks"`
	Untestable []string  `json:"not_black_box_testable"`
	MustPassed int       `json:"musts_passed"`
	MustTotal  int       `json:"musts_run"`
	Failures   int       `json:"failures"`
	Warnings   int       `json:"warnings"`
	Skipped    int       `json:"skipped"`
}

// Run executes the matrix in order and aggregates the report.
func Run(s *Session, version string, probes bool) Report {
	rep := Report{Target: s.Target, Version: version, Untestable: Untestable}
	for _, c := range Checks(probes) {
		res := c.Run(s)
		rep.Checks = append(rep.Checks, Outcome{
			ID: c.ID, Section: c.Section, Level: c.Level, Name: c.Name,
			Status: res.Status, Detail: res.Detail,
		})
		switch res.Status {
		case Pass:
			if c.Level == "MUST" {
				rep.MustPassed++
				rep.MustTotal++
			}
		case Fail:
			rep.Failures++
			if c.Level == "MUST" {
				rep.MustTotal++
			}
		case Warn:
			rep.Warnings++
		case Skip:
			rep.Skipped++
		}
	}
	return rep
}

// Passed reports whether the run had no MUST failures.
func (r Report) Passed() bool { return r.Failures == 0 }

// WriteText prints the human report.
func (r Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "wedge-conform %s → %s\n\n", r.Version, r.Target)
	for _, c := range r.Checks {
		line := fmt.Sprintf("%-4s %-9s %-4s %s", c.Status, c.Section, c.ID, c.Name)
		if c.Detail != "" {
			line += " — " + c.Detail
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w, "\nNot black-box-testable (assert by code review, not this harness):")
	for _, u := range r.Untestable {
		fmt.Fprintln(w, "  - "+u)
	}
	fmt.Fprintf(w, "\nSummary: %d/%d wire-observable MUSTs pass, %d warning(s), %d skipped.\n",
		r.MustPassed, r.MustTotal, r.Warnings, r.Skipped)
	if !r.Passed() {
		fmt.Fprintln(w, "RESULT: NOT CONFORMANT")
	} else {
		fmt.Fprintln(w, "RESULT: conformant (all wire-observable MUSTs pass)")
	}
}

// WriteJSON prints the machine report.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

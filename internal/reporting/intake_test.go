package reporting

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSingleNormalizesConfirmedDraft(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	intake := newIntake(func() time.Time { return now })

	report, err := intake.Single(Draft{
		IPAddress: " ::ffff:192.0.2.1 ", Categories: []int{22, 18, 22},
		ReportedAt: "2026-08-09T12:00:00Z", Comment: " SSH brute-force ",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if report.IPAddress != "192.0.2.1" || report.Comment != "SSH brute-force" {
		t.Fatalf("report was not normalized: %+v", report)
	}
	if !slices.Equal(report.Categories, []int{18, 22}) {
		t.Fatalf("categories = %v, want [18 22]", report.Categories)
	}
}

func TestSingleRequiresConfirmation(t *testing.T) {
	intake := newIntake(time.Now)
	if _, err := intake.Single(Draft{}, false); err == nil || !strings.Contains(err.Error(), "confirm must be true") {
		t.Fatalf("confirmation error = %v", err)
	}
}

func TestIntakeRejectsInvalidTimestamps(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	intake := newIntake(func() time.Time { return now })
	base := Draft{IPAddress: "192.0.2.1", Categories: []int{14}, Comment: "TCP port scan"}

	for _, tt := range []struct {
		name      string
		timestamp string
		want      string
	}{
		{"too old", "2026-06-01T00:00:00Z", "older than 60 days"},
		{"future", "2026-08-10T12:00:01Z", "in the future"},
		{"malformed", "yesterday", "RFC 3339"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			draft := base
			draft.ReportedAt = tt.timestamp
			if _, err := intake.Single(draft, true); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("timestamp error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestBulkValidatesEveryDraftWithOneClockReading(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	clockReads := 0
	intake := newIntake(func() time.Time {
		clockReads++
		return now
	})
	drafts := []Draft{
		{IPAddress: "192.0.2.1", Categories: []int{14}, ReportedAt: "2026-08-09T12:00:00Z", Comment: "scan"},
		{IPAddress: "2001:db8::1", Categories: []int{18, 22}, ReportedAt: "2026-08-09T13:00:00Z", Comment: "SSH attempts"},
	}

	reports, err := intake.Bulk(drafts, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 || clockReads != 1 {
		t.Fatalf("reports = %d, clock reads = %d", len(reports), clockReads)
	}

	drafts[1].IPAddress = "not-an-ip"
	if _, err := intake.Bulk(drafts, true); err == nil || !strings.Contains(err.Error(), "reports[1]") {
		t.Fatalf("indexed bulk error = %v", err)
	}
}

func TestBulkEnforcesShapeBeforeValidation(t *testing.T) {
	intake := newIntake(time.Now)
	if _, err := intake.Bulk(nil, false); err == nil || !strings.Contains(err.Error(), "confirm must be true") {
		t.Fatalf("confirmation error = %v", err)
	}
	if _, err := intake.Bulk(nil, true); err == nil || !strings.Contains(err.Error(), "at least one row") {
		t.Fatalf("empty bulk error = %v", err)
	}
	if _, err := intake.Bulk(make([]Draft, MaxBulkRows+1), true); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("row limit error = %v", err)
	}
}

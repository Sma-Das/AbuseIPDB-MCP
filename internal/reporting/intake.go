package reporting

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	// MaxBulkRows leaves room for the header in AbuseIPDB's 10,000-line limit.
	MaxBulkRows     = 9999
	maxCommentBytes = 1024
	maxReportAge    = 60 * 24 * time.Hour
)

// Draft is untrusted abuse report input.
type Draft struct {
	IPAddress  string
	Categories []int
	ReportedAt string
	Comment    string
}

// Report is a normalized, policy-checked abuse report ready for an upstream
// adapter.
type Report struct {
	IPAddress  string
	Categories []int
	ReportedAt string
	Comment    string
}

// Intake validates single and bulk abuse report writes.
type Intake struct {
	now func() time.Time
}

// NewIntake creates report intake backed by the system clock.
func NewIntake() Intake {
	return newIntake(time.Now)
}

func newIntake(now func() time.Time) Intake {
	return Intake{now: now}
}

// Single confirms and validates one abuse report draft.
func (i Intake) Single(draft Draft, confirmed bool) (Report, error) {
	if !confirmed {
		return Report{}, errors.New("confirm must be true before submitting an external abuse report")
	}
	return validate(draft, false, i.now())
}

// Bulk confirms and validates abuse report drafts as one bulk write.
func (i Intake) Bulk(drafts []Draft, confirmed bool) ([]Report, error) {
	if !confirmed {
		return nil, errors.New("confirm must be true before bulk-submitting external abuse reports")
	}
	if len(drafts) == 0 {
		return nil, errors.New("reports must contain at least one row")
	}
	if len(drafts) > MaxBulkRows {
		return nil, fmt.Errorf("reports must contain at most %d rows", MaxBulkRows)
	}

	now := i.now()
	reports := make([]Report, len(drafts))
	for index, draft := range drafts {
		report, err := validate(draft, true, now)
		if err != nil {
			return nil, fmt.Errorf("reports[%d]: %w", index, err)
		}
		reports[index] = report
	}
	return reports, nil
}

func validate(draft Draft, timestampRequired bool, now time.Time) (Report, error) {
	ip, err := normalizeIP(draft.IPAddress)
	if err != nil {
		return Report{}, err
	}
	categories, err := normalizeCategories(draft.Categories)
	if err != nil {
		return Report{}, err
	}
	comment := strings.TrimSpace(draft.Comment)
	if comment == "" {
		return Report{}, errors.New("comment is required by the AbuseIPDB reporting policy")
	}
	if len(comment) > maxCommentBytes {
		return Report{}, fmt.Errorf("comment must not exceed %d bytes", maxCommentBytes)
	}
	timestamp, err := validateTimestamp(draft.ReportedAt, timestampRequired, now)
	if err != nil {
		return Report{}, err
	}
	return Report{
		IPAddress:  ip,
		Categories: categories,
		ReportedAt: timestamp,
		Comment:    comment,
	}, nil
}

func normalizeIP(raw string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("ip_address must be a valid IPv4 or IPv6 address")
	}
	return addr.Unmap().String(), nil
}

func normalizeCategories(values []int) ([]int, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one category is required")
	}
	seen := make(map[int]struct{}, len(values))
	result := make([]int, 0, len(values))
	for _, value := range values {
		if !validCategory(value) {
			return nil, fmt.Errorf("category %d is invalid; valid category IDs are 1 through 23", value)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Ints(result)
	return result, nil
}

func validateTimestamp(raw string, required bool, now time.Time) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if required {
			return "", errors.New("reported_at is required")
		}
		return "", nil
	}
	timestamp, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return "", errors.New("reported_at must be an RFC 3339 timestamp with a timezone")
	}
	if timestamp.Before(now.Add(-maxReportAge)) {
		return "", errors.New("reported_at must not be older than 60 days")
	}
	if timestamp.After(now) {
		return "", errors.New("reported_at must not be in the future")
	}
	return timestamp.Format(time.RFC3339), nil
}

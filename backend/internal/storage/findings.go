package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/contract"
)

var (
	ErrFindingNotFound          = errors.New("finding not found")
	ErrFindingTenantMismatch    = errors.New("finding tenant does not match authenticated tenant")
	ErrUnknownAsset             = errors.New("referenced asset does not exist in this tenant")
	ErrInvalidFindingPagination = errors.New("invalid finding pagination parameters")
)

const maxFindingPageSize = 100

// FindingRecord contains a validated Finding and its internal database metadata.
type FindingRecord struct {
	ID        int64
	Finding   contract.Finding
	CreatedAt time.Time
	UpdatedAt time.Time
}

type findingScanner interface {
	Scan(dest ...any) error
}

// These columns must stay in the same order as scanFinding.
const findingSelectColumns = `
id,
tenant_id::text,
schema_version,
finding_id,
asset_id,
source,
title,
description,
status,
severity,
confidence,
cvss_version,
cvss_score,
cvss_vector,
cwe_ids,
references_json,
evidence_refs,
remediation_guidance,
detected_at,
last_observed_at,
deduplication_key,
references_to_incidents,
created_at,
updated_at
`

// findingEvidenceJSON defines the database JSON representation.
// It deliberately contains metadata and references only, never raw evidence.
type findingEvidenceJSON struct {
	EvidenceID     string  `json:"evidence_id"`
	Classification string  `json:"classification"`
	Redacted       bool    `json:"redacted"`
	SHA256         *string `json:"sha256,omitempty"`
	StorageRef     *string `json:"storage_ref,omitempty"`
	MediaType      *string `json:"media_type,omitempty"`
}

func findingEvidenceToJSON(
	values []contract.FindingEvidenceReference,
) []findingEvidenceJSON {
	result := make([]findingEvidenceJSON, 0, len(values))

	for _, value := range values {
		result = append(result, findingEvidenceJSON{
			EvidenceID:     value.EvidenceID,
			Classification: value.Classification,
			Redacted:       value.Redacted,
			SHA256:         value.SHA256,
			StorageRef:     value.StorageRef,
			MediaType:      value.MediaType,
		})
	}

	return result
}

func nullableFindingString(value *string) any {
	if value == nil {
		return nil
	}

	return *value
}

func nullableFindingTime(value *time.Time) any {
	if value == nil {
		return nil
	}

	return *value
}

// scanFinding converts one database row into a FindingRecord.
func scanFinding(row findingScanner) (FindingRecord, error) {
	var record FindingRecord
	finding := &record.Finding

	var tenantID string

	var description sql.NullString
	var cvssVersion sql.NullString
	var cvssScore sql.NullFloat64
	var cvssVector sql.NullString
	var remediationGuidance sql.NullString
	var lastObservedAt sql.NullTime
	var deduplicationKey sql.NullString

	var cweIDsJSON []byte
	var referencesJSON []byte
	var evidenceRefsJSON []byte
	var referencesToIncidentsJSON []byte

	err := row.Scan(
		&record.ID,
		&tenantID,
		&finding.SchemaVersion,
		&finding.FindingID,
		&finding.AssetID,
		&finding.Source,
		&finding.Title,
		&description,
		&finding.Status,
		&finding.Severity,
		&finding.Confidence,
		&cvssVersion,
		&cvssScore,
		&cvssVector,
		&cweIDsJSON,
		&referencesJSON,
		&evidenceRefsJSON,
		&remediationGuidance,
		&finding.DetectedAt,
		&lastObservedAt,
		&deduplicationKey,
		&referencesToIncidentsJSON,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if err != nil {
		return FindingRecord{}, err
	}

	finding.TenantID = &tenantID

	if description.Valid {
		value := description.String
		finding.Description = &value
	}

	// The database constraint ensures CVSS columns are either all absent
	// or contain a valid version and score.
	if cvssVersion.Valid {
		if !cvssScore.Valid {
			return FindingRecord{}, errors.New(
				"inconsistent stored CVSS metadata: score is missing",
			)
		}

		cvss := &contract.FindingCVSS{
			Version: cvssVersion.String,
			Score:   cvssScore.Float64,
		}

		if cvssVector.Valid {
			value := cvssVector.String
			cvss.Vector = &value
		}

		finding.CVSS = cvss
	} else if cvssScore.Valid || cvssVector.Valid {
		return FindingRecord{}, errors.New(
			"inconsistent stored CVSS metadata: version is missing",
		)
	}

	if err := json.Unmarshal(cweIDsJSON, &finding.CWEIDs); err != nil {
		return FindingRecord{}, fmt.Errorf("decode finding CWE IDs: %w", err)
	}

	if err := json.Unmarshal(referencesJSON, &finding.References); err != nil {
		return FindingRecord{}, fmt.Errorf("decode finding references: %w", err)
	}

	var evidenceItems []findingEvidenceJSON

	if err := json.Unmarshal(evidenceRefsJSON, &evidenceItems); err != nil {
		return FindingRecord{}, fmt.Errorf("decode finding evidence references: %w", err)
	}

	finding.EvidenceRefs = make(
		[]contract.FindingEvidenceReference,
		0,
		len(evidenceItems),
	)

	for _, item := range evidenceItems {
		finding.EvidenceRefs = append(
			finding.EvidenceRefs,
			contract.FindingEvidenceReference{
				EvidenceID:     item.EvidenceID,
				Classification: item.Classification,
				Redacted:       item.Redacted,
				SHA256:         item.SHA256,
				StorageRef:     item.StorageRef,
				MediaType:      item.MediaType,
			},
		)
	}

	if err := json.Unmarshal(
		referencesToIncidentsJSON,
		&finding.ReferencesToIncidents,
	); err != nil {
		return FindingRecord{}, fmt.Errorf(
			"decode finding incident references: %w",
			err,
		)
	}

	if remediationGuidance.Valid {
		value := remediationGuidance.String
		finding.RemediationGuidance = &value
	}

	if lastObservedAt.Valid {
		value := lastObservedAt.Time
		finding.LastObservedAt = &value
	}

	if deduplicationKey.Valid {
		value := deduplicationKey.String
		finding.DeduplicationKey = &value
	}

	finding.CWEIDs = normalizeStringSlice(finding.CWEIDs)
	finding.References = normalizeStringSlice(finding.References)
	finding.ReferencesToIncidents = normalizeStringSlice(
		finding.ReferencesToIncidents,
	)

	return record, nil
}

// InsertFinding creates a Finding inside the authenticated tenant.
//
// tenantID must come from the authenticated principal, not from the request body.
// The composite foreign key in PostgreSQL ensures that the referenced Asset
// belongs to the same tenant.
func (s *Store) InsertFinding(
	ctx context.Context,
	tenantID string,
	finding contract.Finding,
) (FindingRecord, error) {
	tenantID = strings.TrimSpace(tenantID)

	if tenantID == "" {
		return FindingRecord{}, ErrTenantRequired
	}

	if finding.TenantID != nil &&
		strings.TrimSpace(*finding.TenantID) != tenantID {
		return FindingRecord{}, ErrFindingTenantMismatch
	}

	// Always use the authenticated tenant ID internally.
	finding.TenantID = &tenantID

	// Normalize optional arrays so PostgreSQL always receives JSON arrays.
	finding.CWEIDs = normalizeStringSlice(finding.CWEIDs)
	finding.References = normalizeStringSlice(finding.References)
	finding.ReferencesToIncidents = normalizeStringSlice(
		finding.ReferencesToIncidents,
	)

	if finding.EvidenceRefs == nil {
		finding.EvidenceRefs = []contract.FindingEvidenceReference{}
	}

	cweIDsJSON, err := json.Marshal(finding.CWEIDs)
	if err != nil {
		return FindingRecord{}, fmt.Errorf("encode finding CWE IDs: %w", err)
	}

	referencesJSON, err := json.Marshal(finding.References)
	if err != nil {
		return FindingRecord{}, fmt.Errorf("encode finding references: %w", err)
	}

	evidenceRefsJSON, err := json.Marshal(
		findingEvidenceToJSON(finding.EvidenceRefs),
	)
	if err != nil {
		return FindingRecord{}, fmt.Errorf("encode finding evidence references: %w", err)
	}

	referencesToIncidentsJSON, err := json.Marshal(
		finding.ReferencesToIncidents,
	)
	if err != nil {
		return FindingRecord{}, fmt.Errorf(
			"encode finding incident references: %w",
			err,
		)
	}

	var cvssVersion any
	var cvssScore any
	var cvssVector any

	if finding.CVSS != nil {
		cvssVersion = finding.CVSS.Version
		cvssScore = finding.CVSS.Score

		if finding.CVSS.Vector != nil {
			cvssVector = *finding.CVSS.Vector
		}
	}

	var record FindingRecord
	record.Finding = finding

	err = s.DB.QueryRowContext(ctx, `
INSERT INTO findings (
    tenant_id,
    schema_version,
    finding_id,
    asset_id,
    source,
    title,
    description,
    status,
    severity,
    confidence,
    cvss_version,
    cvss_score,
    cvss_vector,
    cwe_ids,
    references_json,
    evidence_refs,
    remediation_guidance,
    detected_at,
    last_observed_at,
    deduplication_key,
    references_to_incidents
)
VALUES (
    $1::uuid,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8,
    $9,
    $10,
    $11,
    $12,
    $13,
    $14::jsonb,
    $15::jsonb,
    $16::jsonb,
    $17,
    $18,
    $19,
    $20,
    $21::jsonb
)
RETURNING id, created_at, updated_at
`,
		tenantID,
		finding.SchemaVersion,
		finding.FindingID,
		finding.AssetID,
		finding.Source,
		finding.Title,
		nullableFindingString(finding.Description),
		finding.Status,
		finding.Severity,
		finding.Confidence,
		cvssVersion,
		cvssScore,
		cvssVector,
		string(cweIDsJSON),
		string(referencesJSON),
		string(evidenceRefsJSON),
		nullableFindingString(finding.RemediationGuidance),
		finding.DetectedAt,
		nullableFindingTime(finding.LastObservedAt),
		nullableFindingString(finding.DeduplicationKey),
		string(referencesToIncidentsJSON),
	).Scan(
		&record.ID,
		&record.CreatedAt,
		&record.UpdatedAt,
	)

	if err != nil {
		var pgErr interface {
			SQLState() string
		}

		if errors.As(err, &pgErr) {
			switch pgErr.SQLState() {
			case "23505":
				return FindingRecord{}, ErrDuplicate
			case "23503":
				return FindingRecord{}, ErrUnknownAsset
			}
		}

		return FindingRecord{}, fmt.Errorf("insert finding: %w", err)
	}

	return record, nil
}

// GetFindingByID retrieves a Finding using its external finding_id.
// The query is always restricted to the supplied tenant.
func (s *Store) GetFindingByID(
	ctx context.Context,
	tenantID string,
	findingID string,
) (FindingRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	findingID = strings.TrimSpace(findingID)

	if tenantID == "" {
		return FindingRecord{}, ErrTenantRequired
	}

	if findingID == "" {
		return FindingRecord{}, ErrFindingNotFound
	}

	query := `SELECT ` + findingSelectColumns + `
FROM findings
WHERE tenant_id = $1::uuid
  AND finding_id = $2
`

	record, err := scanFinding(
		s.DB.QueryRowContext(ctx, query, tenantID, findingID),
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return FindingRecord{}, ErrFindingNotFound
		}

		return FindingRecord{}, fmt.Errorf("get finding: %w", err)
	}

	return record, nil
}

// ListFindings returns a tenant-scoped page using keyset pagination.
// afterID is the internal database ID of the last item in the previous page.
// A zero value starts from the first page.
func (s *Store) ListFindings(
	ctx context.Context,
	tenantID string,
	afterID int64,
	limit int,
) ([]FindingRecord, bool, error) {
	tenantID = strings.TrimSpace(tenantID)

	if tenantID == "" {
		return nil, false, ErrTenantRequired
	}

	if afterID < 0 || limit < 1 || limit > maxFindingPageSize {
		return nil, false, ErrInvalidFindingPagination
	}

	query := `SELECT ` + findingSelectColumns + `
FROM findings
WHERE tenant_id = $1::uuid
  AND id > $2
ORDER BY id ASC
LIMIT $3
`

	rows, err := s.DB.QueryContext(
		ctx,
		query,
		tenantID,
		afterID,
		limit+1,
	)
	if err != nil {
		return nil, false, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	records := make([]FindingRecord, 0, limit+1)

	for rows.Next() {
		record, err := scanFinding(rows)
		if err != nil {
			return nil, false, fmt.Errorf("scan listed finding: %w", err)
		}

		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate findings: %w", err)
	}

	hasMore := len(records) > limit

	if hasMore {
		records = records[:limit]
	}

	return records, hasMore, nil
}

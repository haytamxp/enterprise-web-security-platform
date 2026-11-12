package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/contract"
)

var ErrDuplicate = errors.New("record already exists")
var ErrUnknownEvent = errors.New("one or more referenced events do not exist")
var ErrTenantRequired = errors.New("tenant ID is required")

func (s *Store) InsertEvent(
	ctx context.Context,
	tenantID string,
	e contract.Event,
) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ErrTenantRequired
	}

	_, err := s.DB.ExecContext(ctx, `
INSERT INTO events (
tenant_id,
event_id,
schema_version,
source_product,
event_type,
asset_id,
occurred_at,
severity,
confidence,
correlation_id,
src_ip,
dest_ip,
rule_id,
signature,
description,
raw_ref
)
VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
`,
		tenantID,
		e.EventID,
		e.SchemaVersion,
		e.SourceProduct,
		e.EventType,
		e.AssetID,
		e.OccurredAt,
		e.Severity,
		e.Confidence,
		e.CorrelationID,
		e.SrcIP,
		e.DestIP,
		e.RuleID,
		e.Signature,
		e.Description,
		e.RawRef,
	)

	if err != nil {
		var pgErr interface{ SQLState() string }
		if errors.As(err, &pgErr) && pgErr.SQLState() == "23505" {
			return ErrDuplicate
		}
		return fmt.Errorf("insert event: %w", err)
	}

	return nil
}

func (s *Store) InsertIncident(
	ctx context.Context,
	tenantID string,
	i contract.Incident,
) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ErrTenantRequired
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin incident transaction: %w", err)
	}
	defer tx.Rollback()

	// Resolve event IDs only inside the authenticated tenant.
	eventDBIDs := make([]int64, 0, len(i.EventIDs))

	for _, eventID := range i.EventIDs {
		var dbID int64

		err = tx.QueryRowContext(
			ctx,
			`SELECT id
 FROM events
 WHERE tenant_id = $1::uuid
   AND event_id = $2`,
			tenantID,
			eventID,
		).Scan(&dbID)

		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: %s", ErrUnknownEvent, eventID)
			}
			return fmt.Errorf("resolve referenced event: %w", err)
		}

		eventDBIDs = append(eventDBIDs, dbID)
	}

	// Insert the incident with the authenticated tenant ID.
	var incidentDBID int64

	err = tx.QueryRowContext(ctx, `
INSERT INTO incidents (
tenant_id,
incident_id,
schema_version,
asset_id,
occurred_at,
severity,
confidence,
title,
correlation_id,
description,
playbook_ref,
status
)
VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
RETURNING id
`,
		tenantID,
		i.IncidentID,
		i.SchemaVersion,
		i.AssetID,
		i.OccurredAt,
		i.Severity,
		i.Confidence,
		i.Title,
		i.CorrelationID,
		i.Description,
		i.PlaybookRef,
		i.Status,
	).Scan(&incidentDBID)

	if err != nil {
		var pgErr interface{ SQLState() string }
		if errors.As(err, &pgErr) && pgErr.SQLState() == "23505" {
			return ErrDuplicate
		}
		return fmt.Errorf("insert incident: %w", err)
	}

	// The composite foreign keys also enforce tenant consistency.
	for _, eventDBID := range eventDBIDs {
		_, err = tx.ExecContext(ctx, `
INSERT INTO incident_events (
tenant_id,
incident_id,
event_id
)
VALUES ($1::uuid,$2,$3)
`,
			tenantID,
			incidentDBID,
			eventDBID,
		)

		if err != nil {
			var pgErr interface{ SQLState() string }
			if errors.As(err, &pgErr) {
				switch pgErr.SQLState() {
				case "23503":
					return fmt.Errorf(
						"%w: referenced event or tenant does not exist",
						ErrUnknownEvent,
					)
				case "23505":
					return ErrDuplicate
				}
			}
			return fmt.Errorf("link incident event: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit incident: %w", err)
	}

	return nil
}

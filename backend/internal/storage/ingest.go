package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/contract"
)

var ErrDuplicate = errors.New("record already exists")
var ErrUnknownEvent = errors.New("one or more referenced events do not exist")

func (s *Store) InsertEvent(ctx context.Context, e contract.Event) error {
	_, err := s.DB.ExecContext(ctx, `
INSERT INTO events (
event_id, schema_version, source_product, event_type, asset_id,
occurred_at, severity, confidence, correlation_id, src_ip, dest_ip,
rule_id, signature, description, raw_ref
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
`,
		e.EventID, e.SchemaVersion, e.SourceProduct, e.EventType, e.AssetID,
		e.OccurredAt, e.Severity, e.Confidence, e.CorrelationID, e.SrcIP,
		e.DestIP, e.RuleID, e.Signature, e.Description, e.RawRef,
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

func (s *Store) InsertIncident(ctx context.Context, i contract.Incident) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin incident transaction: %w", err)
	}
	defer tx.Rollback()

	// Resolve external event IDs to internal database IDs.
	eventDBIDs := make([]int64, 0, len(i.EventIDs))

	for _, eventID := range i.EventIDs {
		var dbID int64

		err = tx.QueryRowContext(ctx,
			`SELECT id FROM events WHERE event_id = $1`,
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

	// Insert incident and retrieve its internal database ID.
	var incidentDBID int64

	err = tx.QueryRowContext(ctx, `
INSERT INTO incidents (
incident_id, schema_version, asset_id, occurred_at, severity,
confidence, title, correlation_id, description, playbook_ref, status
)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
RETURNING id
`,
		i.IncidentID, i.SchemaVersion, i.AssetID, i.OccurredAt, i.Severity,
		i.Confidence, i.Title, i.CorrelationID, i.Description,
		i.PlaybookRef, i.Status,
	).Scan(&incidentDBID)

	if err != nil {
		var pgErr interface{ SQLState() string }
		if errors.As(err, &pgErr) && pgErr.SQLState() == "23505" {
			return ErrDuplicate
		}
		return fmt.Errorf("insert incident: %w", err)
	}

	// Link incident and events using internal BIGINT IDs.
	for _, eventDBID := range eventDBIDs {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO incident_events (incident_id, event_id) VALUES ($1,$2)`,
			incidentDBID, eventDBID,
		)

		if err != nil {
			var pgErr interface{ SQLState() string }
			if errors.As(err, &pgErr) {
				switch pgErr.SQLState() {
				case "23503":
					return fmt.Errorf("%w: referenced event was deleted", ErrUnknownEvent)
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

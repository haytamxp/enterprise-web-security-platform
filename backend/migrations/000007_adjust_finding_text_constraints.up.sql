-- 000007_adjust_finding_text_constraints (up)
-- Align optional text fields with the Finding contract.

BEGIN;

ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS findings_description_length_check;

ALTER TABLE findings
    ADD CONSTRAINT findings_description_length_check
    CHECK (
        description IS NULL
        OR char_length(description) <= 10000
    );

ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS findings_remediation_guidance_length_check;

ALTER TABLE findings
    ADD CONSTRAINT findings_remediation_guidance_length_check
    CHECK (
        remediation_guidance IS NULL
        OR char_length(remediation_guidance) <= 10000
    );

COMMIT;
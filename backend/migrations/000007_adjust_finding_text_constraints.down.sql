-- 000007_adjust_finding_text_constraints (down)
-- Restores the original description rule.

BEGIN;

ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS findings_remediation_guidance_length_check;

ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS findings_description_length_check;

ALTER TABLE findings
    ADD CONSTRAINT findings_description_length_check
    CHECK (
        description IS NULL
        OR char_length(description) BETWEEN 1 AND 10000
    );

COMMIT;
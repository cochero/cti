-- 0016: tenants.status gains 'onboarding' (companion to 0015).
--
-- A tenant under the onboarding wizard exists but is not yet live: it can
-- hold ledger entries, legal acceptances, and environment registration,
-- while the console treats non-active as not-in-service. The wizard's
-- final step flips status to 'active' (ledger-recorded).

ALTER TABLE tenants DROP CONSTRAINT tenants_status_check;
ALTER TABLE tenants ADD CONSTRAINT tenants_status_check
    CHECK (status IN ('onboarding', 'active', 'suspended', 'offboarding'));

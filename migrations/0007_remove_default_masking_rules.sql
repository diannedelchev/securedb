-- Email, phone and token columns no longer need masking. Drop the seeded rules
-- from existing deployments; the masking engine additionally exempts any
-- *token* column from every remaining rule (card_token, pan_token, ...).
DELETE FROM masking_rules WHERE lower(column_pattern) IN ('email', 'phone', 'token');

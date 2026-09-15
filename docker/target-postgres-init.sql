-- Demo data for the sample PostgreSQL target. Includes sensitive columns to
-- exercise the masking rules (card, iban, egn); email/phone stay visible.
CREATE SCHEMA IF NOT EXISTS app;

CREATE TABLE app.customers (
    id            SERIAL PRIMARY KEY,
    first_name    TEXT NOT NULL,
    last_name     TEXT NOT NULL,
    email         TEXT NOT NULL,
    phone         TEXT,
    iban          TEXT,
    egn           TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE app.payments (
    id            SERIAL PRIMARY KEY,
    customer_id   INTEGER NOT NULL REFERENCES app.customers(id),
    card_number   TEXT,
    amount        NUMERIC(12,2) NOT NULL,
    currency      TEXT NOT NULL DEFAULT 'EUR',
    status        TEXT NOT NULL DEFAULT 'settled',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE app.api_credentials (
    id            SERIAL PRIMARY KEY,
    customer_id   INTEGER NOT NULL REFERENCES app.customers(id),
    api_token     TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO app.customers (first_name, last_name, email, phone, iban, egn) VALUES
 ('John',  'Doe',      'john.doe@example.com',    '+359881234123', 'BG80BNBG96611020345678', '8001014507'),
 ('Maria', 'Petrova',  'maria.petrova@example.bg','+359887654321', 'BG18RZBB91550123456789', '9105022411'),
 ('Alice', 'Nguyen',   'alice.nguyen@example.io', '+14155550111',  'DE89370400440532013000', NULL),
 ('Bob',   'Smith',    'bob.smith@example.com',   '+442071838750', 'GB29NWBK60161331926819', NULL),
 ('Elena', 'Ivanova',  'elena.iv@example.bg',     '+359899112233', 'BG12BUIN95611000000001', '7502191234');

INSERT INTO app.payments (customer_id, card_number, amount, currency, status) VALUES
 (1, '4111111111111234', 249.99, 'EUR', 'settled'),
 (2, '5500005555551111', 1200.00, 'BGN', 'settled'),
 (3, '340000000000009',  89.50,  'USD', 'pending'),
 (4, '4111111111119999', 15.00,  'GBP', 'failed'),
 (5, '5105105105105100', 560.75, 'BGN', 'settled');

INSERT INTO app.api_credentials (customer_id, api_token, client_secret) VALUES
 (1, 'tok_live_9f8e7d6c5b4a', 'cs_live_1a2b3c4d5e6f'),
 (2, 'tok_live_0a1b2c3d4e5f', 'cs_live_6f5e4d3c2b1a');

CREATE VIEW app.customer_payments AS
SELECT c.id, c.first_name, c.last_name, c.email, p.amount, p.currency, p.status
FROM app.customers c JOIN app.payments p ON p.customer_id = c.id;

CREATE INDEX idx_payments_customer ON app.payments(customer_id);

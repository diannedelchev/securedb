-- Demo data for the sample MySQL target.
CREATE TABLE customers (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    first_name    VARCHAR(80) NOT NULL,
    last_name     VARCHAR(80) NOT NULL,
    email         VARCHAR(160) NOT NULL,
    phone         VARCHAR(40),
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    customer_id   INT NOT NULL,
    total         DECIMAL(12,2) NOT NULL,
    status        VARCHAR(20) NOT NULL DEFAULT 'created',
    card_number   VARCHAR(32),
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_orders_customer FOREIGN KEY (customer_id) REFERENCES customers(id)
);

INSERT INTO customers (first_name, last_name, email, phone) VALUES
 ('Georgi', 'Dimitrov', 'georgi.d@example.bg',  '+359884445566'),
 ('Sara',   'Miller',   'sara.miller@example.com', '+16505550123'),
 ('Petar',  'Stoyanov', 'petar.st@example.bg',  '+359877778899');

INSERT INTO orders (customer_id, total, status, card_number) VALUES
 (1, 340.00, 'shipped',  '4111111111111234'),
 (2, 78.25,  'created',  '5500005555551111'),
 (3, 1999.99,'delivered','4000000000000002');

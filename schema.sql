DROP TABLE IF EXISTS scans;
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    target TEXT,
    results TEXT
);

-- Clients table to store basic client information
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    business_name TEXT NOT NULL,
    business_domain TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    contact_phone TEXT,
    scanner_name TEXT,
    subscription_level TEXT DEFAULT 'basic',
    subscription_status TEXT DEFAULT 'active',
    subscription_start TEXT,
    subscription_end TEXT,
    api_key TEXT UNIQUE,
    created_at TEXT,
    created_by INTEGER,
    updated_at TEXT,
    updated_by INTEGER,
    active BOOLEAN DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

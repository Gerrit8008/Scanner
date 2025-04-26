DROP TABLE IF EXISTS scans;
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    target TEXT,
    results TEXT
);

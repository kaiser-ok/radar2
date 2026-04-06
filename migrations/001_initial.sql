CREATE TABLE IF NOT EXISTS units (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    radar_ip    TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS switches (
    id            INTEGER PRIMARY KEY,
    unit_id       INTEGER NOT NULL REFERENCES units(id) ON DELETE CASCADE,
    name          TEXT,
    ip            TEXT NOT NULL,
    community     TEXT NOT NULL DEFAULT 'public',
    snmp_ver      TEXT NOT NULL DEFAULT '2c',
    vendor        TEXT,
    model         TEXT,
    port_count    INTEGER,
    poe_capable   BOOLEAN DEFAULT 0,
    access_method TEXT NOT NULL DEFAULT 'snmp',
    ssh_user      TEXT,
    ssh_password  TEXT,
    ssh_port      INTEGER DEFAULT 22,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_switches_unit_id ON switches(unit_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_switches_ip ON switches(ip);

CREATE TABLE IF NOT EXISTS blocked_macs (
    id         INTEGER PRIMARY KEY,
    unit_id    INTEGER NOT NULL REFERENCES units(id) ON DELETE CASCADE,
    mac        TEXT NOT NULL,
    switch_id  INTEGER REFERENCES switches(id),
    port       INTEGER,
    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(unit_id, mac)
);

CREATE TABLE IF NOT EXISTS mac_locations (
    id         INTEGER PRIMARY KEY,
    unit_id    INTEGER NOT NULL REFERENCES units(id) ON DELETE CASCADE,
    mac        TEXT NOT NULL,
    switch_id  INTEGER NOT NULL REFERENCES switches(id),
    port       INTEGER NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(unit_id, mac)
);

CREATE INDEX IF NOT EXISTS idx_mac_locations_mac ON mac_locations(mac);

CREATE TABLE IF NOT EXISTS rspan_learned (
    id         INTEGER PRIMARY KEY,
    unit_id    INTEGER NOT NULL,
    mac        TEXT NOT NULL,
    ip         TEXT,
    vlan       INTEGER,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(unit_id, mac)
);

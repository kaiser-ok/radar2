package mib

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Store manages MIB files and cached OID lookups.
type Store struct {
	db      *sql.DB
	parser  *Parser
	mibDir  string // directory where MIB files are stored
}

func NewStore(db *sql.DB, mibDir string) (*Store, error) {
	s := &Store{
		db:     db,
		parser: NewParser(),
		mibDir: mibDir,
	}

	if err := s.createTables(); err != nil {
		return nil, err
	}

	// Load existing MIB files
	if err := s.loadAll(); err != nil {
		fmt.Printf("warning: loading MIBs: %v\n", err)
	}

	return s, nil
}

func (s *Store) createTables() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS mib_modules (
			id         INTEGER PRIMARY KEY,
			name       TEXT NOT NULL UNIQUE,
			file_path  TEXT NOT NULL,
			vendor     TEXT,
			loaded_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS mib_oids (
			id         INTEGER PRIMARY KEY,
			module_id  INTEGER NOT NULL REFERENCES mib_modules(id) ON DELETE CASCADE,
			name       TEXT NOT NULL,
			oid        TEXT NOT NULL,
			type       TEXT,
			access     TEXT,
			status     TEXT,
			description TEXT
		);

		CREATE INDEX IF NOT EXISTS idx_mib_oids_name ON mib_oids(name);
		CREATE INDEX IF NOT EXISTS idx_mib_oids_oid ON mib_oids(oid);
	`)
	return err
}

// loadAll loads all MIB files from all subdirectories.
func (s *Store) loadAll() error {
	entries, err := os.ReadDir(s.mibDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		path := filepath.Join(s.mibDir, entry.Name())
		if entry.IsDir() {
			s.parser.LoadDir(path)
		} else if isMIBFile(entry.Name()) {
			s.parser.ParseFile(path)
		}
	}

	// Cache resolved OIDs to DB
	return s.cacheToDB()
}

// UploadMIB saves a MIB file and parses it.
func (s *Store) UploadMIB(filename string, vendor string, content io.Reader) (*MIBModule, error) {
	// Ensure vendor directory exists
	dir := filepath.Join(s.mibDir, vendor)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create dir %s: %w", dir, err)
	}

	// Write file
	destPath := filepath.Join(dir, filename)
	f, err := os.Create(destPath)
	if err != nil {
		return nil, fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, content); err != nil {
		return nil, fmt.Errorf("write file: %w", err)
	}

	// Parse the new file
	if err := s.parser.ParseFile(destPath); err != nil {
		return nil, fmt.Errorf("parse MIB: %w", err)
	}

	// Re-resolve entire tree (new MIB may provide missing parents)
	s.parser.resolveTree()

	// Update cache
	if err := s.cacheToDB(); err != nil {
		return nil, fmt.Errorf("cache to DB: %w", err)
	}

	// Find the module we just loaded
	for _, mod := range s.parser.modules {
		if mod.File == destPath {
			return mod, nil
		}
	}

	return nil, nil
}

// cacheToDB writes all resolved OIDs to the database.
func (s *Store) cacheToDB() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, mod := range s.parser.modules {
		// Upsert module
		var moduleID int64
		err := tx.QueryRow(
			"SELECT id FROM mib_modules WHERE name = ?", mod.Name,
		).Scan(&moduleID)

		if err == sql.ErrNoRows {
			res, err := tx.Exec(
				"INSERT INTO mib_modules (name, file_path, loaded_at) VALUES (?, ?, ?)",
				mod.Name, mod.File, time.Now(),
			)
			if err != nil {
				continue
			}
			moduleID, _ = res.LastInsertId()
		} else if err != nil {
			continue
		}

		// Delete old OIDs for this module and re-insert
		tx.Exec("DELETE FROM mib_oids WHERE module_id = ?", moduleID)

		for _, entry := range mod.OIDs {
			if entry.OID == "" {
				continue
			}
			tx.Exec(
				"INSERT INTO mib_oids (module_id, name, oid, type, access, status, description) VALUES (?, ?, ?, ?, ?, ?, ?)",
				moduleID, entry.Name, entry.OID, entry.Type, entry.Access, entry.Status, entry.Desc,
			)
		}
	}

	return tx.Commit()
}

// LookupOID resolves a name to numeric OID. Checks parser first, then DB cache.
func (s *Store) LookupOID(name string) string {
	// In-memory first
	if oid := s.parser.LookupOID(name); oid != "" {
		return oid
	}

	// DB cache fallback
	var oid string
	s.db.QueryRow("SELECT oid FROM mib_oids WHERE name = ? LIMIT 1", name).Scan(&oid)
	return oid
}

// LookupName resolves a numeric OID to a name.
func (s *Store) LookupName(oid string) string {
	if name := s.parser.LookupName(oid); name != "" {
		return name
	}
	var name string
	s.db.QueryRow("SELECT name FROM mib_oids WHERE oid = ? LIMIT 1", oid).Scan(&name)
	return name
}

// SearchOIDs searches for OIDs by keyword.
func (s *Store) SearchOIDs(keyword string) []OIDEntry {
	// Combine in-memory and DB results
	results := s.parser.SearchOIDs(keyword)

	rows, err := s.db.Query(
		"SELECT name, oid, type, access, status FROM mib_oids WHERE name LIKE ? OR description LIKE ? LIMIT 100",
		"%"+keyword+"%", "%"+keyword+"%",
	)
	if err != nil {
		return results
	}
	defer rows.Close()

	seen := make(map[string]bool)
	for _, r := range results {
		seen[r.Name] = true
	}

	for rows.Next() {
		var e OIDEntry
		rows.Scan(&e.Name, &e.OID, &e.Type, &e.Access, &e.Status)
		if !seen[e.Name] {
			results = append(results, e)
		}
	}

	return results
}

// ListModules returns all loaded MIB module names.
func (s *Store) ListModules() []ModuleInfo {
	rows, err := s.db.Query("SELECT id, name, file_path, vendor, loaded_at FROM mib_modules ORDER BY name")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var modules []ModuleInfo
	for rows.Next() {
		var m ModuleInfo
		var vendor sql.NullString
		rows.Scan(&m.ID, &m.Name, &m.FilePath, &vendor, &m.LoadedAt)
		m.Vendor = vendor.String
		modules = append(modules, m)
	}
	return modules
}

// DeleteModule removes a MIB module and its cached OIDs.
func (s *Store) DeleteModule(name string) error {
	_, err := s.db.Exec("DELETE FROM mib_modules WHERE name = ?", name)
	return err
}

type ModuleInfo struct {
	ID       int64     `json:"id"`
	Name     string    `json:"name"`
	FilePath string    `json:"file_path"`
	Vendor   string    `json:"vendor,omitempty"`
	LoadedAt time.Time `json:"loaded_at"`
}

func isMIBFile(name string) bool {
	ext := filepath.Ext(name)
	switch ext {
	case ".mib", ".my", ".txt", ".MIB":
		return true
	}
	return false
}

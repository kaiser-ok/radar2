package db

import (
	"database/sql"
	"time"

	"new_radar/internal/model"
)

type BlockedMACRepo struct {
	db *sql.DB
}

func NewBlockedMACRepo(db *sql.DB) *BlockedMACRepo {
	return &BlockedMACRepo{db: db}
}

func (r *BlockedMACRepo) GetByUnit(unitID int64) ([]model.BlockedMAC, error) {
	rows, err := r.db.Query(
		"SELECT id, unit_id, mac, switch_id, port, blocked_at FROM blocked_macs WHERE unit_id = ?", unitID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var macs []model.BlockedMAC
	for rows.Next() {
		var m model.BlockedMAC
		if err := rows.Scan(&m.ID, &m.UnitID, &m.MAC, &m.SwitchID, &m.Port, &m.BlockedAt); err != nil {
			return nil, err
		}
		macs = append(macs, m)
	}
	return macs, rows.Err()
}

func (r *BlockedMACRepo) Block(unitID int64, mac string, switchID *int64, port *int) error {
	_, err := r.db.Exec(
		`INSERT OR REPLACE INTO blocked_macs (unit_id, mac, switch_id, port, blocked_at) VALUES (?, ?, ?, ?, ?)`,
		unitID, mac, switchID, port, time.Now(),
	)
	return err
}

func (r *BlockedMACRepo) Unblock(unitID int64, mac string) error {
	_, err := r.db.Exec("DELETE FROM blocked_macs WHERE unit_id = ? AND mac = ?", unitID, mac)
	return err
}

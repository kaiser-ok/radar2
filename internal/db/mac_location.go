package db

import (
	"database/sql"
	"time"

	"new_radar/internal/model"
)

type MACLocationRepo struct {
	db *sql.DB
}

func NewMACLocationRepo(db *sql.DB) *MACLocationRepo {
	return &MACLocationRepo{db: db}
}

func (r *MACLocationRepo) Find(unitID int64, mac string) (*model.MACLocation, error) {
	var m model.MACLocation
	err := r.db.QueryRow(
		"SELECT id, unit_id, mac, switch_id, port, updated_at FROM mac_locations WHERE unit_id = ? AND mac = ?",
		unitID, mac,
	).Scan(&m.ID, &m.UnitID, &m.MAC, &m.SwitchID, &m.Port, &m.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (r *MACLocationRepo) Upsert(unitID int64, mac string, switchID int64, port int) error {
	_, err := r.db.Exec(
		`INSERT INTO mac_locations (unit_id, mac, switch_id, port, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(unit_id, mac) DO UPDATE SET switch_id=excluded.switch_id, port=excluded.port, updated_at=excluded.updated_at`,
		unitID, mac, switchID, port, time.Now(),
	)
	return err
}

func (r *MACLocationRepo) DeleteByUnit(unitID int64) error {
	_, err := r.db.Exec("DELETE FROM mac_locations WHERE unit_id = ?", unitID)
	return err
}

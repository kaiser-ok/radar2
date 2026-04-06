package db

import (
	"database/sql"
	"time"

	"new_radar/internal/model"
)

type UnitRepo struct {
	db *sql.DB
}

func NewUnitRepo(db *sql.DB) *UnitRepo {
	return &UnitRepo{db: db}
}

func (r *UnitRepo) GetAll() ([]model.Unit, error) {
	rows, err := r.db.Query("SELECT id, name, radar_ip, created_at, updated_at FROM units ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var units []model.Unit
	for rows.Next() {
		var u model.Unit
		var radarIP sql.NullString
		if err := rows.Scan(&u.ID, &u.Name, &radarIP, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		u.RadarIP = radarIP.String
		units = append(units, u)
	}
	return units, rows.Err()
}

func (r *UnitRepo) GetByID(id int64) (*model.Unit, error) {
	var u model.Unit
	var radarIP sql.NullString
	err := r.db.QueryRow(
		"SELECT id, name, radar_ip, created_at, updated_at FROM units WHERE id = ?", id,
	).Scan(&u.ID, &u.Name, &radarIP, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.RadarIP = radarIP.String
	return &u, nil
}

func (r *UnitRepo) Create(name, radarIP string) (*model.Unit, error) {
	now := time.Now()
	res, err := r.db.Exec(
		"INSERT INTO units (name, radar_ip, created_at, updated_at) VALUES (?, ?, ?, ?)",
		name, radarIP, now, now,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &model.Unit{ID: id, Name: name, RadarIP: radarIP, CreatedAt: now, UpdatedAt: now}, nil
}

func (r *UnitRepo) Update(id int64, name, radarIP string) error {
	_, err := r.db.Exec(
		"UPDATE units SET name = ?, radar_ip = ?, updated_at = ? WHERE id = ?",
		name, radarIP, time.Now(), id,
	)
	return err
}

func (r *UnitRepo) Delete(id int64) error {
	_, err := r.db.Exec("DELETE FROM units WHERE id = ?", id)
	return err
}

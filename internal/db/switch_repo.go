package db

import (
	"database/sql"
	"time"

	"new_radar/internal/model"
)

type SwitchRepo struct {
	db *sql.DB
}

func NewSwitchRepo(db *sql.DB) *SwitchRepo {
	return &SwitchRepo{db: db}
}

func (r *SwitchRepo) scanSwitch(row interface{ Scan(...any) error }) (*model.Switch, error) {
	var s model.Switch
	var name, vendor, modelStr, sshUser, sshPass sql.NullString
	var portCount, sshPort sql.NullInt64
	var poeCap sql.NullBool

	err := row.Scan(
		&s.ID, &s.UnitID, &name, &s.IP, &s.Community, &s.SNMPVer,
		&vendor, &modelStr, &portCount, &poeCap,
		&s.AccessMethod, &sshUser, &sshPass, &sshPort,
		&s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	s.Name = name.String
	s.Vendor = vendor.String
	s.Model = modelStr.String
	s.PortCount = int(portCount.Int64)
	s.PoECapable = poeCap.Bool
	s.SSHUser = sshUser.String
	s.SSHPassword = sshPass.String
	s.SSHPort = int(sshPort.Int64)
	if s.SSHPort == 0 {
		s.SSHPort = 22
	}
	return &s, nil
}

const switchColumns = `id, unit_id, name, ip, community, snmp_ver, vendor, model, port_count, poe_capable, access_method, ssh_user, ssh_password, ssh_port, created_at, updated_at`

func (r *SwitchRepo) GetByUnit(unitID int64) ([]model.Switch, error) {
	rows, err := r.db.Query(
		"SELECT "+switchColumns+" FROM switches WHERE unit_id = ? ORDER BY id", unitID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var switches []model.Switch
	for rows.Next() {
		s, err := r.scanSwitch(rows)
		if err != nil {
			return nil, err
		}
		switches = append(switches, *s)
	}
	return switches, rows.Err()
}

func (r *SwitchRepo) GetByID(id int64) (*model.Switch, error) {
	return r.scanSwitch(r.db.QueryRow(
		"SELECT "+switchColumns+" FROM switches WHERE id = ?", id,
	))
}

func (r *SwitchRepo) Create(s *model.Switch) error {
	now := time.Now()
	res, err := r.db.Exec(
		`INSERT INTO switches (unit_id, name, ip, community, snmp_ver, vendor, model, port_count, poe_capable, access_method, ssh_user, ssh_password, ssh_port, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.UnitID, s.Name, s.IP, s.Community, s.SNMPVer,
		s.Vendor, s.Model, s.PortCount, s.PoECapable,
		s.AccessMethod, s.SSHUser, s.SSHPassword, s.SSHPort,
		now, now,
	)
	if err != nil {
		return err
	}
	s.ID, _ = res.LastInsertId()
	s.CreatedAt = now
	s.UpdatedAt = now
	return nil
}

func (r *SwitchRepo) Update(s *model.Switch) error {
	_, err := r.db.Exec(
		`UPDATE switches SET name=?, ip=?, community=?, snmp_ver=?, vendor=?, model=?, port_count=?, poe_capable=?, access_method=?, ssh_user=?, ssh_password=?, ssh_port=?, updated_at=?
		 WHERE id=?`,
		s.Name, s.IP, s.Community, s.SNMPVer,
		s.Vendor, s.Model, s.PortCount, s.PoECapable,
		s.AccessMethod, s.SSHUser, s.SSHPassword, s.SSHPort,
		time.Now(), s.ID,
	)
	return err
}

func (r *SwitchRepo) Delete(id int64) error {
	_, err := r.db.Exec("DELETE FROM switches WHERE id = ?", id)
	return err
}

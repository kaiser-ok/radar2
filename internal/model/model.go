package model

import "time"

type Unit struct {
	ID       int64     `json:"id"`
	Name     string    `json:"name"`
	RadarIP  string    `json:"radar_ip,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Switch struct {
	ID           int64  `json:"id"`
	UnitID       int64  `json:"unit_id"`
	Name         string `json:"name,omitempty"`
	IP           string `json:"ip"`
	Community    string `json:"community"`
	SNMPVer      string `json:"snmp_ver"`
	Vendor       string `json:"vendor,omitempty"`
	Model        string `json:"model,omitempty"`
	PortCount    int    `json:"port_count,omitempty"`
	PoECapable   bool   `json:"poe_capable"`
	AccessMethod string `json:"access_method"`
	SSHUser      string `json:"ssh_user,omitempty"`
	SSHPassword  string `json:"ssh_password,omitempty"`
	SSHPort      int    `json:"ssh_port,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type BlockedMAC struct {
	ID        int64     `json:"id"`
	UnitID    int64     `json:"unit_id"`
	MAC       string    `json:"mac"`
	SwitchID  *int64    `json:"switch_id,omitempty"`
	Port      *int      `json:"port,omitempty"`
	BlockedAt time.Time `json:"blocked_at"`
}

type MACLocation struct {
	ID        int64     `json:"id"`
	UnitID    int64     `json:"unit_id"`
	MAC       string    `json:"mac"`
	SwitchID  int64     `json:"switch_id"`
	Port      int       `json:"port"`
	UpdatedAt time.Time `json:"updated_at"`
}

type RSPANLearned struct {
	ID        int64     `json:"id"`
	UnitID    int64     `json:"unit_id"`
	MAC       string    `json:"mac"`
	IP        string    `json:"ip,omitempty"`
	VLAN      int       `json:"vlan,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type PortInfo struct {
	Index       int    `json:"index"`
	Name        string `json:"name,omitempty"`
	AdminStatus string `json:"admin_status"` // enabled/disabled
	LinkStatus  string `json:"link_status"`  // up/down
	Speed       string `json:"speed,omitempty"`
	Description string `json:"description,omitempty"`
}

type PoEPortInfo struct {
	Port int     `json:"port"`
	Watt float64 `json:"watt"`
}

type FDBEntry struct {
	MAC      string `json:"mac"`
	Port     int    `json:"port"`
	VLAN     int    `json:"vlan,omitempty"`
	Status   string `json:"status,omitempty"`
}

type TaskStatus string

const (
	TaskRunning  TaskStatus = "running"
	TaskFinished TaskStatus = "finish"
)

type Task struct {
	ID     string     `json:"task_id"`
	UnitID string     `json:"unit_id,omitempty"`
	Type   string     `json:"type"`
	Status TaskStatus `json:"exec_status"`
	Output string     `json:"output,omitempty"`
	CreatedAt time.Time `json:"-"`
}

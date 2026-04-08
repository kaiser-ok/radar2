package device

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"new_radar/internal/config"
	"new_radar/internal/model"
	"new_radar/internal/snmp"
	"new_radar/internal/sshcli"

	"github.com/gosnmp/gosnmp"
)

// Executor routes operations through the primary → fallback → verify chain
// defined in device profiles.
type Executor struct {
	snmpClient *snmp.Client
	profiles   *config.ProfileRegistry
}

func NewExecutor(snmpClient *snmp.Client, profiles *config.ProfileRegistry) *Executor {
	return &Executor{
		snmpClient: snmpClient,
		profiles:   profiles,
	}
}

// SNMPClient returns the SNMP client for direct queries.
func (e *Executor) SNMPClient() *snmp.Client {
	return e.snmpClient
}

// DetectProfile detects a device profile from sysObjectID and sysDescr.
func (e *Executor) DetectProfile(sysOID, sysDescr string) *config.DeviceProfile {
	if e.profiles == nil {
		return nil
	}
	return e.profiles.DetectDevice(sysOID, sysDescr)
}

// ExecResult contains the result of executing a capability.
type ExecResult struct {
	Method  string      `json:"method"`  // "snmp" or "ssh"
	Success bool        `json:"success"`
	Output  interface{} `json:"output,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// ReadCapability executes a read operation using the profile-defined method chain.
func (e *Executor) ReadCapability(sw *model.Switch, capability string) *ExecResult {
	profile := e.resolveProfile(sw)
	if profile == nil {
		return &ExecResult{Error: "no profile found for device"}
	}

	mapping := e.getMapping(profile, capability)
	if mapping == nil {
		return &ExecResult{Error: fmt.Sprintf("capability %s not mapped", capability)}
	}

	// Try primary
	if mapping.Primary != nil {
		result := e.executeRead(sw, mapping.Primary)
		if result.Success {
			return result
		}
		slog.Warn("primary read failed, trying fallback", "capability", capability, "error", result.Error)
	}

	// Try fallback
	if mapping.Fallback != nil {
		result := e.executeRead(sw, mapping.Fallback)
		if result.Success {
			return result
		}
		slog.Warn("fallback read failed", "capability", capability, "error", result.Error)
	}

	return &ExecResult{Error: fmt.Sprintf("all methods failed for %s", capability)}
}

// WriteCapability executes a write operation using primary → fallback → verify.
func (e *Executor) WriteCapability(sw *model.Switch, capability string, action string, params map[string]string) *ExecResult {
	profile := e.resolveProfile(sw)
	if profile == nil {
		return &ExecResult{Error: "no profile found for device"}
	}

	mapping := e.getMapping(profile, capability)
	if mapping == nil {
		return &ExecResult{Error: fmt.Sprintf("capability %s not mapped", capability)}
	}

	// Try primary
	if mapping.Primary != nil {
		result := e.executeWrite(sw, mapping.Primary, action, params)
		if result.Success {
			// Verify if defined
			if mapping.Verify != nil {
				verify := e.executeRead(sw, mapping.Verify)
				result.Output = map[string]interface{}{
					"write":  result.Output,
					"verify": verify.Output,
				}
			}
			return result
		}
		slog.Warn("primary write failed, trying fallback", "capability", capability, "error", result.Error)
	}

	// Try fallback
	if mapping.Fallback != nil {
		result := e.executeWrite(sw, mapping.Fallback, action, params)
		if result.Success {
			// Verify if defined
			if mapping.Verify != nil {
				verify := e.executeRead(sw, mapping.Verify)
				result.Output = map[string]interface{}{
					"write":  result.Output,
					"verify": verify.Output,
				}
			}
			return result
		}
		slog.Warn("fallback write failed", "capability", capability, "error", result.Error)
	}

	return &ExecResult{Error: fmt.Sprintf("all methods failed for %s.%s", capability, action)}
}

// ExecuteSSH opens an SSH session and runs commands. Useful for direct CLI operations.
func (e *Executor) ExecuteSSH(sw *model.Switch, commands []string) *ExecResult {
	profile := e.resolveProfile(sw)
	sshCfg := e.buildSSHConfig(sw, profile)

	client, err := sshcli.Dial(sshCfg)
	if err != nil {
		return &ExecResult{Method: "ssh", Error: err.Error()}
	}
	defer client.Close()

	output, err := client.ExecuteCommands(commands)
	if err != nil {
		return &ExecResult{Method: "ssh", Output: output, Error: err.Error()}
	}
	return &ExecResult{Method: "ssh", Success: true, Output: output}
}

// --- Internal ---

func (e *Executor) resolveProfile(sw *model.Switch) *config.DeviceProfile {
	if e.profiles == nil {
		return nil
	}
	// Detect via SNMP fingerprint (uses 4-layer merge: fingerprint → capability → vendor → override)
	results, err := e.snmpClient.Get(sw.IP, sw.Community, snmp.ParseVersion(sw.SNMPVer), []string{
		".1.3.6.1.2.1.1.2.0", // sysObjectID
		".1.3.6.1.2.1.1.1.0", // sysDescr
	})
	if err != nil || len(results) < 2 {
		return nil
	}
	sysOID := results[0].AsString()
	sysDescr := results[1].AsString()
	return e.profiles.DetectDevice(sysOID, sysDescr)
}

func (e *Executor) getMapping(profile *config.DeviceProfile, capability string) *config.CapabilityMapping {
	if profile == nil || profile.Mappings == nil {
		return nil
	}
	m, ok := profile.Mappings[capability]
	if !ok {
		return nil
	}
	// If no Primary is set but top-level method is, wrap it as Primary
	if m.Primary == nil && m.Method != "" {
		m.Primary = &config.MethodConfig{
			Method:      m.Method,
			OIDTemplate: m.OIDTemplate,
			OIDs:        m.OIDs,
			Table:       m.Table,
			Fields:      m.Fields,
			ValueMap:    m.ValueMap,
			Commands:    m.Commands,
		}
	}
	return &m
}

func (e *Executor) executeRead(sw *model.Switch, method *config.MethodConfig) *ExecResult {
	if method == nil {
		return &ExecResult{Error: "nil method"}
	}

	switch method.Method {
	case "snmp":
		return e.snmpRead(sw, method)
	case "ssh":
		return e.sshRead(sw, method)
	default:
		return &ExecResult{Error: fmt.Sprintf("unknown method: %s", method.Method)}
	}
}

func (e *Executor) executeWrite(sw *model.Switch, method *config.MethodConfig, action string, params map[string]string) *ExecResult {
	if method == nil {
		return &ExecResult{Error: "nil method"}
	}

	switch method.Method {
	case "snmp":
		return e.snmpWrite(sw, method, action, params)
	case "ssh":
		return e.sshWrite(sw, method, action, params)
	default:
		return &ExecResult{Error: fmt.Sprintf("unknown method: %s", method.Method)}
	}
}

func (e *Executor) snmpRead(sw *model.Switch, method *config.MethodConfig) *ExecResult {
	ver := snmp.ParseVersion(sw.SNMPVer)

	if method.OIDTemplate != "" {
		results, err := e.snmpClient.Get(sw.IP, sw.Community, ver, []string{method.OIDTemplate})
		if err != nil {
			return &ExecResult{Method: "snmp", Error: err.Error()}
		}
		if len(results) > 0 {
			return &ExecResult{Method: "snmp", Success: true, Output: results[0].AsString()}
		}
	}

	if method.Table != "" {
		results, err := e.snmpClient.BulkWalk(sw.IP, sw.Community, ver, method.Table)
		if err != nil {
			return &ExecResult{Method: "snmp", Error: err.Error()}
		}
		return &ExecResult{Method: "snmp", Success: true, Output: results}
	}

	// Handle OIDs map
	if method.OIDs != nil {
		data := map[string]string{}
		oids := []string{}
		keys := []string{}
		for k, v := range method.OIDs {
			keys = append(keys, k)
			oids = append(oids, v)
		}
		results, err := e.snmpClient.Get(sw.IP, sw.Community, ver, oids)
		if err != nil {
			return &ExecResult{Method: "snmp", Error: err.Error()}
		}
		for i, r := range results {
			if i < len(keys) {
				data[keys[i]] = r.AsString()
			}
		}
		return &ExecResult{Method: "snmp", Success: true, Output: data}
	}

	return &ExecResult{Method: "snmp", Error: "no OID configured"}
}

func (e *Executor) snmpWrite(sw *model.Switch, method *config.MethodConfig, action string, params map[string]string) *ExecResult {
	ver := snmp.ParseVersion(sw.SNMPVer)

	oidTemplate := method.OIDTemplate
	if oidTemplate == "" {
		return &ExecResult{Method: "snmp", Error: "no OID template for write"}
	}

	// Substitute params in OID template
	oid := oidTemplate
	for k, v := range params {
		oid = strings.ReplaceAll(oid, "{"+k+"}", v)
	}

	// Get value from value_map
	val, ok := method.ValueMap[action]
	if !ok {
		return &ExecResult{Method: "snmp", Error: fmt.Sprintf("no value mapped for action %q", action)}
	}

	err := e.snmpClient.Set(sw.IP, sw.Community, ver, oid, gosnmp.Integer, val)
	if err != nil {
		return &ExecResult{Method: "snmp", Error: err.Error()}
	}

	return &ExecResult{Method: "snmp", Success: true, Output: fmt.Sprintf("SET %s = %d", oid, val)}
}

func (e *Executor) sshRead(sw *model.Switch, method *config.MethodConfig) *ExecResult {
	cmds := e.extractCommands(method, "")
	if len(cmds) == 0 {
		return &ExecResult{Method: "ssh", Error: "no SSH commands configured"}
	}

	profile := e.resolveProfile(sw)
	sshCfg := e.buildSSHConfig(sw, profile)

	client, err := sshcli.Dial(sshCfg)
	if err != nil {
		return &ExecResult{Method: "ssh", Error: err.Error()}
	}
	defer client.Close()

	output, err := client.ExecuteCommands(cmds)
	if err != nil {
		return &ExecResult{Method: "ssh", Output: output, Error: err.Error()}
	}
	return &ExecResult{Method: "ssh", Success: true, Output: output}
}

func (e *Executor) sshWrite(sw *model.Switch, method *config.MethodConfig, action string, params map[string]string) *ExecResult {
	cmds := e.extractCommands(method, action)
	if len(cmds) == 0 {
		return &ExecResult{Method: "ssh", Error: fmt.Sprintf("no SSH commands for action %q", action)}
	}

	// Substitute params in commands
	for i, cmd := range cmds {
		for k, v := range params {
			cmd = strings.ReplaceAll(cmd, "{"+k+"}", v)
		}
		cmds[i] = cmd
	}

	profile := e.resolveProfile(sw)
	sshCfg := e.buildSSHConfig(sw, profile)

	client, err := sshcli.Dial(sshCfg)
	if err != nil {
		return &ExecResult{Method: "ssh", Error: err.Error()}
	}
	defer client.Close()

	output, err := client.ExecuteCommands(cmds)
	if err != nil {
		return &ExecResult{Method: "ssh", Output: output, Error: err.Error()}
	}
	return &ExecResult{Method: "ssh", Success: true, Output: output}
}

func (e *Executor) buildSSHConfig(sw *model.Switch, profile *config.DeviceProfile) sshcli.Config {
	cfg := sshcli.Config{
		Host:        sw.IP,
		Port:        sw.SSHPort,
		User:        sw.SSHUser,
		Password:    sw.SSHPassword,
		ReadTimeout: 15 * time.Second,
	}
	if profile != nil && profile.Protocols.SSH.PromptRegex != "" {
		cfg.PromptRegex = profile.Protocols.SSH.PromptRegex
	}
	if profile != nil && profile.Protocols.SSH.PagerDisable != "" {
		cfg.PagerDisable = profile.Protocols.SSH.PagerDisable
	}
	return cfg
}

// extractCommands gets command list from a MethodConfig.
// For reads, action is empty and we get all commands.
// For writes, action selects the specific command list (e.g. "up", "down").
func (e *Executor) extractCommands(method *config.MethodConfig, action string) []string {
	if method.Commands == nil {
		return nil
	}

	switch cmds := method.Commands.(type) {
	case map[string]interface{}:
		if action != "" {
			// Write: get specific action commands
			if v, ok := cmds[action]; ok {
				return toStringSlice(v)
			}
			return nil
		}
		// Read: collect all commands
		var all []string
		for _, v := range cmds {
			all = append(all, toStringSlice(v)...)
		}
		return all
	case []interface{}:
		return toStringSlice(cmds)
	case string:
		return []string{cmds}
	default:
		return nil
	}
}

func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return val
	case string:
		return []string{val}
	default:
		return nil
	}
}

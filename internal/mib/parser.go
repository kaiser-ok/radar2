package mib

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// OIDEntry represents a parsed OID from a MIB file.
type OIDEntry struct {
	Name       string // e.g. "ifAdminStatus"
	OID        string // e.g. "1.3.6.1.2.1.2.2.1.7"
	Parent     string // e.g. "ifEntry"
	SubID      int    // e.g. 7
	Type       string // OBJECT-TYPE syntax, e.g. "INTEGER", "Counter32"
	Access     string // read-only, read-write, etc.
	Status     string // current, deprecated, obsolete
	Desc       string // DESCRIPTION text
	Module     string // MIB module name, e.g. "IF-MIB"
}

// MIBModule represents a parsed MIB module.
type MIBModule struct {
	Name    string
	File    string
	Imports map[string][]string // module -> [imported names]
	OIDs    []OIDEntry
	Nodes   map[string]string   // name -> parent.subid for tree resolution
}

// Parser reads MIB files and extracts OID mappings.
type Parser struct {
	modules map[string]*MIBModule  // module name -> parsed module
	oidTree map[string]string      // name -> resolved numeric OID
}

func NewParser() *Parser {
	p := &Parser{
		modules: make(map[string]*MIBModule),
		oidTree: make(map[string]string),
	}
	// Seed well-known root OIDs
	p.oidTree["iso"] = "1"
	p.oidTree["org"] = "1.3"
	p.oidTree["dod"] = "1.3.6"
	p.oidTree["internet"] = "1.3.6.1"
	p.oidTree["mgmt"] = "1.3.6.1.2"
	p.oidTree["mib-2"] = "1.3.6.1.2.1"
	p.oidTree["system"] = "1.3.6.1.2.1.1"
	p.oidTree["interfaces"] = "1.3.6.1.2.1.2"
	p.oidTree["ip"] = "1.3.6.1.2.1.4"
	p.oidTree["transmission"] = "1.3.6.1.2.1.10"
	p.oidTree["snmpV2"] = "1.3.6.1.6"
	p.oidTree["snmpModules"] = "1.3.6.1.6.3"
	p.oidTree["enterprises"] = "1.3.6.1.4.1"
	p.oidTree["private"] = "1.3.6.1.4"
	p.oidTree["experimental"] = "1.3.6.1.3"
	p.oidTree["directory"] = "1.3.6.1.1"
	p.oidTree["dot1dBridge"] = "1.3.6.1.2.1.17"
	p.oidTree["snmpDot3MauMgt"] = "1.3.6.1.2.1.26"
	return p
}

// regex patterns for MIB parsing
var (
	moduleDefRe   = regexp.MustCompile(`^(\S+)\s+DEFINITIONS\s*::=\s*BEGIN`)
	importsRe     = regexp.MustCompile(`(?s)IMPORTS\s+(.*?)\s*;`)
	objectIDRe    = regexp.MustCompile(`(\w+)\s+OBJECT IDENTIFIER\s*::=\s*\{\s*(\w+)\s+(\d+)\s*\}`)
	objectTypeRe  = regexp.MustCompile(`(\w+)\s+OBJECT-TYPE`)
	syntaxRe      = regexp.MustCompile(`SYNTAX\s+(\S+)`)
	accessRe      = regexp.MustCompile(`(?:MAX-)?ACCESS\s+(\S+)`)
	statusRe      = regexp.MustCompile(`STATUS\s+(\S+)`)
	assignmentRe  = regexp.MustCompile(`::=\s*\{\s*(\w+)\s+(\d+)\s*\}`)
	moduleIdentRe = regexp.MustCompile(`(\w+)\s+MODULE-IDENTITY`)
	notifTypeRe   = regexp.MustCompile(`(\w+)\s+NOTIFICATION-TYPE`)
)

// LoadDir loads all .mib, .my, and .txt MIB files from a directory.
func (p *Parser) LoadDir(dir string) error {
	patterns := []string{"*.mib", "*.my", "*.txt", "*.MIB"}
	var files []string
	for _, pat := range patterns {
		matches, _ := filepath.Glob(filepath.Join(dir, pat))
		files = append(files, matches...)
	}

	// First pass: parse all files
	for _, f := range files {
		if err := p.ParseFile(f); err != nil {
			// Log but continue — some MIBs may have unresolved imports
			fmt.Printf("warning: parse %s: %v\n", f, err)
		}
	}

	// Second pass: resolve OID tree
	p.resolveTree()

	return nil
}

// ParseFile parses a single MIB file.
func (p *Parser) ParseFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	content := string(data)
	mod := &MIBModule{
		File:    path,
		Imports: make(map[string][]string),
		Nodes:   make(map[string]string),
	}

	// Extract module name
	if m := moduleDefRe.FindStringSubmatch(content); m != nil {
		mod.Name = m[1]
	} else {
		// Use filename as fallback
		mod.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}

	// Extract IMPORTS
	if m := importsRe.FindStringSubmatch(content); m != nil {
		parseImports(m[1], mod)
	}

	// Parse line by line for assignments
	scanner := bufio.NewScanner(strings.NewReader(content))
	var currentObj string
	var currentSyntax, currentAccess, currentStatus string
	var inObject bool

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// OBJECT IDENTIFIER assignment (simple node)
		if m := objectIDRe.FindStringSubmatch(trimmed); m != nil {
			name, parent, subIDStr := m[1], m[2], m[3]
			subID, _ := strconv.Atoi(subIDStr)
			mod.Nodes[name] = fmt.Sprintf("%s.%d", parent, subID)
			mod.OIDs = append(mod.OIDs, OIDEntry{
				Name:   name,
				Parent: parent,
				SubID:  subID,
				Module: mod.Name,
			})
			continue
		}

		// MODULE-IDENTITY
		if m := moduleIdentRe.FindStringSubmatch(trimmed); m != nil {
			currentObj = m[1]
			inObject = true
			continue
		}

		// OBJECT-TYPE start
		if m := objectTypeRe.FindStringSubmatch(trimmed); m != nil {
			currentObj = m[1]
			currentSyntax, currentAccess, currentStatus = "", "", ""
			inObject = true
			continue
		}

		// NOTIFICATION-TYPE
		if m := notifTypeRe.FindStringSubmatch(trimmed); m != nil {
			currentObj = m[1]
			inObject = true
			continue
		}

		if inObject {
			if m := syntaxRe.FindStringSubmatch(trimmed); m != nil {
				currentSyntax = m[1]
			}
			if m := accessRe.FindStringSubmatch(trimmed); m != nil {
				currentAccess = m[1]
			}
			if m := statusRe.FindStringSubmatch(trimmed); m != nil {
				currentStatus = m[1]
			}

			// ::= { parent subid } assignment
			if m := assignmentRe.FindStringSubmatch(trimmed); m != nil {
				parent := m[1]
				subID, _ := strconv.Atoi(m[2])
				mod.Nodes[currentObj] = fmt.Sprintf("%s.%d", parent, subID)
				mod.OIDs = append(mod.OIDs, OIDEntry{
					Name:   currentObj,
					Parent: parent,
					SubID:  subID,
					Type:   currentSyntax,
					Access: currentAccess,
					Status: currentStatus,
					Module: mod.Name,
				})
				inObject = false
				currentObj = ""
			}
		}
	}

	p.modules[mod.Name] = mod
	return nil
}

// parseImports extracts FROM clauses from IMPORTS block.
func parseImports(block string, mod *MIBModule) {
	// Format: name1, name2 FROM MODULE-NAME name3 FROM OTHER-MODULE ;
	parts := strings.Split(block, "FROM")
	for i := 1; i < len(parts); i++ {
		// The module name is the first word of this part
		fields := strings.Fields(parts[i])
		if len(fields) == 0 {
			continue
		}
		moduleName := strings.TrimRight(fields[0], ",;")

		// The imported names are in the previous part
		names := strings.Fields(parts[i-1])
		var imported []string
		for _, n := range names {
			n = strings.Trim(n, ",;")
			if n != "" {
				imported = append(imported, n)
			}
		}
		mod.Imports[moduleName] = imported
	}
}

// resolveTree resolves all node names to numeric OIDs.
func (p *Parser) resolveTree() {
	// Merge all module nodes into global tree
	for _, mod := range p.modules {
		for name, parentDotSub := range mod.Nodes {
			if _, exists := p.oidTree[name]; !exists {
				p.oidTree[name] = parentDotSub // temporarily store "parent.subid"
			}
		}
	}

	// Iteratively resolve until no more changes
	for i := 0; i < 20; i++ { // max depth
		changed := false
		for name, val := range p.oidTree {
			// Already fully numeric?
			if isNumericOID(val) {
				continue
			}
			// Format: "parentName.subID"
			dot := strings.LastIndex(val, ".")
			if dot < 0 {
				continue
			}
			parentName := val[:dot]
			subID := val[dot+1:]

			if parentOID, ok := p.oidTree[parentName]; ok && isNumericOID(parentOID) {
				p.oidTree[name] = parentOID + "." + subID
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	// Update OIDEntry.OID fields in all modules
	for _, mod := range p.modules {
		for i := range mod.OIDs {
			if oid, ok := p.oidTree[mod.OIDs[i].Name]; ok && isNumericOID(oid) {
				mod.OIDs[i].OID = oid
			}
		}
	}
}

func isNumericOID(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// LookupOID returns the numeric OID for a given name, or empty string.
func (p *Parser) LookupOID(name string) string {
	if oid, ok := p.oidTree[name]; ok && isNumericOID(oid) {
		return oid
	}
	return ""
}

// LookupName returns the name for a numeric OID, or empty string.
func (p *Parser) LookupName(oid string) string {
	for name, val := range p.oidTree {
		if val == oid {
			return name
		}
	}
	return ""
}

// GetAllOIDs returns all resolved OID entries across all loaded modules.
func (p *Parser) GetAllOIDs() []OIDEntry {
	var all []OIDEntry
	for _, mod := range p.modules {
		for _, entry := range mod.OIDs {
			if entry.OID != "" {
				all = append(all, entry)
			}
		}
	}
	return all
}

// GetModuleOIDs returns resolved OIDs for a specific module.
func (p *Parser) GetModuleOIDs(moduleName string) []OIDEntry {
	mod, ok := p.modules[moduleName]
	if !ok {
		return nil
	}
	var resolved []OIDEntry
	for _, entry := range mod.OIDs {
		if entry.OID != "" {
			resolved = append(resolved, entry)
		}
	}
	return resolved
}

// ListModules returns all loaded module names.
func (p *Parser) ListModules() []string {
	names := make([]string, 0, len(p.modules))
	for name := range p.modules {
		names = append(names, name)
	}
	return names
}

// SearchOIDs finds OID entries matching a keyword in name or description.
func (p *Parser) SearchOIDs(keyword string) []OIDEntry {
	lower := strings.ToLower(keyword)
	var results []OIDEntry
	for _, mod := range p.modules {
		for _, entry := range mod.OIDs {
			if entry.OID != "" &&
				(strings.Contains(strings.ToLower(entry.Name), lower) ||
					strings.Contains(strings.ToLower(entry.Desc), lower)) {
				results = append(results, entry)
			}
		}
	}
	return results
}

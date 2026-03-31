package ubuntu

import (
	"regexp"
	"strings"
)

var ubuntuReleases = map[string]string{
	"dapper":   "6.06",
	"hardy":    "8.04",
	"lucid":    "10.04",
	"precise":  "12.04",
	"quantal":  "12.10",
	"raring":   "13.04",
	"trusty":   "14.04",
	"utopic":   "14.10",
	"vivid":    "15.04",
	"wily":     "15.10",
	"xenial":   "16.04",
	"yakkety":  "16.10",
	"zesty":    "17.04",
	"artful":   "17.10",
	"bionic":   "18.04",
	"cosmic":   "18.10",
	"disco":    "19.04",
	"eoan":     "19.10",
	"focal":    "20.04",
	"groovy":   "20.10",
	"hirsute":  "21.04",
	"impish":   "21.10",
	"jammy":    "22.04",
	"kinetic":  "22.10",
	"lunar":    "23.04",
	"mantic":   "23.10",
	"noble":    "24.04",
	"oracular": "24.10",
	"plucky":   "25.04",
	"questing": "25.10",
}

var severityMap = map[string]string{
	"low":       "Low",
	"medium":    "Medium",
	"high":      "High",
	"critical":  "Critical",
	"unknown":   "Unknown",
	"untriaged": "Unknown",
}

var patchStates = map[string]bool{
	"DNE":          false,
	"needs-triage": true,
	"ignored":      false,
	"not-affected": false,
	"needed":       true,
	"released":     true,
	"pending":      true,
	"active":       true,
	"deferred":     true,
}

var (
	patchesHeaderRegex   = regexp.MustCompile(`^Patches_(\S+)\s*`)
	patchesRegex         = regexp.MustCompile(`^\s*(\S+)_(\S+)\s*:\s+(.+)\s*`)
	patchStateRegex      = regexp.MustCompile(`^\s*(\S+)(\s+.+)?\s*`)
	indentLineRegex      = regexp.MustCompile(`^\s+\S+`)
	packagePriorityRegex = regexp.MustCompile(`^\s*Priority_(\S+)\s*:\s+(\S+)\s*`)
	cveFilenameRegex     = regexp.MustCompile(`^CVE-[0-9]+-[0-9]+$`)
)

type Patch struct {
	Distro   string
	Status   string
	Version  string
	Package  string
	Priority string
}

type CVEFile struct {
	Name           string
	Priority       string
	Patches        []Patch
	IgnoredPatches []Patch
	References     []string
	Description    string
}

func mapNamespace(releaseName string) string {
	dist, ok := ubuntuReleases[releaseName]
	if !ok {
		return ""
	}
	return "ubuntu:" + dist
}

func mapSeverity(priority string) string {
	if sev, ok := severityMap[strings.ToLower(priority)]; ok {
		return sev
	}
	return "Unknown"
}

func checkRelease(releaseName string) bool {
	_, ok := ubuntuReleases[releaseName]
	return ok
}

func checkState(state string) bool {
	return patchStates[state]
}

func getPatchSection(headerLine string) string {
	match := patchesHeaderRegex.FindStringSubmatch(headerLine)
	if match != nil {
		return match[1]
	}
	return ""
}

func checkHeader(expected string, lines []string) bool {
	if len(lines) == 0 {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(lines[0]), expected+":")
}

func parseSimpleKeyValue(expectedKey string, lines []string) (string, []string) {
	if len(lines) == 0 {
		return "", lines
	}
	tokens := strings.SplitN(lines[0], ":", 2)
	if len(tokens) != 2 || tokens[0] != expectedKey {
		return "", lines
	}
	return strings.TrimSpace(tokens[1]), lines[1:]
}

func parseList(header string, lines []string) ([]string, []string) {
	if !checkHeader(header, lines) {
		return nil, lines
	}
	lines = lines[1:]

	var refs []string
	for len(lines) > 0 {
		if indentLineRegex.MatchString(lines[0]) {
			refs = append(refs, strings.TrimSpace(lines[0]))
			lines = lines[1:]
		} else {
			break
		}
	}

	return refs, lines
}

func parseMultilineKeyValue(header string, lines []string) (string, []string) {
	if !checkHeader(header, lines) {
		return "", lines
	}
	lines = lines[1:]

	var content []string
	for len(lines) > 0 && indentLineRegex.MatchString(lines[0]) {
		content = append(content, strings.TrimSpace(lines[0]))
		lines = lines[1:]
	}

	return strings.Join(content, " "), lines
}

func parsePatchSection(lines []string) ([]Patch, []string) {
	var patches []Patch
	var priority string

	for len(lines) > 0 {
		line := strings.TrimSpace(lines[0])
		if line == "" {
			break
		}

		pkgPriority := packagePriorityRegex.FindStringSubmatch(line)
		if pkgPriority != nil {
			pkg := pkgPriority[1]
			priority = pkgPriority[2]
			for i := range patches {
				if patches[i].Package == pkg {
					patches[i].Priority = priority
				}
			}
			lines = lines[1:]
			continue
		}

		match := patchesRegex.FindStringSubmatch(line)
		if match != nil {
			version := ""
			state := match[3]
			statusMatch := patchStateRegex.FindStringSubmatch(match[3])
			if statusMatch != nil && statusMatch[1] != "" {
				state = statusMatch[1]
				if patchStates[state] {
					v := strings.TrimSpace(statusMatch[2])
					if v != "" {
						if len(v) >= 2 && v[0] == '(' && v[len(v)-1] == ')' {
							v = v[1 : len(v)-1]
						}
						version = v
					}
				}
			}

			patches = append(patches, Patch{
				Distro:   match[1],
				Package:  match[2],
				Status:   state,
				Version:  version,
				Priority: priority,
			})
			lines = lines[1:]
		} else {
			break
		}
	}

	return patches, lines
}

func parseCVEFile(cveID string, content string) CVEFile {
	lines := strings.Split(content, "\n")
	parsed := CVEFile{
		Name:     cveID,
		Priority: "Unknown",
	}

	for len(lines) > 0 {
		line := strings.TrimSpace(lines[0])
		if line == "" || strings.HasPrefix(line, "#") {
			lines = lines[1:]
			continue
		}

		section := strings.SplitN(line, ":", 2)[0]

		switch section {
		case "Candidate":
			val, rest := parseSimpleKeyValue("Candidate", lines)
			if val != "" {
				parsed.Name = val
			}
			lines = rest
		case "References":
			refs, rest := parseList("References", lines)
			parsed.References = refs
			lines = rest
		case "Description":
			desc, rest := parseMultilineKeyValue("Description", lines)
			parsed.Description = desc
			lines = rest
		case "Priority":
			val, rest := parseSimpleKeyValue("Priority", lines)
			if val != "" {
				parsed.Priority = val
			}
			lines = rest
		default:
			patchName := getPatchSection(section)
			pMatch := patchesRegex.FindStringSubmatch(line)
			if patchName != "" {
				var patches []Patch
				if checkHeader(section, lines) {
					lines = lines[1:]
					patches, lines = parsePatchSection(lines)
				}
				parsed.Patches = append(parsed.Patches, patches...)
			} else if pMatch != nil && mapNamespace(pMatch[1]) != "" {
				patches, rest := parsePatchSection(lines)
				parsed.Patches = append(parsed.Patches, patches...)
				lines = rest
			} else {
				lines = lines[1:]
			}
		}
	}

	return parsed
}

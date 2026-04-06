package mitre_attack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/shift/vulnz/pkg/grc"
	"github.com/shift/vulnz/pkg/storage"
)

const (
	MITRECatalogURL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
	FrameworkID     = "MITRE_ATT&CK_v14"
)

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string { return "mitre_attack" }

func (p *Provider) Run(ctx context.Context) (int, error) {
	p.logger.Info("fetching MITRE ATT&CK catalog", "url", MITRECatalogURL)
	destPath := filepath.Join(os.TempDir(), "mitre_attack_catalog.json")
	if err := p.download(ctx, MITRECatalogURL, destPath); err != nil {
		p.logger.Warn("MITRE ATT&CK catalog download failed, using embedded controls", "error", err)
		return p.writeEmbedded(ctx)
	}
	defer os.Remove(destPath)
	controls, err := p.parse(destPath)
	if err != nil {
		p.logger.Warn("MITRE ATT&CK catalog parse failed, using embedded controls", "error", err)
		return p.writeEmbedded(ctx)
	}
	return p.writeControls(ctx, controls)
}

func (p *Provider) download(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func (p *Provider) parse(path string) ([]grc.Control, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var stix struct {
		Objects []struct {
			Type            string   `json:"type"`
			ID              string   `json:"id"`
			Name            string   `json:"name"`
			Description     string   `json:"description"`
			XMitrePlatforms []string `json:"x_mitre_platforms"`
		} `json:"objects"`
	}
	if err := json.NewDecoder(f).Decode(&stix); err != nil {
		return nil, fmt.Errorf("decode MITRE ATT&CK catalog: %w", err)
	}
	var controls []grc.Control
	for _, obj := range stix.Objects {
		if obj.Type == "attack-pattern" {
			controls = append(controls, grc.Control{
				Framework:   FrameworkID,
				ControlID:   obj.ID,
				Title:       obj.Name,
				Family:      "Techniques",
				Description: obj.Description,
				Level:       "high",
			})
		}
	}
	return controls, nil
}

func (p *Provider) writeControls(ctx context.Context, controls []grc.Control) (int, error) {
	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}
	p.logger.Info("wrote MITRE ATT&CK controls to storage", "count", count)
	return count, nil
}

func (p *Provider) writeEmbedded(ctx context.Context) (int, error) {
	return p.writeControls(ctx, embeddedMITREControls())
}

func embeddedMITREControls() []grc.Control {
	return []grc.Control{
		// Initial Access
		{Framework: FrameworkID, ControlID: "T1566", Title: "Phishing", Family: "Initial Access", Description: "Adversaries may send phishing messages to gain access to victim systems.", Level: "high", ImplementationGuidance: "Deploy email filtering. Conduct phishing awareness training."},
		{Framework: FrameworkID, ControlID: "T1190", Title: "Exploit Public-Facing Application", Family: "Initial Access", Description: "Adversaries may attempt to exploit a weakness in an Internet-facing host or system.", Level: "high", ImplementationGuidance: "Patch public-facing applications. Deploy WAF."},
		{Framework: FrameworkID, ControlID: "T1133", Title: "External Remote Services", Family: "Initial Access", Description: "Adversaries may leverage external-facing remote services to initially access a network.", Level: "high", ImplementationGuidance: "Secure remote access with MFA. Monitor for anomalous remote access."},
		{Framework: FrameworkID, ControlID: "T1078", Title: "Valid Accounts", Family: "Initial Access", Description: "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining access.", Level: "high", ImplementationGuidance: "Implement MFA. Monitor for anomalous account usage."},
		{Framework: FrameworkID, ControlID: "T1199", Title: "Trusted Relationship", Family: "Initial Access", Description: "Adversaries may breach or otherwise leverage organizations with access to victim networks.", Level: "high", ImplementationGuidance: "Assess third-party security. Implement network segmentation."},

		// Execution
		{Framework: FrameworkID, ControlID: "T1059", Title: "Command and Scripting Interpreter", Family: "Execution", Description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.", Level: "high", ImplementationGuidance: "Restrict scripting languages. Implement application control."},
		{Framework: FrameworkID, ControlID: "T1053", Title: "Scheduled Task/Job", Family: "Execution", Description: "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution.", Level: "high", ImplementationGuidance: "Monitor scheduled task creation. Alert on unusual task patterns."},
		{Framework: FrameworkID, ControlID: "T1106", Title: "Native API", Family: "Execution", Description: "Adversaries may directly interact with the native OS API to execute commands.", Level: "medium", ImplementationGuidance: "Monitor API calls from suspicious processes. Implement EDR."},
		{Framework: FrameworkID, ControlID: "T1204", Title: "User Execution", Family: "Execution", Description: "Adversaries may rely on users to execute files to gain initial access or execute code.", Level: "high", ImplementationGuidance: "Conduct security awareness training. Implement application control."},

		// Persistence
		{Framework: FrameworkID, ControlID: "T1547", Title: "Boot or Logon Autostart Execution", Family: "Persistence", Description: "Adversaries may configure system settings to automatically execute a program during system boot or logon.", Level: "high", ImplementationGuidance: "Monitor autostart locations. Implement file integrity monitoring."},
		{Framework: FrameworkID, ControlID: "T1098", Title: "Account Manipulation", Family: "Persistence", Description: "Adversaries may manipulate accounts to maintain access to victim systems.", Level: "high", ImplementationGuidance: "Monitor account changes. Alert on privilege escalation."},
		{Framework: FrameworkID, ControlID: "T1136", Title: "Create Account", Family: "Persistence", Description: "Adversaries may create an account to maintain access to victim systems.", Level: "high", ImplementationGuidance: "Monitor account creation. Alert on unauthorized accounts."},
		{Framework: FrameworkID, ControlID: "T1546", Title: "Event Triggered Execution", Family: "Persistence", Description: "Adversaries may establish persistence by executing malicious content triggered by specific events.", Level: "high", ImplementationGuidance: "Monitor event subscriptions. Alert on suspicious event triggers."},
		{Framework: FrameworkID, ControlID: "T1556", Title: "Modify Authentication Process", Family: "Persistence", Description: "Adversaries may modify authentication mechanisms to access user credentials or enable otherwise unwarranted access.", Level: "high", ImplementationGuidance: "Monitor authentication configuration changes. Implement integrity monitoring."},
		{Framework: FrameworkID, ControlID: "T1053.005", Title: "Scheduled Task", Family: "Persistence", Description: "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution.", Level: "high", ImplementationGuidance: "Monitor Windows Task Scheduler. Alert on suspicious tasks."},

		// Privilege Escalation
		{Framework: FrameworkID, ControlID: "T1068", Title: "Exploitation for Privilege Escalation", Family: "Privilege Escalation", Description: "Adversaries may exploit software vulnerabilities to gain elevated privileges.", Level: "high", ImplementationGuidance: "Patch systems promptly. Implement least privilege."},
		{Framework: FrameworkID, ControlID: "T1548", Title: "Abuse Elevation Control Mechanism", Family: "Privilege Escalation", Description: "Adversaries may circumvent mechanisms designed to control privilege usage.", Level: "high", ImplementationGuidance: "Monitor UAC bypass attempts. Implement application control."},
		{Framework: FrameworkID, ControlID: "T1134", Title: "Access Token Manipulation", Family: "Privilege Escalation", Description: "Adversaries may modify access tokens to operate under a different user context.", Level: "high", ImplementationGuidance: "Monitor token manipulation. Implement process monitoring."},

		// Defense Evasion
		{Framework: FrameworkID, ControlID: "T1027", Title: "Obfuscated Files or Information", Family: "Defense Evasion", Description: "Adversaries may attempt to make their payload or activity difficult to detect.", Level: "high", ImplementationGuidance: "Deploy advanced malware detection. Analyze suspicious files in sandbox."},
		{Framework: FrameworkID, ControlID: "T1070", Title: "Indicator Removal", Family: "Defense Evasion", Description: "Adversaries may delete or alter generated artifacts on a host system.", Level: "high", ImplementationGuidance: "Centralize logs. Implement log integrity protection."},
		{Framework: FrameworkID, ControlID: "T1562", Title: "Impair Defenses", Family: "Defense Evasion", Description: "Adversaries may maliciously modify components of a victim environment to evade defenses.", Level: "high", ImplementationGuidance: "Monitor security tool status. Alert on security tool disablement."},
		{Framework: FrameworkID, ControlID: "T1036", Title: "Masquerading", Family: "Defense Evasion", Description: "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate.", Level: "high", ImplementationGuidance: "Verify file signatures. Monitor for suspicious process names."},
		{Framework: FrameworkID, ControlID: "T1553", Title: "Subvert Trust Controls", Family: "Defense Evasion", Description: "Adversaries may modify trust mechanisms to evade detection and establish persistence.", Level: "high", ImplementationGuidance: "Monitor trust configuration changes. Implement code signing verification."},
		{Framework: FrameworkID, ControlID: "T1564", Title: "Hide Artifacts", Family: "Defense Evasion", Description: "Adversaries may attempt to hide artifacts associated with their behaviors.", Level: "high", ImplementationGuidance: "Monitor for hidden files and processes. Implement comprehensive logging."},

		// Credential Access
		{Framework: FrameworkID, ControlID: "T1003", Title: "OS Credential Dumping", Family: "Credential Access", Description: "Adversaries may attempt to dump credentials to obtain account login and credential material.", Level: "high", ImplementationGuidance: "Protect LSASS. Implement Credential Guard. Monitor for credential dumping."},
		{Framework: FrameworkID, ControlID: "T1110", Title: "Brute Force", Family: "Credential Access", Description: "Adversaries may use brute force techniques to gain access to accounts.", Level: "high", ImplementationGuidance: "Implement account lockout. Deploy MFA. Monitor for brute force patterns."},
		{Framework: FrameworkID, ControlID: "T1557", Title: "Adversary-in-the-Middle", Family: "Credential Access", Description: "Adversaries may attempt to position themselves between two networked devices to intercept data.", Level: "high", ImplementationGuidance: "Implement network segmentation. Use mutual TLS. Monitor for ARP spoofing."},
		{Framework: FrameworkID, ControlID: "T1558", Title: "Steal or Forge Kerberos Credentials", Family: "Credential Access", Description: "Adversaries may abuse Kerberos authentication to obtain credentials or forge tickets.", Level: "high", ImplementationGuidance: "Monitor for Kerberoasting. Implement strong password policies."},
		{Framework: FrameworkID, ControlID: "T1528", Title: "Steal Application Access Token", Family: "Credential Access", Description: "Adversaries can steal application access tokens as part of obtaining credentials.", Level: "high", ImplementationGuidance: "Monitor token access. Implement least privilege for service accounts."},

		// Discovery
		{Framework: FrameworkID, ControlID: "T1087", Title: "Account Discovery", Family: "Discovery", Description: "Adversaries may attempt to get a listing of domain or local accounts.", Level: "medium", ImplementationGuidance: "Monitor account enumeration commands. Alert on suspicious discovery activity."},
		{Framework: FrameworkID, ControlID: "T1082", Title: "System Information Discovery", Family: "Discovery", Description: "Adversaries may attempt to get detailed information about the operating system and hardware.", Level: "medium", ImplementationGuidance: "Monitor system enumeration commands. Implement process monitoring."},
		{Framework: FrameworkID, ControlID: "T1046", Title: "Network Service Discovery", Family: "Discovery", Description: "Adversaries may attempt to get a listing of services running on remote hosts.", Level: "medium", ImplementationGuidance: "Monitor for network scanning. Deploy IDS/IPS."},
		{Framework: FrameworkID, ControlID: "T1018", Title: "Remote System Discovery", Family: "Discovery", Description: "Adversaries may attempt to get a listing of other systems by IP address or hostname.", Level: "medium", ImplementationGuidance: "Monitor for network discovery commands. Implement network segmentation."},
		{Framework: FrameworkID, ControlID: "T1482", Title: "Domain Trust Discovery", Family: "Discovery", Description: "Adversaries may attempt to gather information on domain trust relationships.", Level: "medium", ImplementationGuidance: "Monitor for trust enumeration commands. Restrict domain query access."},

		// Lateral Movement
		{Framework: FrameworkID, ControlID: "T1021", Title: "Remote Services", Family: "Lateral Movement", Description: "Adversaries may use valid accounts to log into remote services to move laterally.", Level: "high", ImplementationGuidance: "Restrict remote access. Monitor for lateral movement patterns."},
		{Framework: FrameworkID, ControlID: "T1570", Title: "Lateral Tool Transfer", Family: "Lateral Movement", Description: "Adversaries may transfer tools or other files between systems in a compromised environment.", Level: "high", ImplementationGuidance: "Monitor file transfers between systems. Implement network segmentation."},
		{Framework: FrameworkID, ControlID: "T1080", Title: "Taint Shared Content", Family: "Lateral Movement", Description: "Adversaries may deliver payloads to remote systems by adding content to shared drives.", Level: "high", ImplementationGuidance: "Monitor shared content access. Implement file integrity monitoring."},

		// Collection
		{Framework: FrameworkID, ControlID: "T1005", Title: "Data from Local System", Family: "Collection", Description: "Adversaries may search local systems for files of interest to collect.", Level: "high", ImplementationGuidance: "Monitor file access patterns. Implement DLP controls."},
		{Framework: FrameworkID, ControlID: "T1114", Title: "Email Collection", Family: "Collection", Description: "Adversaries may target user email to collect sensitive information.", Level: "high", ImplementationGuidance: "Monitor email access patterns. Implement email security controls."},
		{Framework: FrameworkID, ControlID: "T1119", Title: "Automated Collection", Family: "Collection", Description: "Adversaries may use automated techniques to collect data from a compromised system.", Level: "high", ImplementationGuidance: "Monitor for automated data collection. Implement file access monitoring."},
		{Framework: FrameworkID, ControlID: "T1530", Title: "Data from Cloud Storage", Family: "Collection", Description: "Adversaries may access data from cloud storage services to collect sensitive information.", Level: "high", ImplementationGuidance: "Monitor cloud storage access. Implement cloud DLP."},
		{Framework: FrameworkID, ControlID: "T1113", Title: "Screen Capture", Family: "Collection", Description: "Adversaries may attempt to take screen captures to collect information.", Level: "medium", ImplementationGuidance: "Monitor for screen capture APIs. Implement endpoint protection."},

		// Command and Control
		{Framework: FrameworkID, ControlID: "T1071", Title: "Application Layer Protocol", Family: "Command and Control", Description: "Adversaries may communicate using OSI application layer protocols to avoid detection.", Level: "high", ImplementationGuidance: "Monitor for anomalous protocol usage. Implement network traffic analysis."},
		{Framework: FrameworkID, ControlID: "T1573", Title: "Encrypted Channel", Family: "Command and Control", Description: "Adversaries may employ a known encryption algorithm to conceal command and control traffic.", Level: "high", ImplementationGuidance: "Monitor encrypted traffic patterns. Implement TLS inspection where appropriate."},
		{Framework: FrameworkID, ControlID: "T1090", Title: "Proxy", Family: "Command and Control", Description: "Adversaries may use proxy servers to redirect network traffic and hide C2 infrastructure.", Level: "high", ImplementationGuidance: "Monitor for proxy usage. Implement egress filtering."},
		{Framework: FrameworkID, ControlID: "T1572", Title: "Protocol Tunneling", Family: "Command and Control", Description: "Adversaries may tunnel network communications to encapsulate and hide traffic.", Level: "high", ImplementationGuidance: "Monitor for tunneling protocols. Implement deep packet inspection."},
		{Framework: FrameworkID, ControlID: "T1105", Title: "Ingress Tool Transfer", Family: "Command and Control", Description: "Adversaries may transfer tools or other files from a controlled system to a compromised system.", Level: "high", ImplementationGuidance: "Monitor file downloads. Implement egress filtering."},
		{Framework: FrameworkID, ControlID: "T1095", Title: "Non-Application Layer Protocol", Family: "Command and Control", Description: "Adversaries may use non-application layer protocols for C2 communications.", Level: "high", ImplementationGuidance: "Monitor for unusual protocol usage. Implement network segmentation."},

		// Exfiltration
		{Framework: FrameworkID, ControlID: "T1041", Title: "Exfiltration Over C2 Channel", Family: "Exfiltration", Description: "Adversaries may steal data by exfiltrating it over an existing command and control channel.", Level: "high", ImplementationGuidance: "Monitor for data exfiltration patterns. Implement DLP."},
		{Framework: FrameworkID, ControlID: "T1048", Title: "Exfiltration Over Alternative Protocol", Family: "Exfiltration", Description: "Adversaries may steal data by exfiltrating it over a different protocol than the C2 channel.", Level: "high", ImplementationGuidance: "Monitor egress traffic. Implement DLP controls."},
		{Framework: FrameworkID, ControlID: "T1567", Title: "Exfiltration Over Web Service", Family: "Exfiltration", Description: "Adversaries may use web services to exfiltrate data.", Level: "high", ImplementationGuidance: "Monitor cloud storage uploads. Implement DLP for web services."},
		{Framework: FrameworkID, ControlID: "T1029", Title: "Scheduled Transfer", Family: "Exfiltration", Description: "Adversaries may schedule data exfiltration to occur at specific times.", Level: "high", ImplementationGuidance: "Monitor scheduled data transfers. Alert on unusual transfer patterns."},

		// Impact
		{Framework: FrameworkID, ControlID: "T1486", Title: "Data Encrypted for Impact", Family: "Impact", Description: "Adversaries may encrypt data on target systems to interrupt availability.", Level: "high", ImplementationGuidance: "Maintain offline backups. Deploy ransomware detection. Implement EDR."},
		{Framework: FrameworkID, ControlID: "T1490", Title: "Inhibit System Recovery", Family: "Impact", Description: "Adversaries may delete or remove built-in OS data to prevent system recovery.", Level: "high", ImplementationGuidance: "Protect backup infrastructure. Monitor for shadow copy deletion."},
		{Framework: FrameworkID, ControlID: "T1499", Title: "Endpoint Denial of Service", Family: "Impact", Description: "Adversaries may perform DoS attacks to reduce availability of systems.", Level: "high", ImplementationGuidance: "Implement rate limiting. Deploy DDoS mitigation."},
		{Framework: FrameworkID, ControlID: "T1565", Title: "Data Manipulation", Family: "Impact", Description: "Adversaries may insert, delete, or manipulate data to influence outcomes.", Level: "high", ImplementationGuidance: "Implement data integrity monitoring. Maintain data backups."},
		{Framework: FrameworkID, ControlID: "T1485", Title: "Data Destruction", Family: "Impact", Description: "Adversaries may destroy data and files on specific systems or networks.", Level: "high", ImplementationGuidance: "Implement backup and recovery. Monitor for mass file deletion."},
		{Framework: FrameworkID, ControlID: "T1496", Title: "Resource Hijacking", Family: "Impact", Description: "Adversaries may leverage computing resources from compromised systems for their own benefit.", Level: "medium", ImplementationGuidance: "Monitor for anomalous resource usage. Implement resource quotas."},
		{Framework: FrameworkID, ControlID: "T1498", Title: "Network Denial of Service", Family: "Impact", Description: "Adversaries may perform DoS attacks to reduce availability of network resources.", Level: "high", ImplementationGuidance: "Deploy DDoS mitigation. Implement traffic rate limiting."},
	}
}

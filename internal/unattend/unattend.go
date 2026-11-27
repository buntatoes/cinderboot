// SPDX-License-Identifier: GPL-3.0-only
package unattend

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// Options configures optional Windows 10/11 Setup customizations written to autounattend.xml.
type Options struct {
	BypassRequirements bool   `json:"bypass_requirements"` // Skip TPM 2.0, Secure Boot, and 4 GiB RAM checks
	BypassMSA          bool   `json:"bypass_msa"`          // Allow local account without Microsoft Account / internet
	DisableBitLocker   bool   `json:"disable_bitlocker"`   // Prevent automatic BitLocker device encryption
	SkipPrivacy        bool   `json:"skip_privacy"`        // Skip OOBE privacy prompts
	LocalUsername      string `json:"local_username,omitempty"`
}

// Enabled reports whether any Windows customization option is active.
func (o Options) Enabled() bool {
	return o.BypassRequirements || o.BypassMSA || o.DisableBitLocker || o.SkipPrivacy || strings.TrimSpace(o.LocalUsername) != ""
}

// Generate produces a valid Microsoft Windows Setup autounattend.xml document.
func Generate(o Options) ([]byte, error) {
	if !o.Enabled() {
		return nil, nil
	}

	var peCmds []string
	addPE := func(desc, cmd string) {
		order := len(peCmds) + 1
		peCmds = append(peCmds, fmt.Sprintf(
			"        <RunSynchronousCommand wcm:action=\"add\">\n"+
				"          <Order>%d</Order>\n"+
				"          <Description>%s</Description>\n"+
				"          <Path>%s</Path>\n"+
				"        </RunSynchronousCommand>",
			order, escapeXML(desc), escapeXML(cmd),
		))
	}

	if o.BypassRequirements {
		addPE("Bypass TPM 2.0 Check", `reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 1 /f`)
		addPE("Bypass Secure Boot Check", `reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 1 /f`)
		addPE("Bypass RAM Check", `reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassRAMCheck /t REG_DWORD /d 1 /f`)
		addPE("Bypass Storage Check", `reg add "HKLM\SYSTEM\Setup\LabConfig" /v BypassStorageCheck /t REG_DWORD /d 1 /f`)
	}

	var specCmds []string
	addSpec := func(desc, cmd string) {
		order := len(specCmds) + 1
		specCmds = append(specCmds, fmt.Sprintf(
			"        <RunSynchronousCommand wcm:action=\"add\">\n"+
				"          <Order>%d</Order>\n"+
				"          <Description>%s</Description>\n"+
				"          <Path>%s</Path>\n"+
				"        </RunSynchronousCommand>",
			order, escapeXML(desc), escapeXML(cmd),
		))
	}

	if o.BypassMSA {
		addSpec("Allow Local Account (BypassNRO)", `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f`)
	}
	if o.DisableBitLocker {
		addSpec("Disable Automatic BitLocker Encryption", `reg add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /v PreventDeviceEncryption /t REG_DWORD /d 1 /f`)
	}

	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
	b.WriteString("<unattend xmlns=\"urn:schemas-microsoft-com:unattend\" xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\">\n")

	if len(peCmds) > 0 {
		b.WriteString("  <settings pass=\"windowsPE\">\n")
		b.WriteString("    <component name=\"Microsoft-Windows-Setup\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\">\n")
		b.WriteString("      <RunSynchronous>\n")
		b.WriteString(strings.Join(peCmds, "\n") + "\n")
		b.WriteString("      </RunSynchronous>\n")
		b.WriteString("    </component>\n")
		b.WriteString("  </settings>\n")
	}

	if len(specCmds) > 0 {
		b.WriteString("  <settings pass=\"specialize\">\n")
		b.WriteString("    <component name=\"Microsoft-Windows-Deployment\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\">\n")
		b.WriteString("      <RunSynchronous>\n")
		b.WriteString(strings.Join(specCmds, "\n") + "\n")
		b.WriteString("      </RunSynchronous>\n")
		b.WriteString("    </component>\n")
		b.WriteString("  </settings>\n")
	}

	user := sanitizeLocalUsername(o.LocalUsername)
	if o.SkipPrivacy || user != "" {
		b.WriteString("  <settings pass=\"oobeSystem\">\n")
		b.WriteString("    <component name=\"Microsoft-Windows-Shell-Setup\" processorArchitecture=\"amd64\" publicKeyToken=\"31bf3856ad364e35\" language=\"neutral\" versionScope=\"nonSxS\">\n")
		if o.SkipPrivacy {
			b.WriteString("      <OOBE>\n")
			b.WriteString("        <HideEULAPage>true</HideEULAPage>\n")
			b.WriteString("        <HideLocalAccountScreen>false</HideLocalAccountScreen>\n")
			b.WriteString("        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>\n")
			b.WriteString("        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>\n")
			b.WriteString("        <ProtectYourPC>3</ProtectYourPC>\n")
			b.WriteString("      </OOBE>\n")
		}
		if user != "" {
			b.WriteString("      <UserAccounts>\n")
			b.WriteString("        <LocalAccounts>\n")
			b.WriteString("          <LocalAccount wcm:action=\"add\">\n")
			b.WriteString(fmt.Sprintf("            <Name>%s</Name>\n", escapeXML(user)))
			b.WriteString("            <Group>Administrators</Group>\n")
			b.WriteString("            <Password>\n")
			b.WriteString("              <Value></Value>\n")
			b.WriteString("              <PlainText>true</PlainText>\n")
			b.WriteString("            </Password>\n")
			b.WriteString("          </LocalAccount>\n")
			b.WriteString("        </LocalAccounts>\n")
			b.WriteString("      </UserAccounts>\n")
		}
		b.WriteString("    </component>\n")
		b.WriteString("  </settings>\n")
	}

	b.WriteString("</unattend>\n")
	out := []byte(b.String())

	// Validate XML syntax before returning.
	dec := xml.NewDecoder(bytes.NewReader(out))
	for {
		if _, err := dec.Token(); err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("generated invalid autounattend.xml: %w", err)
		}
	}
	return out, nil
}

func escapeXML(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

func sanitizeLocalUsername(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 20 {
		s = s[:20]
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == ' ' {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

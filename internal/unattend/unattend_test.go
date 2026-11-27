// SPDX-License-Identifier: GPL-3.0-only
package unattend

import (
	"strings"
	"testing"
)

func TestGenerateAutoUnattend(t *testing.T) {
	if out, err := Generate(Options{}); err != nil || out != nil {
		t.Fatalf("expected nil output when disabled, got len=%d err=%v", len(out), err)
	}

	xmlBytes, err := Generate(Options{
		BypassRequirements: true,
		BypassMSA:          true,
		DisableBitLocker:   true,
		SkipPrivacy:        true,
		LocalUsername:      "AdminUser",
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	s := string(xmlBytes)
	for _, want := range []string{
		"BypassTPMCheck",
		"BypassSecureBootCheck",
		"BypassRAMCheck",
		"BypassNRO",
		"PreventDeviceEncryption",
		"<ProtectYourPC>3</ProtectYourPC>",
		"<Name>AdminUser</Name>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("generated XML missing expected snippet %q", want)
		}
	}
}

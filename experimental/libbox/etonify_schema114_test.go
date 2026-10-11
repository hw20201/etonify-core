//go:build with_quic && with_utls

package libbox

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// The client tests migrate input -> expected using this same corpus. The core
// consumes only the normalized output: it must not implement a second importer.
func TestEtonifyAndroidConfigCorpusSchema114(t *testing.T) {
	content, err := os.ReadFile("testdata/etonify_schema114.json")
	require.NoError(t, err)
	var cases []struct {
		Name     string         `json:"name"`
		Expected map[string]any `json:"expected"`
	}
	require.NoError(t, json.Unmarshal(content, &cases))
	require.NotEmpty(t, cases)
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			selector := map[string]any{"type": "selector", "tag": "select", "outbounds": []string{"proxy"}}
			config := etonifyConfig(nil, []any{selector, tc.Expected})
			encoded, err := json.Marshal(config)
			require.NoError(t, err)
			require.NoError(t, CheckConfig(string(encoded)))
		})
	}
}

func TestEtonifyAndroidConfigCorpusTUNDNSModes(t *testing.T) {
	for _, mode := range []string{"", "disabled", "hijack", "native"} {
		for _, autoRoute := range []bool{false, true} {
			name := mode
			if name == "" {
				name = "default"
			}
			if autoRoute {
				name += "/auto-route"
			} else {
				name += "/no-auto-route"
			}
			t.Run(name, func(t *testing.T) {
				inbound := etonifyTUNInbound("")
				delete(inbound, "stack")
				inbound["auto_route"] = autoRoute
				if mode != "" {
					inbound["dns_mode"] = mode
				}
				encoded, err := json.Marshal(etonifyConfig([]any{inbound}, []any{etonifySelector(), etonifyDirect()}))
				require.NoError(t, err)
				require.NoError(t, CheckConfig(string(encoded)))
			})
		}
	}
}

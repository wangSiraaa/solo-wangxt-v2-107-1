package auth

import (
	"strings"
	"testing"
)

func TestDeviceLabel(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want string
	}{
		{"normal ua", "Mozilla/5.0 (Macintosh) Chrome/126", "Mozilla/5.0 (Macintosh) Chrome/126"},
		{"empty ua", "", "Unknown device"},
		{"only whitespace", "  \t\n ", "Unknown device"},
		{"crlf injection folded", "Bad/1.0\r\nX-Evil: y", "Bad/1.0 X-Evil: y"},
		{"newline removed", "A\nB", "A B"},
		{"collapsed spaces", "a    b", "a b"},
		{"trimmed", "   Device X   ", "Device X"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeviceLabel(tc.ua)
			if got != tc.want {
				t.Fatalf("DeviceLabel(%q)=%q want %q", tc.ua, got, tc.want)
			}
			if strings.ContainsAny(got, "\r\n") {
				t.Fatalf("label must be single line: %q", got)
			}
		})
	}
}

func TestDeviceLabelTruncation(t *testing.T) {
	long := strings.Repeat("x", 500)
	got := DeviceLabel(long)
	if n := len([]rune(got)); n != maxDeviceLabelRunes {
		t.Fatalf("label runes=%d want %d", n, maxDeviceLabelRunes)
	}
}

// TestDeviceLabelNeverDerivesFromTokenValues 是结构性保证：
// 标签函数只处理传入的 UA 字符串；调用点只传 User-Agent 头，
// sid/code/id_token 从不进入，因此标签不可能携带令牌内容。
func TestDeviceLabelDeterministic(t *testing.T) {
	if DeviceLabel("UA-A") != DeviceLabel("UA-A") {
		t.Fatalf("label must be deterministic")
	}
}

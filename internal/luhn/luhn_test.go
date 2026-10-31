package luhn

import "testing"

func TestValid(t *testing.T) {
	tests := []struct {
		number string
		want   bool
	}{
		{"12345678903", true},
		{"2377225624", true},
		{"9278923470", true},
		{"0", true},
		{"12345678904", false},
		{"2377225625", false},
		{"", false},
		{"1234a678903", false},
		{" 12345678903", false},
		{"-12345678903", false},
	}
	for _, tt := range tests {
		if got := Valid(tt.number); got != tt.want {
			t.Errorf("Valid(%q) = %v, want %v", tt.number, got, tt.want)
		}
	}
}

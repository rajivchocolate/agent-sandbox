package api

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDuration_MarshalJSON(t *testing.T) {
	d := Duration{Duration: 10 * time.Second}
	b, err := d.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `"10s"`
	if string(b) != want {
		t.Errorf("MarshalJSON() = %s, want %s", b, want)
	}
}

func TestDuration_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		input   string
		want    time.Duration
		wantErr bool
	}{
		{`"10s"`, 10 * time.Second, false},
		{`"500ms"`, 500 * time.Millisecond, false},
		{`"1m"`, time.Minute, false},
		{`"not-a-duration"`, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var d Duration
			err := json.Unmarshal([]byte(tt.input), &d)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && d.Duration != tt.want {
				t.Errorf("UnmarshalJSON(%s) = %s, want %s", tt.input, d.Duration, tt.want)
			}
		})
	}
}

func TestDuration_RoundTrip(t *testing.T) {
	original := Duration{Duration: 30 * time.Second}

	b, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Duration
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Duration != original.Duration {
		t.Errorf("round trip: got %s, want %s", decoded.Duration, original.Duration)
	}
}

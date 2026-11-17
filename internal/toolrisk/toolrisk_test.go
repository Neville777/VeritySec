package toolrisk

import "testing"

func TestCVSSBaseScores(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H": 9.6,
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for vec, want := range cases {
		got, ok := cvss3Base(vec)
		if !ok || got != want {
			t.Fatalf("%s: got %v ok=%v, want %v", vec, got, ok, want)
		}
	}
	if _, ok := cvss3Base("not-a-vector"); ok {
		t.Fatal("invalid vector must be rejected")
	}
}

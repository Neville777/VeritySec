package vision

import "testing"

func TestLooksLikeCaptchaQuestion(t *testing.T) {
	if !looksLikeCaptchaQuestion("identify the captcha, output only characters") {
		t.Fatal("expected captcha hint")
	}
	if looksLikeCaptchaQuestion("describe the login page layout") {
		t.Fatal("expected non-captcha")
	}
}

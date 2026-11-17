package c2

import (
	"encoding/base64"
	"os"
)

// Purpose of these thin wrappers:
//   - Make the logic in manager.go / handler more readable and avoid importing os repeatedly;
//   - Make it easier to abstract behind an interface later (for example an internal/storage implementation) for unit tests.

func osMkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func osWriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

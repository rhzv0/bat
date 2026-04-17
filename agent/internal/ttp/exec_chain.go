package ttp

import (
	"fmt"
	"os/exec"
	"strings"
)

// ExecChain runs a sequence of commands that Aura's exec_trace probe will detect.
func ExecChain() (string, error) {
	commands := []struct {
		name string
		args []string
	}{
		{"sh", []string{"-c", "id"}},
		{"python3", []string{"-c", "import os; print(os.getpid())"}},
		{"sleep", []string{"1"}},
	}

	var out strings.Builder
	for _, c := range commands {
		cmd := exec.Command(c.name, c.args...)
		result, err := cmd.CombinedOutput()
		out.WriteString(fmt.Sprintf("[%s] %s\n", c.name, strings.TrimSpace(string(result))))
		if err != nil {
			out.WriteString(fmt.Sprintf("[%s] error: %v\n", c.name, err))
		}
	}
	return out.String(), nil
}

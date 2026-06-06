package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	// Read our own PID's memory map from /proc
	pid := os.Getpid()
	path := fmt.Sprintf("/proc/%d/maps", pid)

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}

	lines := strings.Split(string(data), "\n")
	fmt.Printf("PID %d has %d memory regions:\n\n", pid, len(lines))

	for i, line := range lines {
		if line == "" {
			continue
		}
		fmt.Printf("[%d] %s\n", i+1, line)
	}

	_ = strconv.Itoa(pid) // just to use the import
}
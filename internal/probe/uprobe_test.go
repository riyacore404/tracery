package probe

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
)

func buildTestBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("uprobe symbol resolution test requires a Linux ELF binary")
	}

	src := `package main
func targetFunc(a, b int) int { return a + b }
func main() { targetFunc(1, 2) }
`
	dir := t.TempDir()
	srcPath := dir + "/main.go"
	if err := os.WriteFile(srcPath, []byte(src), 0644); err != nil {
		t.Fatalf("writing test source: %v", err)
	}

	binPath := dir + "/testbin"
	cmd := exec.Command("go", "build", "-gcflags=-l", "-o", binPath, srcPath)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building test binary: %v\n%s", err, out)
	}
	return binPath
}

func TestResolveSymbolOffset_Found(t *testing.T) {
	bin := buildTestBinary(t)

	// Go symbol names are mangled with the package path, e.g. main.targetFunc
	off, err := resolveSymbolOffset(bin, "main.targetFunc")
	if err != nil {
		t.Fatalf("expected to resolve main.targetFunc, got error: %v", err)
	}
	if off == 0 {
		t.Errorf("expected non-zero offset for main.targetFunc")
	}
}

func TestResolveSymbolOffset_NotFound(t *testing.T) {
	bin := buildTestBinary(t)

	_, err := resolveSymbolOffset(bin, "main.doesNotExist")
	if err == nil {
		t.Fatalf("expected error for missing symbol, got nil")
	}
}

func TestResolveSymbolOffset_BadBinary(t *testing.T) {
	_, err := resolveSymbolOffset("/nonexistent/path/binary", "main.targetFunc")
	if err == nil {
		t.Fatalf("expected error for nonexistent binary, got nil")
	}
}
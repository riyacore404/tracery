package output

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// MemRegion represents one line from /proc/PID/maps.
type MemRegion struct {
	Start  uint64
	End    uint64
	Offset uint64
	Path   string
}

// ReadMaps parses /proc/PID/maps into a slice of MemRegion.
func ReadMaps(pid uint32) ([]MemRegion, error) {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			// ReadMaps is read-only — close error is non-fatal, log it
			_, _ = fmt.Fprintf(os.Stderr, "warning: closing %s: %v\n", path, cerr)
		}
	}()

	var regions []MemRegion
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: start-end perms offset dev inode pathname
		// e.g.: 7f1234000-7f1235000 r-xp 00001000 08:01 123456 /usr/lib/libc.so.6
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		addrs := strings.SplitN(fields[0], "-", 2)
		if len(addrs) != 2 {
			continue
		}
		start, err := strconv.ParseUint(addrs[0], 16, 64)
		if err != nil {
			continue
		}
		end, err := strconv.ParseUint(addrs[1], 16, 64)
		if err != nil {
			continue
		}
		offset, err := strconv.ParseUint(fields[2], 16, 64)
		if err != nil {
			continue
		}
		path := ""
		if len(fields) >= 6 {
			path = fields[5]
		}
		regions = append(regions, MemRegion{
			Start:  start,
			End:    end,
			Offset: offset,
			Path:   path,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning %s: %w", path, err)
	}
	return regions, nil
}

// ResolveAddress maps a raw address to a binary path and offset within it.
// Returns the binary path and file offset, or empty string if not found.
func ResolveAddress(addr uint64, regions []MemRegion) (string, uint64) {
	for _, r := range regions {
		if addr >= r.Start && addr < r.End {
			fileOffset := r.Offset + (addr - r.Start)
			return r.Path, fileOffset
		}
	}
	return "", 0
}

// FormatAddress returns a human-readable label for an address.
// Uses /proc/PID/maps regions to annotate with binary name.
// Falls back to hex address if no mapping found.
func FormatAddress(addr uint64, regions []MemRegion) string {
	path, offset := ResolveAddress(addr, regions)
	if path == "" {
		return fmt.Sprintf("0x%x", addr)
	}
	// Use just the filename, not the full path
	parts := strings.Split(path, "/")
	name := parts[len(parts)-1]
	if name == "" {
		return fmt.Sprintf("0x%x", addr)
	}
	return fmt.Sprintf("%s+0x%x", name, offset)
}

// ResolveStack converts a slice of raw addresses into human-readable frame labels.
// Addresses of 0 indicate the end of the stack — they are skipped.
func ResolveStack(addrs []uint64, regions []MemRegion) []string {
	var frames []string
	for _, addr := range addrs {
		if addr == 0 {
			break
		}
		frames = append(frames, FormatAddress(addr, regions))
	}
	return frames
}
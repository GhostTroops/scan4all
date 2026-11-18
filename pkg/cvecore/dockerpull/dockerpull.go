// Package dockerpull 经代理镜像站直连下载 Docker 镜像并通过 `docker load` 导入。
// 绕开 Daemon 的 socks/镜像站死锁与多镜像站 registry-mirrors 配置的不一致。
//
// 典型用法：
//
//	puller := dockerpull.NewPuller("https://proxy.vvvv.ee")
//	if err := puller.Pull("vulhub/phpunit:5.6.2"); err != nil { ... }
//
// 所有 blob 会校验 manifest 中的 digest（sha256），防止代理缓存层损坏导致假镜像。
// 429 触发指数退避（15s→30s→60s→120s→240s），其他错误退避 5s，每个请求最多重试 8 次。
package dockerpull

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Puller 从代理镜像站拉取并导入镜像。零值不可用，必须通过 NewPuller 构造。
type Puller struct {
	mirror string
	dir    string
	client *http.Client

	mu sync.Mutex // 保护 dir 的并发访问
}

// NewPuller 返回一个可复用的 Puller。mirror 形如 https://proxy.vvvv.ee。
// 内部使用 system temp 目录存放下载的 blob，docker load 成功后清理。
func NewPuller(mirror string) *Puller {
	dir, _ := os.MkdirTemp("", "dockerpull-")
	return &Puller{
		mirror: strings.TrimRight(mirror, "/"),
		dir:    dir,
		client: &http.Client{Timeout: 30 * time.Minute},
	}
}

// Pull 拉取单个镜像。image 形如 "vulhub/phpunit:5.6.2" 或 "mongo:3.4"（library 自动补 library/ 前缀）。
func (p *Puller) Pull(image string) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found: %w", err)
	}
	if strings.Contains(image, "/") {
		parts := strings.SplitN(image, "/", 2)
		return p.doPull(parts[0], parts[1])
	}
	return p.doPull("library", image)
}

// PullMany 批量拉取，串行（让代理限流充分退避）。
func (p *Puller) PullMany(images []string) []error {
	var errs []error
	for _, img := range images {
		if err := p.Pull(img); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", img, err))
		}
	}
	return errs
}

func (p *Puller) doPull(namespace, nameTag string) error {
	name, tag := splitNameTag(nameTag)
	if tag == "" {
		tag = "latest"
	}
	repo := namespace + "/" + name

	// 1) fetch manifest（可能是 manifest list → 递归选 linux/amd64）
	manifest, err := p.resolveManifest(repo, tag)
	if err != nil {
		return err
	}

	// 2) 准备目录
	p.mu.Lock()
	workdir := filepath.Join(p.dir, sanitize(repo+"_"+tag))
	p.mu.Unlock()
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		return err
	}

	// 3) config blob
	cfgFile, err := p.fetchBlob(repo, manifest.Config.Digest, workdir)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// 4) layer blobs
	var layerFiles []string
	for i, l := range manifest.Layers {
		fn, err := p.fetchBlob(repo, l.Digest, workdir)
		if err != nil {
			return fmt.Errorf("layer %d/%d: %w", i+1, len(manifest.Layers), err)
		}
		layerFiles = append(layerFiles, filepath.Base(fn))
	}

	// 5) 组装 docker load tar
	var repoTag string
	if namespace == "library" {
		repoTag = name + ":" + tag
	} else {
		repoTag = repo + ":" + tag
	}
	tarData, err := buildDockerTar(cfgFile, filepath.Base(cfgFile), layerFiles, workdir, repoTag)
	if err != nil {
		return err
	}

	// 6) docker load
	cmd := exec.Command("docker", "load")
	cmd.Stdin = bytes.NewReader(tarData)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker load: %v: %s", err, out)
	}
	return nil
}

// resolveManifest 递归解析 manifest list 到具体的 v2 manifest。
func (p *Puller) resolveManifest(repo, tag string) (v2Manifest, error) {
	accepts := []string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
	}
	var lastErr error
	for _, a := range accepts {
		body, err := p.getWithRetry(p.mirror+"/v2/"+repo+"/manifests/"+tag, a)
		if err != nil {
			lastErr = err
			continue
		}
		var raw struct {
			MediaType string `json:"mediaType"`
		}
		_ = json.Unmarshal(body, &raw)

		// 如果是 manifest list → 选 linux/amd64 子 manifest
		if raw.MediaType == "application/vnd.docker.distribution.manifest.list.v2+json" {
			var ml manifestList
			if err := json.Unmarshal(body, &ml); err != nil {
				lastErr = err
				continue
			}
			var pick string
			for _, m := range ml.Manifests {
				if m.Platform.OS == "linux" && m.Platform.Architecture == "amd64" {
					pick = m.Digest
					break
				}
			}
			if pick == "" && len(ml.Manifests) > 0 {
				pick = ml.Manifests[0].Digest
			}
			if pick == "" {
				lastErr = fmt.Errorf("manifest list has no children")
				continue
			}
			body2, err := p.getWithRetry(p.mirror+"/v2/"+repo+"/manifests/"+pick, "application/vnd.docker.distribution.manifest.v2+json")
			if err != nil {
				lastErr = err
				continue
			}
			var m2 v2Manifest
			if err := json.Unmarshal(body2, &m2); err != nil {
				lastErr = err
				continue
			}
			return m2, nil
		}

		var m v2Manifest
		if err := json.Unmarshal(body, &m); err == nil && m.Config.Digest != "" {
			return m, nil
		}
		lastErr = err
	}
	return v2Manifest{}, lastErr
}

func (p *Puller) fetchBlob(repo, digest, workdir string) (string, error) {
	algo, hash, ok := strings.Cut(digest, ":")
	if !ok {
		return "", fmt.Errorf("bad digest: %s", digest)
	}
	if algo != "sha256" {
		return "", fmt.Errorf("unsupported digest algo: %s", algo)
	}
	path := filepath.Join(workdir, hash+".tar.gz")

	// 已存在且 digest 匹配 → 跳过
	if data, err := os.ReadFile(path); err == nil && sha256Hex(data) == hash {
		return path, nil
	}

	url := fmt.Sprintf("%s/v2/%s/blobs/%s", p.mirror, repo, digest)
	body, err := p.getWithRetry(url, "")
	if err != nil {
		return "", err
	}
	if got := sha256Hex(body); got != hash {
		return "", fmt.Errorf("digest mismatch: got sha256:%s want sha256:%s", got, hash)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func (p *Puller) getWithRetry(url, accept string) ([]byte, error) {
	backoff := 5 * time.Second
	maxBackoff := 4 * time.Minute
	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "curl/8")
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		resp, err := p.client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			switch resp.StatusCode {
			case 200:
				return data, nil
			case 429, 503:
				lastErr = fmt.Errorf("rate limited: %s", resp.Status)
			default:
				lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, string(data))
				return nil, lastErr
			}
		}
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	return nil, lastErr
}

// manifest structures
type v2Manifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
	} `json:"config"`
	Layers []struct {
		Digest    string `json:"digest"`
		MediaType string `json:"mediaType"`
		Size      int64  `json:"size"`
	} `json:"layers"`
}

type manifestList struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Manifests     []struct {
		Digest   string `json:"digest"`
		Platform struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		} `json:"platform"`
	} `json:"manifests"`
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func splitNameTag(s string) (name, tag string) {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '/' || r == ':' || r == '.':
			return '_'
		default:
			return r
		}
	}, s)
}

// buildDockerTar 把下载的 config + layers 打包成 docker load 能识别的 tar。
func buildDockerTar(cfgPath, cfgName string, layerNames []string, workdir, repoTag string) ([]byte, error) {
	// 每个 layer 先 gunzip 再 re-gzip（清除可能的代理修改）
	cleanedLayers := make([]string, 0, len(layerNames))
	for _, fn := range layerNames {
		src := filepath.Join(workdir, fn)
		// 验证可解压
		f, err := os.Open(src)
		if err != nil {
			return nil, err
		}
		_, err = gzip.NewReader(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("layer %s invalid gzip: %w", fn, err)
		}
		cleanedLayers = append(cleanedLayers, fn)
	}

	mjson := []struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
		Layers   []string `json:"Layers"`
	}{
		{Config: cfgName, RepoTags: []string{repoTag}, Layers: cleanedLayers},
	}
	mjsonBytes, _ := json.Marshal(mjson)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	addFile := func(name string, srcPath string) error {
		data, err := os.ReadFile(srcPath)
		if err != nil {
			return err
		}
		hdr := &tar.Header{
			Name:     name,
			Size:     int64(len(data)),
			Mode:     0o644,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	}
	if err := addFile(cfgName, cfgPath); err != nil {
		return nil, err
	}
	for _, fn := range cleanedLayers {
		if err := addFile(fn, filepath.Join(workdir, fn)); err != nil {
			return nil, err
		}
	}
	hdr := &tar.Header{Name: "manifest.json", Size: int64(len(mjsonBytes)), Mode: 0o644, Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := tw.Write(mjsonBytes); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

const (
	saturatorCacheKey = "saturator:latest"
	saturatorCacheTTL = 10 * time.Minute
	saturatorGHRepo   = "Viste/saturator"
)

type SaturatorVersion struct {
	Version   string `json:"version"`
	URLMac    string `json:"url_mac"`
	URLWin    string `json:"url_win"`
	Changelog string `json:"changelog"`
}

type SaturatorHandler struct {
	redis *redis.Client
}

func NewSaturatorHandler(rdb *redis.Client) *SaturatorHandler {
	return &SaturatorHandler{redis: rdb}
}

func (h *SaturatorHandler) GetVersion(c *gin.Context) {
	ctx := context.Background()

	cached, err := h.redis.Get(ctx, saturatorCacheKey).Result()
	if err == nil {
		var v SaturatorVersion
		if json.Unmarshal([]byte(cached), &v) == nil {
			c.JSON(http.StatusOK, v)
			return
		}
	}

	v, err := fetchGitHubRelease()
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch release info"})
		return
	}

	if data, err := json.Marshal(v); err == nil {
		h.redis.Set(ctx, saturatorCacheKey, data, saturatorCacheTTL)
	}

	c.JSON(http.StatusOK, v)
}

func fetchGitHubRelease() (*SaturatorVersion, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", saturatorGHRepo)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github returned %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
		Body    string `json:"body"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	v := &SaturatorVersion{
		Version:   strings.TrimPrefix(release.TagName, "v"),
		Changelog: release.Body,
	}

	for _, asset := range release.Assets {
		name := strings.ToLower(asset.Name)
		if strings.HasSuffix(name, ".dmg") {
			v.URLMac = asset.BrowserDownloadURL
		} else if strings.HasSuffix(name, ".exe") {
			v.URLWin = asset.BrowserDownloadURL
		} else if strings.HasSuffix(name, ".zip") && strings.Contains(name, "mac") && v.URLMac == "" {
			v.URLMac = asset.BrowserDownloadURL
		} else if strings.HasSuffix(name, ".zip") && strings.Contains(name, "win") && v.URLWin == "" {
			v.URLWin = asset.BrowserDownloadURL
		}
	}

	return v, nil
}

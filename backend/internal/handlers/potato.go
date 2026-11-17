package handlers

import (
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
)

var potatoBuild = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)
var potatoAPK = regexp.MustCompile(`^potato-(arm64|armv7|universal)-[a-f0-9]{64}\.apk$`)

// Garage's public website API selects the bucket from Host. Only these release
// objects may pass through the site. Cookies and API tokens stay at the site.
func RegisterPotato(api *gin.RouterGroup) {
	client := &http.Client{
		Transport:     &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 90 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	registerPotato(api, client)
}

func registerPotato(api *gin.RouterGroup, client *http.Client) {
	serve := func(c *gin.Context) {
		file := c.Param("file")
		key, mime := "latest.json", "application/json"
		cache := "no-cache"
		if file != "" {
			build := c.Param("build")
			if !potatoBuild.MatchString(build) || !potatoAPK.MatchString(file) {
				c.Status(http.StatusNotFound)
				return
			}
			key, mime = build+"/"+file, "application/vnd.android.package-archive"
			cache = "public, max-age=31536000, immutable"
		}
		req, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, "http://garage-web.garage.svc:3902/"+key, nil)
		if err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		req.Host = "potato-releases.dev-vlab.ru"
		for _, h := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
			if value := c.GetHeader(h); value != "" {
				req.Header.Set(h, value)
			}
		}
		res, err := client.Do(req)
		if err != nil {
			c.Header("Cache-Control", "no-store")
			c.Status(http.StatusBadGateway)
			return
		}
		defer res.Body.Close()
		if res.StatusCode != 200 && res.StatusCode != 206 && res.StatusCode != 304 {
			c.Header("Cache-Control", "no-store")
			switch res.StatusCode {
			case 404, 416:
				c.Header("Content-Range", res.Header.Get("Content-Range"))
				c.Status(res.StatusCode)
			default:
				c.Status(http.StatusBadGateway)
			}
			return
		}
		c.Header("Cache-Control", cache)
		for _, h := range []string{"ETag", "Last-Modified", "Accept-Ranges", "Content-Range"} {
			if value := res.Header.Get(h); value != "" {
				c.Header(h, value)
			}
		}
		if res.StatusCode == 304 {
			c.Status(304)
			return
		}
		if file != "" {
			c.Header("Content-Disposition", `attachment; filename="`+file+`"`)
		}
		c.DataFromReader(res.StatusCode, res.ContentLength, mime, res.Body, nil)
	}
	for _, path := range []string{"/potato/version", "/potato/releases/:build/:file"} {
		api.GET(path, serve)
		api.HEAD(path, serve)
	}
}

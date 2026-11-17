package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type garageTransport func(*http.Request) (*http.Response, error)

func (f garageTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPotatoReleaseRoutes(t *testing.T) {
	file := "potato-arm64-" + strings.Repeat("a", 64) + ".apk"
	for _, tc := range []struct {
		name, method, route, object string
		origin, status              int
	}{
		{"version", "GET", "version", "/latest.json", 200, 200},
		{"apk range", "GET", "releases/7/" + file, "/7/" + file, 206, 206},
		{"apk head", "HEAD", "releases/7/" + file, "/7/" + file, 200, 200},
		{"unpublished", "GET", "version", "/latest.json", 404, 404},
		{"upstream error", "GET", "version", "/latest.json", 503, 502},
		{"foreign object", "GET", "releases/7/private.json", "", 0, 404},
		{"invalid build", "GET", "releases/bad/" + file, "", 0, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			router := gin.New()
			registerPotato(router.Group("/api"), &http.Client{Transport: garageTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Host != "potato-releases.dev-vlab.ru" || r.URL.Path != tc.object || r.Method != tc.method || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Fatalf("unexpected request to Garage: %s %s %v", r.Method, r.URL, r.Header)
				}
				header := make(http.Header)
				body := "abc"
				if tc.method == "HEAD" {
					body = ""
				}
				if tc.origin == 206 {
					if r.Header.Get("Range") != "bytes=0-2" {
						t.Fatal("range missing")
					}
					header.Set("Content-Range", "bytes 0-2/20")
				}
				return &http.Response{StatusCode: tc.origin, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: 3}, nil
			})})
			req := httptest.NewRequest(tc.method, "/api/potato/"+tc.route+"?token=private", nil)
			req.Header.Set("Authorization", "Bearer cookie")
			req.Header.Set("Cookie", "session=x")
			if tc.origin == 206 {
				req.Header.Set("Range", "bytes=0-2")
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.status || (calls == 1) != (tc.object != "") {
				t.Fatalf("status %d, calls %d", rec.Code, calls)
			}
			if tc.origin == 206 && (rec.Body.String() != "abc" || rec.Header().Get("Content-Range") != "bytes 0-2/20" || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable")) {
				t.Fatal("invalid partial response")
			}
			if tc.origin >= 400 && rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("error cached")
			}
			if tc.method == "HEAD" && (rec.Body.Len() != 0 || rec.Header().Get("Content-Length") != "3") {
				t.Fatal("invalid HEAD")
			}
		})
	}
}

package handlers

import (
	"net/http"
	"strconv"

	"dev-vlab/internal/models"
	"dev-vlab/internal/repository"

	"github.com/gin-gonic/gin"
)

type MusicHandler struct {
	repo *repository.Repository
}

func NewMusicHandler(repo *repository.Repository) *MusicHandler {
	return &MusicHandler{repo: repo}
}

func (h *MusicHandler) ListReleases(c *gin.Context) {
	releases, err := h.repo.GetReleases()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch releases"})
		return
	}
	c.JSON(http.StatusOK, releases)
}

func (h *MusicHandler) ListDemos(c *gin.Context) {
	demos, err := h.repo.GetDemos()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch demos"})
		return
	}
	c.JSON(http.StatusOK, demos)
}

func (h *MusicHandler) GetRadio(c *gin.Context) {
	radio, err := h.repo.GetActiveRadio()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no active radio stream"})
		return
	}
	c.JSON(http.StatusOK, radio)
}

// --- Admin: Releases ---

func (h *MusicHandler) AdminCreateRelease(c *gin.Context) {
	var req models.MusicRelease
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.repo.CreateRelease(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create release"})
		return
	}
	c.JSON(http.StatusCreated, req)
}

func (h *MusicHandler) AdminUpdateRelease(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	release, err := h.repo.GetReleaseByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "release not found"})
		return
	}

	var req struct {
		Title       *string `json:"title"`
		Artist      *string `json:"artist"`
		CoverURL    *string `json:"cover_url"`
		ReleaseURL  *string `json:"release_url"`
		EmbedURL    *string `json:"embed_url"`
		SortOrder   *int    `json:"sort_order"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Title != nil {
		release.Title = *req.Title
	}
	if req.Artist != nil {
		release.Artist = *req.Artist
	}
	if req.CoverURL != nil {
		release.CoverURL = *req.CoverURL
	}
	if req.ReleaseURL != nil {
		release.ReleaseURL = *req.ReleaseURL
	}
	if req.EmbedURL != nil {
		release.EmbedURL = *req.EmbedURL
	}
	if req.SortOrder != nil {
		release.SortOrder = *req.SortOrder
	}

	if err := h.repo.UpdateRelease(release); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
		return
	}
	c.JSON(http.StatusOK, release)
}

func (h *MusicHandler) AdminDeleteRelease(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	h.repo.DeleteRelease(uint(id))
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

// --- Admin: Demos ---

func (h *MusicHandler) AdminCreateDemo(c *gin.Context) {
	var req models.MusicDemo
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.repo.CreateDemo(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create demo"})
		return
	}
	c.JSON(http.StatusCreated, req)
}

func (h *MusicHandler) AdminUpdateDemo(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	demo, err := h.repo.GetDemoByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "demo not found"})
		return
	}

	var req struct {
		Title       *string `json:"title"`
		Description *string `json:"description"`
		FileURL     *string `json:"file_url"`
		EmbedURL    *string `json:"embed_url"`
		SortOrder   *int    `json:"sort_order"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Title != nil {
		demo.Title = *req.Title
	}
	if req.Description != nil {
		demo.Description = *req.Description
	}
	if req.FileURL != nil {
		demo.FileURL = *req.FileURL
	}
	if req.EmbedURL != nil {
		demo.EmbedURL = *req.EmbedURL
	}
	if req.SortOrder != nil {
		demo.SortOrder = *req.SortOrder
	}

	if err := h.repo.UpdateDemo(demo); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
		return
	}
	c.JSON(http.StatusOK, demo)
}

func (h *MusicHandler) AdminDeleteDemo(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	h.repo.DeleteDemo(uint(id))
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

// --- Admin: Radio ---

func (h *MusicHandler) AdminCreateRadio(c *gin.Context) {
	var req models.RadioStream
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.repo.CreateRadio(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create radio"})
		return
	}
	c.JSON(http.StatusCreated, req)
}

func (h *MusicHandler) AdminUpdateRadio(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	radio, err := h.repo.GetRadioByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "radio not found"})
		return
	}

	var req struct {
		Title     *string `json:"title"`
		StreamURL *string `json:"stream_url"`
		IsActive  *bool   `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Title != nil {
		radio.Title = *req.Title
	}
	if req.StreamURL != nil {
		radio.StreamURL = *req.StreamURL
	}
	if req.IsActive != nil {
		radio.IsActive = *req.IsActive
	}

	if err := h.repo.UpdateRadio(radio); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
		return
	}
	c.JSON(http.StatusOK, radio)
}

func (h *MusicHandler) AdminDeleteRadio(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	h.repo.DeleteRadio(uint(id))
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

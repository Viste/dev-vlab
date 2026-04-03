package handlers

import (
	"net/http"
	"strconv"

	"dev-vlab/internal/models"
	"dev-vlab/internal/repository"

	"github.com/gin-gonic/gin"
)

type NavLinkHandler struct {
	repo *repository.Repository
}

func NewNavLinkHandler(repo *repository.Repository) *NavLinkHandler {
	return &NavLinkHandler{repo: repo}
}

func (h *NavLinkHandler) List(c *gin.Context) {
	links, err := h.repo.GetActiveNavLinks()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch links"})
		return
	}
	c.JSON(http.StatusOK, links)
}

// --- Admin ---

func (h *NavLinkHandler) AdminList(c *gin.Context) {
	links, err := h.repo.GetAllNavLinks()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch links"})
		return
	}
	c.JSON(http.StatusOK, links)
}

func (h *NavLinkHandler) AdminCreate(c *gin.Context) {
	var req models.NavigationLink
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.repo.CreateNavLink(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create link"})
		return
	}
	c.JSON(http.StatusCreated, req)
}

func (h *NavLinkHandler) AdminUpdate(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	link, err := h.repo.GetNavLinkByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "link not found"})
		return
	}

	var req struct {
		Title     *string `json:"title"`
		URL       *string `json:"url"`
		Icon      *string `json:"icon"`
		SortOrder *int    `json:"sort_order"`
		IsActive  *bool   `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Title != nil {
		link.Title = *req.Title
	}
	if req.URL != nil {
		link.URL = *req.URL
	}
	if req.Icon != nil {
		link.Icon = *req.Icon
	}
	if req.SortOrder != nil {
		link.SortOrder = *req.SortOrder
	}
	if req.IsActive != nil {
		link.IsActive = *req.IsActive
	}

	if err := h.repo.UpdateNavLink(link); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
		return
	}
	c.JSON(http.StatusOK, link)
}

func (h *NavLinkHandler) AdminDelete(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	h.repo.DeleteNavLink(uint(id))
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

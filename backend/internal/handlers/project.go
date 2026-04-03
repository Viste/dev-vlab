package handlers

import (
	"net/http"
	"strconv"

	"dev-vlab/internal/models"
	"dev-vlab/internal/repository"

	"github.com/gin-gonic/gin"
)

type ProjectHandler struct {
	repo *repository.Repository
}

func NewProjectHandler(repo *repository.Repository) *ProjectHandler {
	return &ProjectHandler{repo: repo}
}

func (h *ProjectHandler) List(c *gin.Context) {
	projects, err := h.repo.GetProjects()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch projects"})
		return
	}
	c.JSON(http.StatusOK, projects)
}

// --- Admin ---

func (h *ProjectHandler) AdminCreate(c *gin.Context) {
	var req models.Project
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.repo.CreateProject(&req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create project"})
		return
	}
	c.JSON(http.StatusCreated, req)
}

func (h *ProjectHandler) AdminUpdate(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	project, err := h.repo.GetProjectByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
		return
	}

	var req struct {
		Title       *string `json:"title"`
		Description *string `json:"description"`
		ImageURL    *string `json:"image_url"`
		ProjectURL  *string `json:"project_url"`
		SortOrder   *int    `json:"sort_order"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Title != nil {
		project.Title = *req.Title
	}
	if req.Description != nil {
		project.Description = *req.Description
	}
	if req.ImageURL != nil {
		project.ImageURL = *req.ImageURL
	}
	if req.ProjectURL != nil {
		project.ProjectURL = *req.ProjectURL
	}
	if req.SortOrder != nil {
		project.SortOrder = *req.SortOrder
	}

	if err := h.repo.UpdateProject(project); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
		return
	}
	c.JSON(http.StatusOK, project)
}

func (h *ProjectHandler) AdminDelete(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	h.repo.DeleteProject(uint(id))
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

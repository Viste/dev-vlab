package handlers

import (
	"net/http"
	"strconv"

	"dev-vlab/internal/middleware"
	"dev-vlab/internal/models"
	"dev-vlab/internal/repository"

	"github.com/gin-gonic/gin"
	"github.com/gosimple/slug"
)

type BlogHandler struct {
	repo *repository.Repository
}

func NewBlogHandler(repo *repository.Repository) *BlogHandler {
	return &BlogHandler{repo: repo}
}

func (h *BlogHandler) ListPosts(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 50 {
		limit = 10
	}

	posts, total, err := h.repo.GetPublishedPosts(page, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch posts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"posts": posts,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (h *BlogHandler) GetPost(c *gin.Context) {
	post, err := h.repo.GetPostBySlug(c.Param("slug"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "post not found"})
		return
	}
	c.JSON(http.StatusOK, post)
}

func (h *BlogHandler) AddComment(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "login required"})
		return
	}

	post, err := h.repo.GetPostBySlug(c.Param("slug"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "post not found"})
		return
	}

	var req struct {
		Content string `json:"content" binding:"required,min=1,max=2000"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	comment := &models.Comment{
		PostID:  post.ID,
		UserID:  userID,
		Content: req.Content,
	}
	if err := h.repo.CreateComment(comment); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create comment"})
		return
	}

	c.JSON(http.StatusCreated, comment)
}

func (h *BlogHandler) DeleteComment(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	comment, err := h.repo.GetCommentByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "comment not found"})
		return
	}

	userID, _ := middleware.GetUserID(c)
	isAdmin, _ := c.Get("is_admin")
	if comment.UserID != userID && !(isAdmin != nil && isAdmin.(bool)) {
		c.JSON(http.StatusForbidden, gin.H{"error": "not allowed"})
		return
	}

	h.repo.DeleteComment(uint(id))
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

// --- Admin ---

func (h *BlogHandler) AdminListPosts(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if page < 1 {
		page = 1
	}

	posts, total, err := h.repo.GetAllPosts(page, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch posts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"posts": posts, "total": total, "page": page, "limit": limit})
}

func (h *BlogHandler) AdminCreatePost(c *gin.Context) {
	var req struct {
		Title     string `json:"title" binding:"required"`
		Content   string `json:"content" binding:"required"`
		Summary   string `json:"summary"`
		CoverURL  string `json:"cover_url"`
		Published bool   `json:"published"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	post := &models.BlogPost{
		Title:     req.Title,
		Slug:      slug.Make(req.Title),
		Content:   req.Content,
		Summary:   req.Summary,
		CoverURL:  req.CoverURL,
		Published: req.Published,
	}

	if err := h.repo.CreatePost(post); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create post"})
		return
	}

	c.JSON(http.StatusCreated, post)
}

func (h *BlogHandler) AdminUpdatePost(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	post, err := h.repo.GetPostByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "post not found"})
		return
	}

	var req struct {
		Title     *string `json:"title"`
		Content   *string `json:"content"`
		Summary   *string `json:"summary"`
		CoverURL  *string `json:"cover_url"`
		Published *bool   `json:"published"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Title != nil {
		post.Title = *req.Title
		post.Slug = slug.Make(*req.Title)
	}
	if req.Content != nil {
		post.Content = *req.Content
	}
	if req.Summary != nil {
		post.Summary = *req.Summary
	}
	if req.CoverURL != nil {
		post.CoverURL = *req.CoverURL
	}
	if req.Published != nil {
		post.Published = *req.Published
	}

	if err := h.repo.UpdatePost(post); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update post"})
		return
	}

	c.JSON(http.StatusOK, post)
}

func (h *BlogHandler) AdminDeletePost(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	h.repo.DeletePost(uint(id))
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

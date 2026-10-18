package handlers

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"dev-vlab/internal/middleware"
	"dev-vlab/internal/models"
	"dev-vlab/internal/repository"
	"dev-vlab/internal/services"

	"github.com/gin-gonic/gin"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{2,64}$`)

type AdminUserHandler struct {
	repo *repository.Repository
}

func NewAdminUserHandler(repo *repository.Repository) *AdminUserHandler {
	return &AdminUserHandler{repo: repo}
}

func (h *AdminUserHandler) List(c *gin.Context) {
	users, err := h.repo.GetUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch users"})
		return
	}
	if users == nil {
		users = []models.User{}
	}
	c.JSON(http.StatusOK, users)
}

func (h *AdminUserHandler) Create(c *gin.Context) {
	var req struct {
		Username  string `json:"username" binding:"required"`
		Password  string `json:"password" binding:"required,min=6,max=128"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		IsAdmin   bool   `json:"is_admin"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	username := strings.TrimSpace(req.Username)
	if !usernameRe.MatchString(username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username: 2-64 chars, latin letters, digits, . _ -"})
		return
	}
	if _, err := h.repo.GetUserByUsername(username); err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "username already taken"})
		return
	}

	user := models.User{
		Username:     username,
		PasswordHash: services.HashPassword(req.Password),
		FirstName:    strings.TrimSpace(req.FirstName),
		LastName:     strings.TrimSpace(req.LastName),
		Email:        strings.TrimSpace(req.Email),
		Provider:     "local",
		IsAdmin:      req.IsAdmin,
	}
	if err := h.repo.CreateUser(&user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}
	c.JSON(http.StatusCreated, user)
}

func (h *AdminUserHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	user, err := h.repo.GetUserByID(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	selfID, _ := middleware.GetUserID(c)

	var req struct {
		Username  *string `json:"username"`
		Password  *string `json:"password"`
		FirstName *string `json:"first_name"`
		LastName  *string `json:"last_name"`
		Email     *string `json:"email"`
		IsAdmin   *bool   `json:"is_admin"`
		IsBanned  *bool   `json:"is_banned"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Username != nil {
		username := strings.TrimSpace(*req.Username)
		if !usernameRe.MatchString(username) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username: 2-64 chars, latin letters, digits, . _ -"})
			return
		}
		if username != user.Username {
			if other, err := h.repo.GetUserByUsername(username); err == nil && other.ID != user.ID {
				c.JSON(http.StatusConflict, gin.H{"error": "username already taken"})
				return
			}
			user.Username = username
		}
	}
	if req.Password != nil {
		if len(*req.Password) < 6 || len(*req.Password) > 128 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password must be 6-128 chars"})
			return
		}
		user.PasswordHash = services.HashPassword(*req.Password)
	}
	if req.FirstName != nil {
		user.FirstName = strings.TrimSpace(*req.FirstName)
	}
	if req.LastName != nil {
		user.LastName = strings.TrimSpace(*req.LastName)
	}
	if req.Email != nil {
		user.Email = strings.TrimSpace(*req.Email)
	}
	if req.IsAdmin != nil {
		if user.ID == selfID && !*req.IsAdmin {
			c.JSON(http.StatusBadRequest, gin.H{"error": "you cannot remove your own admin rights"})
			return
		}
		user.IsAdmin = *req.IsAdmin
	}
	if req.IsBanned != nil {
		if user.ID == selfID && *req.IsBanned {
			c.JSON(http.StatusBadRequest, gin.H{"error": "you cannot ban yourself"})
			return
		}
		user.IsBanned = *req.IsBanned
	}

	if err := h.repo.UpdateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *AdminUserHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	selfID, _ := middleware.GetUserID(c)
	if uint(id) == selfID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "you cannot delete yourself"})
		return
	}
	if _, err := h.repo.GetUserByID(uint(id)); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if err := h.repo.DeleteUser(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

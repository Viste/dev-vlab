package repository

import (
	"dev-vlab/internal/models"

	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func New(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// --- User ---

func (r *Repository) GetUserByID(id uint) (*models.User, error) {
	var user models.User
	err := r.db.First(&user, id).Error
	return &user, err
}

func (r *Repository) GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := r.db.Where("username = ?", username).First(&user).Error
	return &user, err
}

func (r *Repository) GetUserByVKID(vkID string) (*models.User, error) {
	var user models.User
	err := r.db.Where("vk_id = ?", vkID).First(&user).Error
	return &user, err
}

func (r *Repository) GetUserByTelegramID(tgID string) (*models.User, error) {
	var user models.User
	err := r.db.Where("telegram_id = ?", tgID).First(&user).Error
	return &user, err
}

func (r *Repository) CreateUser(user *models.User) error {
	return r.db.Create(user).Error
}

func (r *Repository) UpdateUser(user *models.User) error {
	return r.db.Save(user).Error
}

// --- Blog ---

func (r *Repository) GetPublishedPosts(page, limit int) ([]models.BlogPost, int64, error) {
	var posts []models.BlogPost
	var total int64

	r.db.Model(&models.BlogPost{}).Where("published = ?", true).Count(&total)

	err := r.db.Where("published = ?", true).
		Order("created_at DESC").
		Offset((page - 1) * limit).
		Limit(limit).
		Find(&posts).Error

	return posts, total, err
}

func (r *Repository) GetAllPosts(page, limit int) ([]models.BlogPost, int64, error) {
	var posts []models.BlogPost
	var total int64

	r.db.Model(&models.BlogPost{}).Count(&total)

	err := r.db.Order("created_at DESC").
		Offset((page - 1) * limit).
		Limit(limit).
		Find(&posts).Error

	return posts, total, err
}

func (r *Repository) GetPostBySlug(slug string) (*models.BlogPost, error) {
	var post models.BlogPost
	err := r.db.Where("slug = ?", slug).Preload("Comments", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at DESC")
	}).Preload("Comments.User").First(&post).Error
	return &post, err
}

func (r *Repository) GetPostByID(id uint) (*models.BlogPost, error) {
	var post models.BlogPost
	err := r.db.First(&post, id).Error
	return &post, err
}

func (r *Repository) CreatePost(post *models.BlogPost) error {
	return r.db.Create(post).Error
}

func (r *Repository) UpdatePost(post *models.BlogPost) error {
	return r.db.Save(post).Error
}

func (r *Repository) DeletePost(id uint) error {
	return r.db.Delete(&models.BlogPost{}, id).Error
}

// --- Comment ---

func (r *Repository) CreateComment(comment *models.Comment) error {
	return r.db.Create(comment).Error
}

func (r *Repository) DeleteComment(id uint) error {
	return r.db.Delete(&models.Comment{}, id).Error
}

func (r *Repository) GetCommentByID(id uint) (*models.Comment, error) {
	var comment models.Comment
	err := r.db.First(&comment, id).Error
	return &comment, err
}

// --- Music Release ---

func (r *Repository) GetReleases() ([]models.MusicRelease, error) {
	var releases []models.MusicRelease
	err := r.db.Order("sort_order ASC, created_at DESC").Find(&releases).Error
	return releases, err
}

func (r *Repository) GetReleaseByID(id uint) (*models.MusicRelease, error) {
	var release models.MusicRelease
	err := r.db.First(&release, id).Error
	return &release, err
}

func (r *Repository) CreateRelease(release *models.MusicRelease) error {
	return r.db.Create(release).Error
}

func (r *Repository) UpdateRelease(release *models.MusicRelease) error {
	return r.db.Save(release).Error
}

func (r *Repository) DeleteRelease(id uint) error {
	return r.db.Delete(&models.MusicRelease{}, id).Error
}

// --- Music Demo ---

func (r *Repository) GetDemos() ([]models.MusicDemo, error) {
	var demos []models.MusicDemo
	err := r.db.Order("sort_order ASC, created_at DESC").Find(&demos).Error
	return demos, err
}

func (r *Repository) GetDemoByID(id uint) (*models.MusicDemo, error) {
	var demo models.MusicDemo
	err := r.db.First(&demo, id).Error
	return &demo, err
}

func (r *Repository) CreateDemo(demo *models.MusicDemo) error {
	return r.db.Create(demo).Error
}

func (r *Repository) UpdateDemo(demo *models.MusicDemo) error {
	return r.db.Save(demo).Error
}

func (r *Repository) DeleteDemo(id uint) error {
	return r.db.Delete(&models.MusicDemo{}, id).Error
}

// --- Radio ---

func (r *Repository) GetActiveRadio() (*models.RadioStream, error) {
	var radio models.RadioStream
	err := r.db.Where("is_active = ?", true).First(&radio).Error
	return &radio, err
}

func (r *Repository) GetRadioByID(id uint) (*models.RadioStream, error) {
	var radio models.RadioStream
	err := r.db.First(&radio, id).Error
	return &radio, err
}

func (r *Repository) CreateRadio(radio *models.RadioStream) error {
	return r.db.Create(radio).Error
}

func (r *Repository) UpdateRadio(radio *models.RadioStream) error {
	return r.db.Save(radio).Error
}

func (r *Repository) DeleteRadio(id uint) error {
	return r.db.Delete(&models.RadioStream{}, id).Error
}

// --- Project ---

func (r *Repository) GetProjects() ([]models.Project, error) {
	var projects []models.Project
	err := r.db.Order("sort_order ASC, created_at DESC").Find(&projects).Error
	return projects, err
}

func (r *Repository) GetProjectByID(id uint) (*models.Project, error) {
	var project models.Project
	err := r.db.First(&project, id).Error
	return &project, err
}

func (r *Repository) CreateProject(project *models.Project) error {
	return r.db.Create(project).Error
}

func (r *Repository) UpdateProject(project *models.Project) error {
	return r.db.Save(project).Error
}

func (r *Repository) DeleteProject(id uint) error {
	return r.db.Delete(&models.Project{}, id).Error
}

// --- Navigation Link ---

func (r *Repository) GetActiveNavLinks() ([]models.NavigationLink, error) {
	var links []models.NavigationLink
	err := r.db.Where("is_active = ?", true).Order("sort_order ASC").Find(&links).Error
	return links, err
}

func (r *Repository) GetAllNavLinks() ([]models.NavigationLink, error) {
	var links []models.NavigationLink
	err := r.db.Order("sort_order ASC").Find(&links).Error
	return links, err
}

func (r *Repository) GetNavLinkByID(id uint) (*models.NavigationLink, error) {
	var link models.NavigationLink
	err := r.db.First(&link, id).Error
	return &link, err
}

func (r *Repository) CreateNavLink(link *models.NavigationLink) error {
	return r.db.Create(link).Error
}

func (r *Repository) UpdateNavLink(link *models.NavigationLink) error {
	return r.db.Save(link).Error
}

func (r *Repository) DeleteNavLink(id uint) error {
	return r.db.Delete(&models.NavigationLink{}, id).Error
}

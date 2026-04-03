package models

import (
	"time"

	"gorm.io/gorm"
)

func (User) TableName() string { return "user" }

type User struct {
	ID             uint           `json:"id" gorm:"primaryKey"`
	Username       string         `json:"username" gorm:"uniqueIndex;size:64;not null"`
	Email          string         `json:"email,omitempty" gorm:"size:255"`
	PasswordHash   string         `json:"-" gorm:"size:255"`
	FirstName      string         `json:"first_name,omitempty" gorm:"size:64"`
	LastName       string         `json:"last_name,omitempty" gorm:"size:64"`
	ProfilePicture string         `json:"profile_picture,omitempty" gorm:"size:255"`
	TelegramID     string         `json:"telegram_id,omitempty" gorm:"size:64;index"`
	VKID           string         `json:"vk_id,omitempty" gorm:"size:64;index"`
	Provider       string         `json:"provider,omitempty" gorm:"size:32"`
	IsAdmin        bool           `json:"is_admin" gorm:"default:false"`
	IsBanned       bool           `json:"is_banned" gorm:"default:false"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `json:"-" gorm:"index"`

	Comments []Comment `json:"-" gorm:"foreignKey:UserID"`
}

type BlogPost struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	Title     string         `json:"title" gorm:"size:255;not null"`
	Slug      string         `json:"slug" gorm:"uniqueIndex;size:255;not null"`
	Content   string         `json:"content" gorm:"type:text;not null"`
	Summary   string         `json:"summary,omitempty" gorm:"size:512"`
	CoverURL  string         `json:"cover_url,omitempty" gorm:"size:255"`
	Published bool           `json:"published" gorm:"default:false"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`

	Comments []Comment `json:"comments,omitempty" gorm:"foreignKey:PostID"`
}

type Comment struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	PostID    uint           `json:"post_id" gorm:"index;not null"`
	UserID    uint           `json:"user_id" gorm:"index;not null"`
	Content   string         `json:"content" gorm:"type:text;not null"`
	CreatedAt time.Time      `json:"created_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`

	User User `json:"user" gorm:"foreignKey:UserID"`
}

type MusicRelease struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	Title       string         `json:"title" gorm:"size:255;not null"`
	Artist      string         `json:"artist,omitempty" gorm:"size:255"`
	CoverURL    string         `json:"cover_url,omitempty" gorm:"size:512"`
	ReleaseURL  string         `json:"release_url,omitempty" gorm:"size:512"`
	EmbedURL    string         `json:"embed_url,omitempty" gorm:"size:512"`
	ReleaseDate *time.Time     `json:"release_date,omitempty"`
	SortOrder   int            `json:"sort_order" gorm:"default:0"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

type MusicDemo struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	Title       string         `json:"title" gorm:"size:255;not null"`
	Description string         `json:"description,omitempty" gorm:"type:text"`
	FileURL     string         `json:"file_url,omitempty" gorm:"size:512"`
	EmbedURL    string         `json:"embed_url,omitempty" gorm:"size:512"`
	SortOrder   int            `json:"sort_order" gorm:"default:0"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

type RadioStream struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Title     string    `json:"title" gorm:"size:255;not null"`
	StreamURL string    `json:"stream_url" gorm:"size:512;not null"`
	IsActive  bool      `json:"is_active" gorm:"default:true"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Project struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	Title       string         `json:"title" gorm:"size:255;not null"`
	Description string         `json:"description,omitempty" gorm:"type:text"`
	ImageURL    string         `json:"image_url,omitempty" gorm:"size:512"`
	ProjectURL  string         `json:"project_url,omitempty" gorm:"size:512"`
	SortOrder   int            `json:"sort_order" gorm:"default:0"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

type NavigationLink struct {
	ID        uint   `json:"id" gorm:"primaryKey"`
	Title     string `json:"title" gorm:"size:128;not null"`
	URL       string `json:"url" gorm:"size:512;not null"`
	Icon      string `json:"icon,omitempty" gorm:"size:64"`
	SortOrder int    `json:"sort_order" gorm:"default:0"`
	IsActive  bool   `json:"is_active" gorm:"default:true"`
}

package handlers

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"dev-vlab/internal/middleware"
	"dev-vlab/internal/models"
	"dev-vlab/internal/repository"

	"github.com/gin-gonic/gin"
	"github.com/gosimple/slug"
)

type ApartmentHandler struct {
	repo *repository.Repository
}

func NewApartmentHandler(repo *repository.Repository) *ApartmentHandler {
	return &ApartmentHandler{repo: repo}
}

func DetectApartmentSource(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "other"
	}
	host := strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
	path := strings.ToLower(u.Path)

	hostIs := func(domain string) bool {
		return host == domain || strings.HasSuffix(host, "."+domain)
	}

	switch {
	case hostIs("cian.ru"):
		return "cian"
	case hostIs("realty.yandex.ru"), hostIs("realty.ya.ru"):
		return "yandex"
	case (hostIs("yandex.ru") || hostIs("ya.ru")) && strings.Contains(path, "realty"):
		return "yandex"
	case hostIs("avito.ru"):
		return "avito"
	case hostIs("domclick.ru"):
		return "domclick"
	default:
		return "other"
	}
}

func normalizeURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}
	return u.String(), true
}

func criterionScore(scores map[string]int, criteria []models.ApartmentCriterion) float64 {
	var sum, wsum float64
	for _, c := range criteria {
		if !c.IsActive {
			continue
		}
		v, ok := scores[c.Key]
		if !ok || v <= 0 {
			continue
		}
		w := c.Weight
		if w <= 0 {
			w = 1
		}
		sum += float64(v) * w
		wsum += w
	}
	if wsum == 0 {
		return 0
	}
	return math.Round(sum/wsum*100) / 100
}

func (h *ApartmentHandler) enrich(items []models.Apartment) {
	criteria, err := h.repo.GetApartmentCriteria(true)
	if err != nil {
		return
	}
	for i := range items {
		var total float64
		var n int
		for j := range items[i].Ratings {
			s := criterionScore(items[i].Ratings[j].Scores, criteria)
			items[i].Ratings[j].Score = s
			if s > 0 {
				total += s
				n++
			}
		}
		if n > 0 {
			items[i].Score = math.Round(total/float64(n)*100) / 100
		}
	}
}

func (h *ApartmentHandler) respondOne(c *gin.Context, status int, id uint) {
	item, err := h.repo.GetApartmentByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "apartment not found"})
		return
	}
	items := []models.Apartment{*item}
	h.enrich(items)
	c.JSON(status, items[0])
}

func parseID(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return 0, false
	}
	return uint(id), true
}

func (h *ApartmentHandler) List(c *gin.Context) {
	status := c.Query("status")
	if status != "" && !models.IsValidApartmentStatus(status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
		return
	}
	items, err := h.repo.GetApartments(status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch apartments"})
		return
	}
	h.enrich(items)
	if items == nil {
		items = []models.Apartment{}
	}
	c.JSON(http.StatusOK, items)
}

func (h *ApartmentHandler) Get(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	h.respondOne(c, http.StatusOK, id)
}

type apartmentInput struct {
	URL         *string  `json:"url"`
	Title       *string  `json:"title"`
	Address     *string  `json:"address"`
	Price       *int64   `json:"price"`
	Rooms       *int     `json:"rooms"`
	Area        *float64 `json:"area"`
	Floor       *int     `json:"floor"`
	TotalFloors *int     `json:"total_floors"`
	Notes       *string  `json:"notes"`
	Status      *string  `json:"status"`
}

func applyApartmentInput(item *models.Apartment, in apartmentInput) (string, bool) {
	if in.URL != nil {
		u, ok := normalizeURL(*in.URL)
		if !ok {
			return "valid url required", false
		}
		item.URL = u
		item.Source = DetectApartmentSource(u)
	}
	if in.Title != nil {
		item.Title = strings.TrimSpace(*in.Title)
	}
	if in.Address != nil {
		item.Address = strings.TrimSpace(*in.Address)
	}
	if in.Price != nil {
		if *in.Price < 0 {
			return "price must be >= 0", false
		}
		item.Price = *in.Price
	}
	if in.Rooms != nil {
		if *in.Rooms < 0 || *in.Rooms > 20 {
			return "rooms must be 0..20", false
		}
		item.Rooms = *in.Rooms
	}
	if in.Area != nil {
		if *in.Area < 0 {
			return "area must be >= 0", false
		}
		item.Area = *in.Area
	}
	if in.Floor != nil {
		item.Floor = *in.Floor
	}
	if in.TotalFloors != nil {
		item.TotalFloors = *in.TotalFloors
	}
	if in.Notes != nil {
		item.Notes = strings.TrimSpace(*in.Notes)
	}
	if in.Status != nil {
		if !models.IsValidApartmentStatus(*in.Status) {
			return "invalid status", false
		}
		item.Status = *in.Status
	}
	return "", true
}

func (h *ApartmentHandler) Create(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "login required"})
		return
	}

	var in apartmentInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if in.URL == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "url is required"})
		return
	}

	item := models.Apartment{Status: models.ApartmentStatusNew, CreatedBy: userID}
	if msg, ok := applyApartmentInput(&item, in); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}
	if item.Title == "" {
		item.Title = item.URL
	}

	if err := h.repo.CreateApartment(&item); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create apartment"})
		return
	}
	h.respondOne(c, http.StatusCreated, item.ID)
}

func (h *ApartmentHandler) Update(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	item, err := h.repo.GetApartmentByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "apartment not found"})
		return
	}

	var in apartmentInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if msg, ok := applyApartmentInput(item, in); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}
	if item.Title == "" {
		item.Title = item.URL
	}

	if err := h.repo.UpdateApartment(item); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update apartment"})
		return
	}
	h.respondOne(c, http.StatusOK, item.ID)
}

func (h *ApartmentHandler) Delete(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	if _, err := h.repo.GetApartmentByID(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "apartment not found"})
		return
	}
	if err := h.repo.DeleteApartment(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete apartment"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func (h *ApartmentHandler) Rate(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "login required"})
		return
	}
	id, ok := parseID(c)
	if !ok {
		return
	}
	if _, err := h.repo.GetApartmentByID(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "apartment not found"})
		return
	}

	var req struct {
		Scores  map[string]int `json:"scores"`
		Comment string         `json:"comment"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	criteria, err := h.repo.GetApartmentCriteria(false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load criteria"})
		return
	}
	known := make(map[string]bool, len(criteria))
	for _, cr := range criteria {
		known[cr.Key] = true
	}

	scores := make(map[string]int)
	for k, v := range req.Scores {
		if !known[k] {
			continue
		}
		if v < 0 || v > 5 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "scores must be within 0..5"})
			return
		}
		if v > 0 {
			scores[k] = v
		}
	}
	if len(req.Comment) > 4000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "comment too long"})
		return
	}

	rating := models.ApartmentRating{
		ApartmentID: id,
		UserID:      userID,
		Scores:      scores,
		Comment:     strings.TrimSpace(req.Comment),
	}
	if err := h.repo.UpsertApartmentRating(&rating); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save rating"})
		return
	}
	h.respondOne(c, http.StatusOK, id)
}

func (h *ApartmentHandler) Unrate(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "login required"})
		return
	}
	id, ok := parseID(c)
	if !ok {
		return
	}
	if err := h.repo.DeleteApartmentRating(id, userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete rating"})
		return
	}
	h.respondOne(c, http.StatusOK, id)
}

func (h *ApartmentHandler) ListCriteria(c *gin.Context) {
	items, err := h.repo.GetApartmentCriteria(false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch criteria"})
		return
	}
	if items == nil {
		items = []models.ApartmentCriterion{}
	}
	c.JSON(http.StatusOK, items)
}

func criterionKey(candidates []string, taken map[string]bool) string {
	key := ""
	for _, s := range candidates {
		if key = strings.ReplaceAll(slug.Make(s), "-", "_"); key != "" {
			break
		}
	}
	if key == "" {
		key = "criterion"
	}
	if len(key) > 60 {
		key = key[:60]
	}
	unique := key
	for i := 2; taken[unique]; i++ {
		unique = fmt.Sprintf("%s_%d", key, i)
	}
	return unique
}

func (h *ApartmentHandler) CreateCriterion(c *gin.Context) {
	var req struct {
		Key       string   `json:"key"`
		LabelEn   string   `json:"label_en"`
		LabelRu   string   `json:"label_ru"`
		Weight    *float64 `json:"weight"`
		SortOrder *int     `json:"sort_order"`
		IsActive  *bool    `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	labelEn := strings.TrimSpace(req.LabelEn)
	labelRu := strings.TrimSpace(req.LabelRu)
	if labelEn == "" && labelRu == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "label is required in at least one language"})
		return
	}
	if len(labelEn) > 128 || len(labelRu) > 128 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "label must be at most 128 chars"})
		return
	}

	existing, err := h.repo.GetApartmentCriteria(false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load criteria"})
		return
	}
	taken := make(map[string]bool, len(existing))
	for _, e := range existing {
		taken[e.Key] = true
	}

	item := models.ApartmentCriterion{
		Key:      criterionKey([]string{req.Key, labelEn, labelRu}, taken),
		LabelEn:  labelEn,
		LabelRu:  labelRu,
		Weight:   1,
		IsActive: true,
	}
	if req.Weight != nil {
		if *req.Weight <= 0 || *req.Weight > 10 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "weight must be within 0..10"})
			return
		}
		item.Weight = *req.Weight
	}
	if req.SortOrder != nil {
		item.SortOrder = *req.SortOrder
	}
	if req.IsActive != nil {
		item.IsActive = *req.IsActive
	}

	if err := h.repo.CreateApartmentCriterion(&item); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create criterion"})
		return
	}
	c.JSON(http.StatusCreated, item)
}

func (h *ApartmentHandler) UpdateCriterion(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	item, err := h.repo.GetApartmentCriterionByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "criterion not found"})
		return
	}

	var req struct {
		LabelEn   *string  `json:"label_en"`
		LabelRu   *string  `json:"label_ru"`
		Weight    *float64 `json:"weight"`
		SortOrder *int     `json:"sort_order"`
		IsActive  *bool    `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.LabelEn != nil {
		item.LabelEn = strings.TrimSpace(*req.LabelEn)
	}
	if req.LabelRu != nil {
		item.LabelRu = strings.TrimSpace(*req.LabelRu)
	}
	if item.LabelEn == "" && item.LabelRu == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "label is required in at least one language"})
		return
	}
	if len(item.LabelEn) > 128 || len(item.LabelRu) > 128 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "label must be at most 128 chars"})
		return
	}
	if req.Weight != nil {
		if *req.Weight <= 0 || *req.Weight > 10 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "weight must be within 0..10"})
			return
		}
		item.Weight = *req.Weight
	}
	if req.SortOrder != nil {
		item.SortOrder = *req.SortOrder
	}
	if req.IsActive != nil {
		item.IsActive = *req.IsActive
	}

	if err := h.repo.UpdateApartmentCriterion(item); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update criterion"})
		return
	}
	c.JSON(http.StatusOK, item)
}

func (h *ApartmentHandler) DeleteCriterion(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	if _, err := h.repo.GetApartmentCriterionByID(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "criterion not found"})
		return
	}
	if err := h.repo.DeleteApartmentCriterion(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete criterion"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

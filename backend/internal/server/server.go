package server

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"subadmin/backend/internal/config"
	"subadmin/backend/internal/sublink"
)

type contextKey string

const (
	contextKeyAdmin contextKey = "admin"
)

type AdminClaims struct {
	UserID   int    `json:"uid"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type AdminInfo struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

type Upstream struct {
	ID              int        `json:"id"`
	Name            string     `json:"name"`
	URL             string     `json:"url"`
	Enabled         bool       `json:"enabled"`
	RefreshInterval int        `json:"refresh_interval"`
	LastSyncAt      *time.Time `json:"last_sync_at,omitempty"`
	LastStatus      string     `json:"last_status"`
	CreatedAt       time.Time  `json:"created_at"`
}

type ManualNode struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	RawURI    string    `json:"raw_uri"`
	Enabled   bool      `json:"enabled"`
	GroupName string    `json:"group_name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Settings struct {
	CacheMode     bool   `json:"cache_mode"`
	CacheInterval int    `json:"cache_interval"`
	OutputTemplate string `json:"output_template"`
}

type BackupPayload struct {
	Admins     []BackupAdmin     `json:"admins"`
	Upstreams  []BackupUpstream  `json:"upstreams"`
	ManualNodes []BackupNode     `json:"manual_nodes"`
	Settings   []BackupSetting   `json:"settings"`
	Snapshots  []BackupSnapshot  `json:"snapshots"`
}

type BackupAdmin struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

type BackupUpstream struct {
	ID              int        `json:"id"`
	Name            string     `json:"name"`
	URL             string     `json:"url"`
	Enabled         bool       `json:"enabled"`
	RefreshInterval int        `json:"refresh_interval"`
	LastSyncAt      *time.Time `json:"last_sync_at,omitempty"`
	LastStatus      string     `json:"last_status"`
	CachedContent   string     `json:"cached_content"`
	CreatedAt       time.Time  `json:"created_at"`
}

type BackupNode struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	RawURI    string    `json:"raw_uri"`
	Enabled   bool      `json:"enabled"`
	GroupName string    `json:"group_name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type BackupSetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type BackupSnapshot struct {
	ID        int       `json:"id"`
	Kind      string    `json:"kind"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	Note      string    `json:"note"`
}

type Server struct {
	cfg          *config.Config
	db           *sql.DB
	jwtKey       []byte
	logger       *log.Logger
	router       http.Handler
	sublink      *sublink.Client
	httpClient   *http.Client
	cacheMu      sync.Mutex
	lastCacheRun time.Time
}

func New(cfg *config.Config, db *sql.DB, logger *log.Logger) (*Server, error) {
	if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}

	s := &Server{
		cfg:     cfg,
		db:      db,
		jwtKey:  []byte(cfg.JWTSecret),
		logger:  logger,
		sublink: sublink.New(cfg.SublinkURL, cfg.HTTPTimeout),
		httpClient: &http.Client{
			Timeout: cfg.HTTPTimeout,
		},
	}
	s.router = s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return s.router
}

func (s *Server) routes() http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Get("/clash", s.handleOutput("clash"))
	r.Get("/singbox", s.handleOutput("singbox"))

	r.Route("/api", func(api chi.Router) {
		api.Post("/login", s.handleLogin)
		api.Post("/logout", s.handleLogout)

		api.Group(func(private chi.Router) {
			private.Use(s.authMiddleware)

			private.Get("/me", s.handleMe)
			private.Put("/password", s.handleChangePassword)

			private.Get("/upstreams", s.handleListUpstreams)
			private.Post("/upstreams", s.handleCreateUpstream)
			private.Put("/upstreams/{id}", s.handleUpdateUpstream)
			private.Delete("/upstreams/{id}", s.handleDeleteUpstream)
			private.Post("/upstreams/{id}/sync", s.handleSyncUpstream)
			private.Post("/sync", s.handleSyncAll)

			private.Get("/nodes", s.handleListNodes)
			private.Post("/nodes", s.handleCreateNode)
			private.Put("/nodes/{id}", s.handleUpdateNode)
			private.Delete("/nodes/{id}", s.handleDeleteNode)

			private.Get("/settings", s.handleGetSettings)
			private.Put("/settings", s.handleUpdateSettings)

			private.Get("/backup/export", s.handleExportBackup)
			private.Post("/backup/import", s.handleImportBackup)
		})
	})

	return r
}

func (s *Server) StartScheduler(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.SchedulerTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tickCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			s.runSchedulerTick(tickCtx)
			cancel()
		}
	}
}

func (s *Server) runSchedulerTick(ctx context.Context) {
	if err := s.syncDueUpstreams(ctx); err != nil {
		s.logger.Printf("scheduler sync error: %v", err)
	}

	settings, err := s.getSettings(ctx)
	if err != nil {
		s.logger.Printf("scheduler settings error: %v", err)
		return
	}
	if !settings.CacheMode {
		return
	}

	if time.Since(s.lastCacheRun) < time.Duration(settings.CacheInterval)*time.Minute {
		return
	}

	if _, err := s.refreshCache(ctx); err != nil {
		s.logger.Printf("scheduler refresh cache error: %v", err)
		return
	}
	s.lastCacheRun = time.Now()
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			cookie, err := r.Cookie("subadmin_token")
			if err == nil {
				token = cookie.Value
			}
		}
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing auth token")
			return
		}

		claims := &AdminClaims{}
		parsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return s.jwtKey, nil
		})
		if err != nil || !parsed.Valid {
			writeError(w, http.StatusUnauthorized, "invalid auth token")
			return
		}

		ctx := context.WithValue(r.Context(), contextKeyAdmin, &AdminInfo{ID: claims.UserID, Username: claims.Username})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func adminFromContext(ctx context.Context) (*AdminInfo, bool) {
	admin, ok := ctx.Value(contextKeyAdmin).(*AdminInfo)
	return admin, ok
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	var id int
	var username string
	var passwordHash string
	query := `SELECT id, username, password_hash FROM admins WHERE username = ?`
	if err := s.db.QueryRowContext(r.Context(), query, req.Username).Scan(&id, &username, &passwordHash); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	exp := time.Now().Add(s.cfg.TokenTTL)
	claims := AdminClaims{
		UserID:   id,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   strconv.Itoa(id),
		},
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := jwtToken.SignedString(s.jwtKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create token")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "subadmin_token",
		Value:    tokenString,
		HttpOnly: true,
		Path:     "/",
		Expires:  exp,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"token": tokenString,
		"admin": map[string]any{
			"id":       id,
			"username": username,
		},
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "subadmin_token",
		Value:    "",
		HttpOnly: true,
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "ok"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	admin, ok := adminFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, admin)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	admin, ok := adminFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	type request struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.NewPassword) < 6 {
		writeError(w, http.StatusBadRequest, "new password must be at least 6 characters")
		return
	}

	var currentHash string
	if err := s.db.QueryRowContext(r.Context(), `SELECT password_hash FROM admins WHERE id = ?`, admin.ID).Scan(&currentHash); err != nil {
		writeError(w, http.StatusUnauthorized, "admin not found")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.OldPassword)); err != nil {
		writeError(w, http.StatusUnauthorized, "old password is incorrect")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	if _, err := s.db.ExecContext(r.Context(), `UPDATE admins SET password_hash = ? WHERE id = ?`, string(newHash), admin.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "password updated"})
}

func (s *Server) handleListUpstreams(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryContext(r.Context(), `
		SELECT id, name, url, enabled, refresh_interval, last_sync_at, last_status, created_at
		FROM upstreams
		ORDER BY id DESC`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query upstreams")
		return
	}
	defer rows.Close()

	items := make([]Upstream, 0)
	for rows.Next() {
		var item Upstream
		var enabledInt int
		var lastSync sql.NullTime
		if err := rows.Scan(
			&item.ID,
			&item.Name,
			&item.URL,
			&enabledInt,
			&item.RefreshInterval,
			&lastSync,
			&item.LastStatus,
			&item.CreatedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan upstream")
			return
		}
		item.Enabled = enabledInt == 1
		if lastSync.Valid {
			item.LastSyncAt = &lastSync.Time
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleCreateUpstream(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Name            string `json:"name"`
		URL             string `json:"url"`
		Enabled         *bool  `json:"enabled"`
		RefreshInterval int    `json:"refresh_interval"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.URL) == "" {
		writeError(w, http.StatusBadRequest, "name and url are required")
		return
	}
	if req.RefreshInterval <= 0 {
		req.RefreshInterval = 60
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	result, err := s.db.ExecContext(
		r.Context(),
		`INSERT INTO upstreams(name, url, enabled, refresh_interval, created_at) VALUES(?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		strings.TrimSpace(req.Name),
		strings.TrimSpace(req.URL),
		boolToInt(enabled),
		req.RefreshInterval,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create upstream")
		return
	}
	id, _ := result.LastInsertId()
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Server) handleUpdateUpstream(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid upstream id")
		return
	}

	type request struct {
		Name            string `json:"name"`
		URL             string `json:"url"`
		Enabled         *bool  `json:"enabled"`
		RefreshInterval int    `json:"refresh_interval"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.URL) == "" {
		writeError(w, http.StatusBadRequest, "name and url are required")
		return
	}
	if req.RefreshInterval <= 0 {
		req.RefreshInterval = 60
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	result, err := s.db.ExecContext(
		r.Context(),
		`UPDATE upstreams SET name = ?, url = ?, enabled = ?, refresh_interval = ? WHERE id = ?`,
		strings.TrimSpace(req.Name),
		strings.TrimSpace(req.URL),
		boolToInt(enabled),
		req.RefreshInterval,
		id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update upstream")
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		writeError(w, http.StatusNotFound, "upstream not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "updated"})
}

func (s *Server) handleDeleteUpstream(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid upstream id")
		return
	}
	result, err := s.db.ExecContext(r.Context(), `DELETE FROM upstreams WHERE id = ?`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete upstream")
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		writeError(w, http.StatusNotFound, "upstream not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "deleted"})
}

func (s *Server) handleSyncUpstream(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid upstream id")
		return
	}
	if err := s.syncUpstream(r.Context(), id); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("sync failed: %v", err))
		return
	}
	settings, _ := s.getSettings(r.Context())
	if settings.CacheMode {
		_, _ = s.refreshCache(r.Context())
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "synced"})
}

func (s *Server) handleSyncAll(w http.ResponseWriter, r *http.Request) {
	if err := s.syncAllUpstreams(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("sync failed: %v", err))
		return
	}
	settings, _ := s.getSettings(r.Context())
	if settings.CacheMode {
		_, _ = s.refreshCache(r.Context())
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "all synced"})
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryContext(r.Context(), `
		SELECT id, name, raw_uri, enabled, group_name, created_at, updated_at
		FROM manual_nodes
		ORDER BY id DESC`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query nodes")
		return
	}
	defer rows.Close()

	items := make([]ManualNode, 0)
	for rows.Next() {
		var item ManualNode
		var enabledInt int
		if err := rows.Scan(
			&item.ID,
			&item.Name,
			&item.RawURI,
			&enabledInt,
			&item.GroupName,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan node")
			return
		}
		item.Enabled = enabledInt == 1
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Name      string `json:"name"`
		RawURI    string `json:"raw_uri"`
		Enabled   *bool  `json:"enabled"`
		GroupName string `json:"group_name"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.RawURI) == "" {
		writeError(w, http.StatusBadRequest, "name and raw_uri are required")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	group := strings.TrimSpace(req.GroupName)
	if group == "" {
		group = "default"
	}

	result, err := s.db.ExecContext(
		r.Context(),
		`INSERT INTO manual_nodes(name, raw_uri, enabled, group_name, created_at, updated_at) VALUES(?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		strings.TrimSpace(req.Name),
		strings.TrimSpace(req.RawURI),
		boolToInt(enabled),
		group,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create node")
		return
	}
	id, _ := result.LastInsertId()
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}

	type request struct {
		Name      string `json:"name"`
		RawURI    string `json:"raw_uri"`
		Enabled   *bool  `json:"enabled"`
		GroupName string `json:"group_name"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.RawURI) == "" {
		writeError(w, http.StatusBadRequest, "name and raw_uri are required")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	group := strings.TrimSpace(req.GroupName)
	if group == "" {
		group = "default"
	}

	result, err := s.db.ExecContext(
		r.Context(),
		`UPDATE manual_nodes SET name = ?, raw_uri = ?, enabled = ?, group_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		strings.TrimSpace(req.Name),
		strings.TrimSpace(req.RawURI),
		boolToInt(enabled),
		group,
		id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update node")
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "updated"})
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}
	result, err := s.db.ExecContext(r.Context(), `DELETE FROM manual_nodes WHERE id = ?`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete node")
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "deleted"})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.getSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get settings")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	type request struct {
		CacheMode      *bool  `json:"cache_mode"`
		CacheInterval  *int   `json:"cache_interval"`
		OutputTemplate string `json:"output_template"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	current, err := s.getSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get settings")
		return
	}

	if req.CacheMode != nil {
		current.CacheMode = *req.CacheMode
	}
	if req.CacheInterval != nil && *req.CacheInterval > 0 {
		current.CacheInterval = *req.CacheInterval
	}
	if strings.TrimSpace(req.OutputTemplate) != "" {
		current.OutputTemplate = strings.TrimSpace(req.OutputTemplate)
	}

	if err := s.setSetting(r.Context(), "cache_mode", strconv.FormatBool(current.CacheMode)); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save cache mode")
		return
	}
	if err := s.setSetting(r.Context(), "cache_interval", strconv.Itoa(current.CacheInterval)); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save cache interval")
		return
	}
	if err := s.setSetting(r.Context(), "output_template", current.OutputTemplate); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save output template")
		return
	}
	if current.CacheMode {
		_, _ = s.refreshCache(r.Context())
	}
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) handleOutput(target string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, err := s.getSettings(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to read settings")
			return
		}

		if settings.CacheMode {
			content, err := s.readCache(target)
			if err == nil && strings.TrimSpace(content) != "" {
				writeOutput(w, target, content)
				return
			}

			result, err := s.refreshCache(r.Context())
			if err != nil {
				writeError(w, http.StatusBadGateway, fmt.Sprintf("refresh cache failed: %v", err))
				return
			}
			writeOutput(w, target, result[target])
			return
		}

		nodes, err := s.collectNodesRealtime(r.Context())
		if err != nil {
			writeError(w, http.StatusBadGateway, fmt.Sprintf("collect nodes failed: %v", err))
			return
		}
		content, err := s.sublink.Convert(r.Context(), target, nodes)
		if err != nil {
			writeError(w, http.StatusBadGateway, fmt.Sprintf("convert failed: %v", err))
			return
		}
		writeOutput(w, target, content)
	}
}

func (s *Server) refreshCache(ctx context.Context) (map[string]string, error) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	nodes, err := s.collectNodesFromStore(ctx)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string, 2)
	for _, target := range []string{"clash", "singbox"} {
		converted, err := s.sublink.Convert(ctx, target, nodes)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(s.cacheFile(target), []byte(converted), 0o644); err != nil {
			return nil, fmt.Errorf("write %s cache: %w", target, err)
		}
		if _, err := s.db.ExecContext(
			ctx,
			`INSERT INTO snapshots(kind, content, note, created_at) VALUES(?, ?, ?, CURRENT_TIMESTAMP)`,
			target,
			converted,
			"cache refresh",
		); err != nil {
			s.logger.Printf("insert snapshot failed: %v", err)
		}
		result[target] = converted
	}

	s.lastCacheRun = time.Now()
	return result, nil
}

func (s *Server) collectNodesFromStore(ctx context.Context) ([]string, error) {
	nodes := make([]string, 0)

	rows, err := s.db.QueryContext(ctx, `SELECT cached_content FROM upstreams WHERE enabled = 1`)
	if err != nil {
		return nil, fmt.Errorf("query upstream cache: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cached string
		if err := rows.Scan(&cached); err != nil {
			return nil, fmt.Errorf("scan upstream cache: %w", err)
		}
		nodes = append(nodes, splitNodes(cached)...)
	}

	manualRows, err := s.db.QueryContext(ctx, `SELECT raw_uri FROM manual_nodes WHERE enabled = 1`)
	if err != nil {
		return nil, fmt.Errorf("query manual nodes: %w", err)
	}
	defer manualRows.Close()
	for manualRows.Next() {
		var raw string
		if err := manualRows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan manual node: %w", err)
		}
		raw = strings.TrimSpace(raw)
		if raw != "" {
			nodes = append(nodes, raw)
		}
	}

	return dedupeNodes(nodes), nil
}

func (s *Server) collectNodesRealtime(ctx context.Context) ([]string, error) {
	nodes := make([]string, 0)

	rows, err := s.db.QueryContext(ctx, `SELECT id, url, enabled FROM upstreams ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("query upstreams: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var url string
		var enabledInt int
		if err := rows.Scan(&id, &url, &enabledInt); err != nil {
			return nil, fmt.Errorf("scan upstream: %w", err)
		}
		if enabledInt != 1 {
			continue
		}
		fetched, fetchErr := s.fetchUpstreamNodes(ctx, strings.TrimSpace(url))
		if fetchErr != nil {
			s.logger.Printf("realtime fetch upstream %d failed: %v", id, fetchErr)
			continue
		}
		nodes = append(nodes, fetched...)
	}

	manualRows, err := s.db.QueryContext(ctx, `SELECT raw_uri FROM manual_nodes WHERE enabled = 1`)
	if err != nil {
		return nil, fmt.Errorf("query manual nodes: %w", err)
	}
	defer manualRows.Close()
	for manualRows.Next() {
		var raw string
		if err := manualRows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan manual node: %w", err)
		}
		raw = strings.TrimSpace(raw)
		if raw != "" {
			nodes = append(nodes, raw)
		}
	}

	return dedupeNodes(nodes), nil
}

func (s *Server) syncDueUpstreams(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, refresh_interval, last_sync_at
		FROM upstreams
		WHERE enabled = 1`)
	if err != nil {
		return fmt.Errorf("query due upstreams: %w", err)
	}
	defer rows.Close()

	now := time.Now()
	for rows.Next() {
		var id int
		var interval int
		var lastSync sql.NullTime
		if err := rows.Scan(&id, &interval, &lastSync); err != nil {
			return fmt.Errorf("scan upstream due row: %w", err)
		}
		if interval <= 0 {
			interval = 60
		}
		if lastSync.Valid && now.Sub(lastSync.Time) < time.Duration(interval)*time.Minute {
			continue
		}
		if err := s.syncUpstream(ctx, id); err != nil {
			s.logger.Printf("sync upstream %d failed: %v", id, err)
		}
	}
	return nil
}

func (s *Server) syncAllUpstreams(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM upstreams WHERE enabled = 1`)
	if err != nil {
		return fmt.Errorf("query enabled upstreams: %w", err)
	}
	defer rows.Close()

	var errs []string
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if err := s.syncUpstream(ctx, id); err != nil {
			errs = append(errs, fmt.Sprintf("%d:%v", id, err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (s *Server) syncUpstream(ctx context.Context, id int) error {
	var url string
	var enabledInt int
	if err := s.db.QueryRowContext(ctx, `SELECT url, enabled FROM upstreams WHERE id = ?`, id).Scan(&url, &enabledInt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("upstream %d not found", id)
		}
		return fmt.Errorf("query upstream %d: %w", id, err)
	}
	if enabledInt != 1 {
		return nil
	}

	nodes, err := s.fetchUpstreamNodes(ctx, url)
	if err != nil {
		status := fmt.Sprintf("sync failed: %v", err)
		_, _ = s.db.ExecContext(ctx, `UPDATE upstreams SET last_sync_at = CURRENT_TIMESTAMP, last_status = ? WHERE id = ?`, status, id)
		return err
	}

	status := fmt.Sprintf("ok (%d nodes)", len(nodes))
	_, err = s.db.ExecContext(
		ctx,
		`UPDATE upstreams SET last_sync_at = CURRENT_TIMESTAMP, last_status = ?, cached_content = ? WHERE id = ?`,
		status,
		strings.Join(nodes, "\n"),
		id,
	)
	if err != nil {
		return fmt.Errorf("update upstream cache: %w", err)
	}
	return nil
}

func (s *Server) fetchUpstreamNodes(ctx context.Context, url string) ([]string, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return nil, errors.New("empty upstream url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch upstream: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("upstream status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read upstream: %w", err)
	}

	parsed := parseSubscription(body)
	if len(parsed) == 0 {
		return nil, errors.New("subscription contains no nodes")
	}
	return parsed, nil
}

func parseSubscription(body []byte) []string {
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return nil
	}

	decoded := tryDecodeBase64(raw)
	if decoded != "" {
		lines := splitNodes(decoded)
		if len(lines) > 0 {
			return dedupeNodes(lines)
		}
	}

	return dedupeNodes(splitNodes(raw))
}

func tryDecodeBase64(raw string) string {
	clean := strings.ReplaceAll(raw, "\n", "")
	clean = strings.ReplaceAll(clean, "\r", "")
	clean = strings.TrimSpace(clean)
	if clean == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(clean)
		if err != nil {
			return ""
		}
	}
	text := strings.TrimSpace(string(decoded))
	if !strings.Contains(text, "://") {
		return ""
	}
	return text
}

func splitNodes(text string) []string {
	normalized := strings.ReplaceAll(text, "\r", "")
	lines := strings.Split(normalized, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func dedupeNodes(nodes []string) []string {
	seen := make(map[string]struct{}, len(nodes))
	result := make([]string, 0, len(nodes))
	for _, item := range nodes {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func (s *Server) getSettings(ctx context.Context) (*Settings, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := &Settings{
		CacheMode:      s.cfg.DefaultCacheMode,
		CacheInterval:  s.cfg.DefaultCacheInterval,
		OutputTemplate: "default",
	}

	for rows.Next() {
		var key string
		var value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		switch key {
		case "cache_mode":
			parsed, err := strconv.ParseBool(value)
			if err == nil {
				settings.CacheMode = parsed
			}
		case "cache_interval":
			parsed, err := strconv.Atoi(value)
			if err == nil && parsed > 0 {
				settings.CacheInterval = parsed
			}
		case "output_template":
			if strings.TrimSpace(value) != "" {
				settings.OutputTemplate = strings.TrimSpace(value)
			}
		}
	}

	if settings.CacheInterval <= 0 {
		settings.CacheInterval = 10
	}
	return settings, nil
}

func (s *Server) setSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *Server) handleExportBackup(w http.ResponseWriter, r *http.Request) {
	payload := BackupPayload{}

	adminsRows, err := s.db.QueryContext(r.Context(), `SELECT id, username, password_hash, created_at FROM admins ORDER BY id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query admins failed")
		return
	}
	for adminsRows.Next() {
		var row BackupAdmin
		if err := adminsRows.Scan(&row.ID, &row.Username, &row.PasswordHash, &row.CreatedAt); err != nil {
			adminsRows.Close()
			writeError(w, http.StatusInternalServerError, "scan admins failed")
			return
		}
		payload.Admins = append(payload.Admins, row)
	}
	adminsRows.Close()

	upstreamRows, err := s.db.QueryContext(r.Context(), `SELECT id, name, url, enabled, refresh_interval, last_sync_at, last_status, cached_content, created_at FROM upstreams ORDER BY id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query upstreams failed")
		return
	}
	for upstreamRows.Next() {
		var row BackupUpstream
		var enabledInt int
		var lastSync sql.NullTime
		if err := upstreamRows.Scan(&row.ID, &row.Name, &row.URL, &enabledInt, &row.RefreshInterval, &lastSync, &row.LastStatus, &row.CachedContent, &row.CreatedAt); err != nil {
			upstreamRows.Close()
			writeError(w, http.StatusInternalServerError, "scan upstreams failed")
			return
		}
		row.Enabled = enabledInt == 1
		if lastSync.Valid {
			row.LastSyncAt = &lastSync.Time
		}
		payload.Upstreams = append(payload.Upstreams, row)
	}
	upstreamRows.Close()

	nodeRows, err := s.db.QueryContext(r.Context(), `SELECT id, name, raw_uri, enabled, group_name, created_at, updated_at FROM manual_nodes ORDER BY id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query nodes failed")
		return
	}
	for nodeRows.Next() {
		var row BackupNode
		var enabledInt int
		if err := nodeRows.Scan(&row.ID, &row.Name, &row.RawURI, &enabledInt, &row.GroupName, &row.CreatedAt, &row.UpdatedAt); err != nil {
			nodeRows.Close()
			writeError(w, http.StatusInternalServerError, "scan nodes failed")
			return
		}
		row.Enabled = enabledInt == 1
		payload.ManualNodes = append(payload.ManualNodes, row)
	}
	nodeRows.Close()

	settingRows, err := s.db.QueryContext(r.Context(), `SELECT key, value FROM settings ORDER BY key`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query settings failed")
		return
	}
	for settingRows.Next() {
		var row BackupSetting
		if err := settingRows.Scan(&row.Key, &row.Value); err != nil {
			settingRows.Close()
			writeError(w, http.StatusInternalServerError, "scan settings failed")
			return
		}
		payload.Settings = append(payload.Settings, row)
	}
	settingRows.Close()

	snapshotRows, err := s.db.QueryContext(r.Context(), `SELECT id, kind, content, created_at, note FROM snapshots ORDER BY id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query snapshots failed")
		return
	}
	for snapshotRows.Next() {
		var row BackupSnapshot
		if err := snapshotRows.Scan(&row.ID, &row.Kind, &row.Content, &row.CreatedAt, &row.Note); err != nil {
			snapshotRows.Close()
			writeError(w, http.StatusInternalServerError, "scan snapshots failed")
			return
		}
		payload.Snapshots = append(payload.Snapshots, row)
	}
	snapshotRows.Close()

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=backup-%d.json", time.Now().Unix()))
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleImportBackup(w http.ResponseWriter, r *http.Request) {
	var payload BackupPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid backup payload")
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "start transaction failed")
		return
	}
	defer tx.Rollback()

	clearStatements := []string{
		`DELETE FROM admins`,
		`DELETE FROM upstreams`,
		`DELETE FROM manual_nodes`,
		`DELETE FROM settings`,
		`DELETE FROM snapshots`,
	}
	for _, stmt := range clearStatements {
		if _, err := tx.ExecContext(r.Context(), stmt); err != nil {
			writeError(w, http.StatusInternalServerError, "clear tables failed")
			return
		}
	}

	for _, row := range payload.Admins {
		if _, err := tx.ExecContext(
			r.Context(),
			`INSERT INTO admins(id, username, password_hash, created_at) VALUES(?, ?, ?, ?)`,
			row.ID,
			row.Username,
			row.PasswordHash,
			row.CreatedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "restore admins failed")
			return
		}
	}

	for _, row := range payload.Upstreams {
		if _, err := tx.ExecContext(
			r.Context(),
			`INSERT INTO upstreams(id, name, url, enabled, refresh_interval, last_sync_at, last_status, cached_content, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			row.ID,
			row.Name,
			row.URL,
			boolToInt(row.Enabled),
			row.RefreshInterval,
			row.LastSyncAt,
			row.LastStatus,
			row.CachedContent,
			row.CreatedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "restore upstreams failed")
			return
		}
	}

	for _, row := range payload.ManualNodes {
		if _, err := tx.ExecContext(
			r.Context(),
			`INSERT INTO manual_nodes(id, name, raw_uri, enabled, group_name, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
			row.ID,
			row.Name,
			row.RawURI,
			boolToInt(row.Enabled),
			row.GroupName,
			row.CreatedAt,
			row.UpdatedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "restore nodes failed")
			return
		}
	}

	for _, row := range payload.Settings {
		if _, err := tx.ExecContext(r.Context(), `INSERT INTO settings(key, value) VALUES(?, ?)`, row.Key, row.Value); err != nil {
			writeError(w, http.StatusInternalServerError, "restore settings failed")
			return
		}
	}

	for _, row := range payload.Snapshots {
		if _, err := tx.ExecContext(
			r.Context(),
			`INSERT INTO snapshots(id, kind, content, created_at, note) VALUES(?, ?, ?, ?, ?)`,
			row.ID,
			row.Kind,
			row.Content,
			row.CreatedAt,
			row.Note,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "restore snapshots failed")
			return
		}
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "commit restore failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "backup imported"})
}

func (s *Server) readCache(target string) (string, error) {
	content, err := os.ReadFile(s.cacheFile(target))
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (s *Server) cacheFile(target string) string {
	filename := target + ".txt"
	if target == "clash" {
		filename = "clash.yaml"
	}
	if target == "singbox" {
		filename = "singbox.json"
	}
	return filepath.Join(s.cfg.CacheDir, filename)
}

func writeOutput(w http.ResponseWriter, target, content string) {
	if target == "clash" {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(content))
}

func parseIDParam(r *http.Request, key string) (int, error) {
	value := chi.URLParam(r, key)
	id, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || id <= 0 {
		return 0, errors.New("invalid id")
	}
	return id, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

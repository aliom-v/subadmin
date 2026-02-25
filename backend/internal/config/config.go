package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr            string
	DataDir               string
	DBPath                string
	CacheDir              string
	JWTSecret             string
	TokenTTL              time.Duration
	AdminUsername         string
	AdminPassword         string
	SublinkURL            string
	HTTPTimeout           time.Duration
	DefaultCacheMode      bool
	DefaultCacheInterval  int
	SchedulerTickInterval time.Duration
}

func Load() *Config {
	dataDir := getenv("DATA_DIR", "/data")
	dbPath := getenv("DB_PATH", filepath.Join(dataDir, "subadmin.db"))
	cacheDir := getenv("CACHE_DIR", filepath.Join(dataDir, "cache"))

	return &Config{
		ListenAddr:            getenv("LISTEN_ADDR", ":8080"),
		DataDir:               dataDir,
		DBPath:                dbPath,
		CacheDir:              cacheDir,
		JWTSecret:             getenv("JWT_SECRET", "change-this-in-production"),
		TokenTTL:              time.Duration(getint("TOKEN_TTL_HOURS", 24)) * time.Hour,
		AdminUsername:         getenv("ADMIN_USERNAME", "admin"),
		AdminPassword:         getenv("ADMIN_PASSWORD", "admin123"),
		SublinkURL:            strings.TrimRight(getenv("SUBLINK_URL", "http://sublink:25500"), "/"),
		HTTPTimeout:           time.Duration(getint("HTTP_TIMEOUT_SECONDS", 20)) * time.Second,
		DefaultCacheMode:      getbool("DEFAULT_CACHE_MODE", true),
		DefaultCacheInterval:  getint("DEFAULT_CACHE_INTERVAL_MINUTES", 10),
		SchedulerTickInterval: time.Duration(getint("SCHEDULER_TICK_SECONDS", 30)) * time.Second,
	}
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getint(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getbool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

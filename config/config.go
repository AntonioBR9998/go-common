package config

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type BaseConfig struct {
	Log LogConfig `json:"log"`
	API APIConfig `json:"api"`

	RemoteEnable bool         `json:"-"`
	ConfigPath   string       `json:"-"`
	v            *viper.Viper `json:"-"`
}

func (c *BaseConfig) GetViper() *viper.Viper {
	return c.v
}

func (c *BaseConfig) SetViper(v *viper.Viper) {
	c.v = v
}

func (a *BaseConfig) GetRemoteEnable() bool {
	return a.RemoteEnable
}

func (a *BaseConfig) GetConfigPath() string {
	return a.ConfigPath
}

func (a *BaseConfig) GetLogConfig() *LogConfig {
	return &a.Log
}

type BaseConfigInterface interface {
	GetViper() *viper.Viper
	SetViper(*viper.Viper)
	GetRemoteEnable() bool
	GetConfigPath() string
	GetLogConfig() *LogConfig
}

type APIConfig struct {
	Schema     string `json:"schema"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	TLSEnabled bool   `json:"tlsEnabled"`
	TLSCert    string `json:"tlsCert"`
	TLSKey     string `json:"tlsKey"`
}

func (a APIConfig) GetURL() string {
	return fmt.Sprintf("%s://%s", a.Schema, a.GetRelativeURL())
}

func (a APIConfig) GetRelativeURL() string {
	return fmt.Sprintf("%s:%d", a.Address, a.Port)
}

type PostgreSQLConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbName"`
	SSLMode  string `json:"sslMode"`
}

// LogConfig represents the log configuration
type LogConfig struct {
	FilePath string `json:"filePath"`
	Level    string `json:"level"`
}

// New creates and loads a new configuration.
// This function creates a new configuration and call the
// ReloadConfiguration function.
func New[T BaseConfigInterface](cfg T, opts ...func(cfg T)) T {
	log.Debugln("creating a new configuration")

	var v = viper.NewWithOptions(
		// KeyDelimiter change the dot by double colon.
		// If the configuration contains a key.separated.by.dots or a value.separated.by.dots
		// Viper won't parse them into maps.
		viper.KeyDelimiter("::"),
	)
	cfg.SetViper(v)
	v.SetConfigType("json")

	// Apply options
	log.Traceln("applying options")
	for _, opt := range opts {
		opt(cfg)
	}

	// Reload the configuration
	ReloadConfiguration(cfg)

	return cfg
}

// ReloadConfiguration loads the configuration
func ReloadConfiguration[T BaseConfigInterface](cfg T) {
	log.Debugln("loading configuration")
	log.Traceln("checking if remote configuration provider is enable")
	if cfg.GetRemoteEnable() {
		log.Debugln("getting configuration from remote configuration provider")
		if err := cfg.GetViper().ReadRemoteConfig(); err != nil {
			log.Panicf("configuration error: %v \n", err)
		}
	} else {
		log.Debugln("getting configuration from local file")
		file, err := os.Open(cfg.GetConfigPath())
		if err != nil {
			log.Panic("error to open configuration file path: ", err)
		}

		if err := cfg.GetViper().ReadConfig(file); err != nil {
			log.Panic("error to read configuration file path: ", err)
		}
	}

	log.Traceln("unmarshaling configuration into struct")
	if err := cfg.GetViper().Unmarshal(&cfg); err != nil {
		log.Panicf("unmarshal configuration error: %v\n", err)
	}

	// Set logrus configuration
	SetUpLog(cfg.GetLogConfig())

	log.Debugf("loaded configuration: %v", cfg)
}

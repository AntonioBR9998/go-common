package config

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// SetUpLog configures logrus format and level
func SetUpLog(cfg *LogConfig) {
	log.Infof("Setting up logrus log")

	var logLevelStr string
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		ForceColors:     true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			file := path.Base(f.File)
			funcName := path.Base(f.Function)

			fileColor := "\033[32m"
			funcColor := "\033[36m"
			reset := "\033[0m"

			coloredFunc := fmt.Sprintf("%s%s%s:", funcColor, funcName, reset)
			coloredFile := fmt.Sprintf("%s%s:%d%s", fileColor, file, f.Line, reset)

			return coloredFunc, coloredFile
		},
	})

	if logLevelEnv := cfg.Level; logLevelEnv != "" {
		logLevelStr = logLevelEnv
	} else if logLevelEnv, ok := os.LookupEnv("LOG_LEVEL"); ok {
		logLevelStr = logLevelEnv
	} else {
		flag.StringVar(&logLevelStr, "loglevel", "info", "set log level")
		flag.Parse()
	}

	logLevel, err := log.ParseLevel(logLevelStr)
	if err != nil {
		log.Errorln(err)
		log.Warn("Setting log level to 'info'")
		logLevel = log.InfoLevel
	}

	log.SetLevel(logLevel)

	writers := []io.Writer{
		os.Stdout,
	}

	if filePath := cfg.FilePath; filePath != "" {
		lumberjackLogrotate := &lumberjack.Logger{
			Filename:   filePath,
			MaxSize:    10, // megabytes
			MaxBackups: 0,
			MaxAge:     31,   //days
			Compress:   true, // disabled by default/
		}

		writers = append(writers, lumberjackLogrotate)
	}

	log.SetOutput(io.MultiWriter(writers...))
	log.SetReportCaller(true)
}

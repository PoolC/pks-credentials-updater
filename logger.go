package main

import (
	"log"
	"os"
)

type LoggerGroup struct{}

var Logger = LoggerGroup{}

var (
	infoLogger  = log.New(os.Stdout, "[INFO] ", log.LstdFlags)
	errorLogger = log.New(os.Stderr, "[ERROR] ", log.LstdFlags)
)

func (LoggerGroup) Infof(format string, args ...any) {
	infoLogger.Printf(format, args...)
}

func (LoggerGroup) Errorf(format string, args ...any) {
	errorLogger.Printf(format, args...)
}

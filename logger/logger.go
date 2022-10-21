package logger

import (
	"io"
	"log"
	"os"
)

var (
	verboseLogger *log.Logger
	defaultLogger *log.Logger
)

func init() {
	verboseLogger = log.New(io.Discard, "VERBOSE ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
	defaultLogger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
}

func SetVerbosity(level uint) {
	if level > 0 {
		defaultLogger.SetOutput(os.Stdout)
	} else {
		defaultLogger.SetOutput(io.Discard)
	}

	if level > 1 {
		verboseLogger.SetOutput(os.Stdout)
	} else {
		verboseLogger.SetOutput(io.Discard)
	}
}

func Verbose() *log.Logger {
	return verboseLogger
}

func Default() *log.Logger {
	return defaultLogger
}

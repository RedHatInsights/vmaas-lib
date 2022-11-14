package utils

import (
	log "github.com/sirupsen/logrus"
)

// implement Log function to enable additional log fields
// usage: utils.Log("my_field_1", 1, "my_field_2", 4.3).Info("Testing logging")
func Log(args ...interface{}) *log.Entry {
	nArgs := len(args)
	fields := log.Fields{}
	if nArgs%2 != 0 {
		log.Warningf("Unable to accept odd (%d) arguments count in utils.DebugLog method.", nArgs)
	} else {
		for i := 0; i < nArgs; i += 2 {
			fields[args[i].(string)] = args[i+1]
		}
	}
	return log.WithFields(fields)
}

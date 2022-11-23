package utils

import (
	"fmt"
	"math"
	"runtime"

	"github.com/sirupsen/logrus"
)

func MemTrack(m1 *runtime.MemStats, eventName string) {
	if logrus.GetLevel() == logrus.DebugLevel {
		var m2 runtime.MemStats
		runtime.ReadMemStats(&m2)
		MemUsage(m1, &m2, eventName, "")
	}
}

func MemUsage(m1, m2 *runtime.MemStats, msg, sign string) {
	if len(msg) == 0 {
		msg = "memstat"
	}
	Log(fmt.Sprintf("Alloc: %s", sign), SizeStr(m2.Alloc-m1.Alloc),
		fmt.Sprintf("TotalAlloc: %s", sign), SizeStr(m2.TotalAlloc-m1.TotalAlloc),
		fmt.Sprintf("HeapAlloc: %s", sign), SizeStr(m2.HeapAlloc-m1.HeapAlloc),
	).Debug(msg)
}

var _suffixes = []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"}

// SizeStr Format memory size to human readable
func SizeStr(size uint64) string {
	order := 0
	if size > 0 {
		order = int(math.Log2(float64(size)) / 10)
	}
	return fmt.Sprintf("%.4g%s", float64(size)/float64(int(1)<<(order*10)), _suffixes[order])
}

func RunGC() {
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)
	Log().Debug("Running GC")
	runtime.GC()
	runtime.ReadMemStats(&m2)
	MemUsage(&m2, &m1, "Memory cleaned by GC", "-")
}

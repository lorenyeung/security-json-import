package helpers

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

//TraceData trace data struct
type TraceData struct {
	File string
	Line int
	Fn   string
}

//SetLogger sets logger settings
func SetLogger(logLevelVar string) {
	level, err := log.ParseLevel(logLevelVar)
	if err != nil {
		level = log.InfoLevel
	}
	log.SetLevel(level)

	log.SetReportCaller(true)
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.QuoteEmptyFields = true
	customFormatter.FullTimestamp = true
	customFormatter.CallerPrettyfier = func(f *runtime.Frame) (string, string) {
		repopath := strings.Split(f.File, "/")
		function := strings.Replace(f.Function, "security-json-import/", "", -1)
		return fmt.Sprintf("%s\t", function), fmt.Sprintf(" %s:%d\t", repopath[len(repopath)-1], f.Line)
	}

	log.SetFormatter(customFormatter)
	fmt.Println("Log level set at ", level)
}

//Check logger for errors
func Check(e error, panicCheck bool, logs string, trace TraceData) {
	if e != nil && panicCheck {
		log.Error(logs, " failed with error:", e, " ", trace.Fn, " on line:", trace.Line)
		panic(e)
	}
	if e != nil && !panicCheck {
		log.Warn(logs, " failed with error:", e, " ", trace.Fn, " on line:", trace.Line)
	}
}

//Trace get function data
func Trace() TraceData {
	var trace TraceData
	pc, file, line, ok := runtime.Caller(1)
	if !ok {
		log.Warn("Failed to get function data")
		return trace
	}

	fn := runtime.FuncForPC(pc)
	trace.File = file
	trace.Line = line
	trace.Fn = fn.Name()
	return trace
}

//PrintDownloadPercent self explanatory
func PrintDownloadPercent(done chan int64, path string, total int64) {
	var stop = false
	if total == -1 {
		log.Warn("-1 Content length, can't load download bar, will download silently")
		return
	}
	for {
		select {
		case <-done:
			stop = true
		default:
			file, err := os.Open(path)
			Check(err, true, "Opening file path", Trace())
			fi, err := file.Stat()
			Check(err, true, "Getting file statistics", Trace())
			size := fi.Size()
			if size == 0 {
				size = 1
			}
			var percent = float64(size) / float64(total) * 100
			if percent != 100 {
				fmt.Printf("\r%.0f%% %s", percent, path)
			}
		}
		if stop {
			break
		}
		time.Sleep(time.Second)
	}
}

//Flags struct
type Flags struct {
	WorkersVar, WorkerSleepVar, DuCheckVar, GroupSkipIndexVar, UserSkipIndexVar, PermissionSkipIndexVar int
	StorageWarningVar, StorageThresholdVar                                                              float64
	UsernameVar, ApikeyVar, URLVar, RepoVar, LogLevelVar, CredsFileVar, UserEmailDomainVar              string
	SkipUserImportVar, SkipGroupImportVar, SkipPermissionImportVar, groupsWithUsersListVar              bool
}

//LineCounter counts  how many lines are in a file
func LineCounter(r io.Reader) (int, error) {
	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := r.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			return count, nil

		case err != nil:
			return count, err
		}
	}
}

//SetFlags function
func SetFlags() Flags {
	var flags Flags
	flag.BoolVar(&flags.groupsWithUsersListVar), "groupsWithUsersList", false, "")
	flag.BoolVar(&flags.SkipUserImportVar, "skipUserImport", false, "Skip user import entirely")
	flag.BoolVar(&flags.SkipPermissionImportVar, "skipPermissionImport", false, "Skip permission import entirely")
	flag.BoolVar(&flags.SkipGroupImportVar, "skipGroupImport", false, "Skip group import entirely")
	flag.IntVar(&flags.PermissionSkipIndexVar, "permissionSkipIndex", -1, "Skip import up to specified permission index")
	flag.IntVar(&flags.GroupSkipIndexVar, "groupSkipIndex", -1, "Skip import up to specified group index")
	flag.IntVar(&flags.UserSkipIndexVar, "userSkipIndex", -1, "Skip import up to specified user index")
	flag.StringVar(&flags.UserEmailDomainVar, "userEmailDomain", "@jfrog.com", "Your email domain if using groups with user list")
	flag.StringVar(&flags.LogLevelVar, "log", "INFO", "Order of Severity: TRACE, DEBUG, INFO, WARN, ERROR, FATAL, PANIC")
	flag.IntVar(&flags.WorkersVar, "workers", 50, "Number of workers")
	flag.IntVar(&flags.WorkerSleepVar, "workersleep", 5, "Worker sleep period in seconds")
	flag.IntVar(&flags.DuCheckVar, "ducheck", 5, "Disk Usage check in minutes")
	flag.Float64Var(&flags.StorageWarningVar, "duwarn", 70, "Set Disk usage warning in %")
	flag.Float64Var(&flags.StorageThresholdVar, "duthreshold", 85, "Set Disk usage threshold in %")
	flag.StringVar(&flags.UsernameVar, "user", "", "Username")
	flag.StringVar(&flags.ApikeyVar, "apikey", "", "API key or password")
	flag.StringVar(&flags.URLVar, "url", "", "Binary Manager URL")
	flag.StringVar(&flags.CredsFileVar, "credsfile", "", "File with creds. If there is more than one, it will pick randomly per request. Use whitespace to separate out user and password")
	flag.Parse()
	return flags
}

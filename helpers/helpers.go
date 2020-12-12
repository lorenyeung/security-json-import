package helpers

import (
	"flag"
	"fmt"
	"runtime"
	"strings"

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

//Flags struct
type Flags struct {
	WorkersVar, WorkerSleepVar, SkipGroupIndexVar, SkipUserIndexVar, SkipPermissionIndexVar                                                 int
	UsernameVar, ApikeyVar, URLVar, RepoVar, LogLevelVar, CredsFileVar, UserEmailDomainVar, UserGroupAssocationFileVar, SecurityJSONFileVar string
	SkipUserImportVar, SkipGroupImportVar, SkipPermissionImportVar, UsersWithGroupsVar, UsersFromGroupsVar                                  bool
}

//SetFlags function
func SetFlags() Flags {
	var flags Flags
	//mandatory flags
	flag.BoolVar(&flags.UsersWithGroupsVar, "usersWithGroups", false, "Import users via users with group list")
	flag.BoolVar(&flags.UsersFromGroupsVar, "usersFromGroups", false, "Import users via group with users list")
	flag.StringVar(&flags.UserGroupAssocationFileVar, "userGroupAssocationFile", "", "File from with the output of either getUsersFromGroups.sh or getUsersWithGroups.sh")
	flag.StringVar(&flags.SecurityJSONFileVar, "securityJSONFile", "", "Security JSON file from Artifactory Support Bundle")
	flag.StringVar(&flags.UsernameVar, "user", "", "Username")
	flag.StringVar(&flags.ApikeyVar, "apikey", "", "API key or password")
	flag.StringVar(&flags.URLVar, "url", "", "Binary Manager URL")

	//skip flags
	flag.BoolVar(&flags.SkipGroupImportVar, "skipGroupImport", false, "Skip group import entirely")
	flag.BoolVar(&flags.SkipPermissionImportVar, "skipPermissionImport", false, "Skip permission import entirely")
	flag.BoolVar(&flags.SkipUserImportVar, "skipUserImport", false, "Skip user import entirely")
	flag.IntVar(&flags.SkipGroupIndexVar, "skipGroupIndex", -1, "Skip import up to specified group index")
	flag.IntVar(&flags.SkipPermissionIndexVar, "skipPermissionIndex", -1, "Skip import up to specified permission index")
	flag.IntVar(&flags.SkipUserIndexVar, "skipUserIndex", -1, "Skip import up to specified user index")

	//customise flags
	flag.StringVar(&flags.UserEmailDomainVar, "userEmailDomain", "@jfrog.com", "Your email domain if using groups with user list")
	flag.StringVar(&flags.CredsFileVar, "credsFile", "", "File with creds. If there is more than one, it will pick randomly per request. Use whitespace to separate out user and password")

	//config flags
	flag.StringVar(&flags.LogLevelVar, "log", "INFO", "Order of Severity: TRACE, DEBUG, INFO, WARN, ERROR, FATAL, PANIC")
	flag.IntVar(&flags.WorkersVar, "workers", 50, "Number of workers")
	flag.IntVar(&flags.WorkerSleepVar, "workerSleep", 5, "Worker sleep period in seconds")

	flag.Parse()
	return flags
}

package main

import (
	"bufio"
	"container/list"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"security-json-import/access"
	"security-json-import/auth"
	"security-json-import/helpers"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

func main() {

	flags := helpers.SetFlags()
	helpers.SetLogger(flags.LogLevelVar)

	if flags.UsernameVar == "" {
		log.Error("Username cannot be empty")
		os.Exit(1)
	}
	if flags.ApikeyVar == "" {
		log.Error("API key/password cannot be empty")
		os.Exit(1)
	}
	if flags.URLVar == "" {
		log.Error("URL cannot be empty")
		os.Exit(1)
	}

	var creds auth.Creds
	creds.Username = flags.UsernameVar
	creds.Apikey = flags.ApikeyVar
	creds.URL = flags.URLVar

	//use different users to create things
	credsFilelength := 0
	credsFileHash := make(map[int][]string)
	if flags.CredsFileVar != "" {
		credsFile, err := os.Open(flags.CredsFileVar)
		if err != nil {
			log.Error("Invalid creds file:", err)
			os.Exit(0)
		}
		defer credsFile.Close()
		scanner := bufio.NewScanner(credsFile)

		for scanner.Scan() {
			credsFileCreds := strings.Split(scanner.Text(), " ")
			credsFileHash[credsFilelength] = credsFileCreds
			credsFilelength = credsFilelength + 1
		}

		flags.UsernameVar = credsFileHash[0][0]
		flags.ApikeyVar = credsFileHash[0][1]
		log.Info("Number of creds in file:", credsFilelength)
		log.Info("choose first one first:", flags.UsernameVar)
	}

	if !auth.VerifyAPIKey(flags.URLVar, flags.UsernameVar, flags.ApikeyVar) {
		log.Error("Looks like there's an issue with your credentials. Exiting")
		os.Exit(1)
	}

	//case switch for different access types
	workQueue := list.New()

	//hardcode now
	go func() {
		err := access.ReadSecurityJSON(workQueue, "/Users/loreny/security-json-convert/security.json", "/Users/loreny/security-json-convert/user-group-association.json", true)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}()

	//build the list here
	// go func() {
	// 	debian.GetDebianHrefs(extractedURL+"pool/", extractedURLStripped, 1, "", workQueue)
	// }()

	//disk usage check
	go func() {
		for {
			log.Debug("Running Storage summary check every ", flags.DuCheckVar, " minutes")
			auth.StorageCheck(creds, flags.StorageWarningVar, flags.StorageThresholdVar)
			time.Sleep(time.Duration(flags.DuCheckVar) * time.Minute)
		}
	}()

	//work queue
	var ch = make(chan interface{}, flags.WorkersVar+1)
	var wg sync.WaitGroup
	for i := 0; i < flags.WorkersVar; i++ {
		go func(i int) {
			for {

				s, ok := <-ch
				if !ok {
					log.Info("Worker being returned to queue", i)
					wg.Done()
				}
				log.Debug("worker ", i, " starting job")

				if flags.CredsFileVar != "" {
					//pick random user and password from list
					numCreds := len(credsFileHash)
					rand.Seed(time.Now().UnixNano())
					randCredIndex := rand.Intn(numCreds)
					creds.Username = credsFileHash[randCredIndex][0]
					creds.Apikey = credsFileHash[randCredIndex][1]
				}

				//get data
				requestData := s.(access.ListTypes)
				switch requestData.AccessType {

				case "group":
					md := requestData.Group
					log.Debug("worker ", i, " starting group index:", requestData.GroupIndex, " name:", md.Name)
					if requestData.GroupIndex < flags.GroupSkipIndexVar {
						log.Info("worker ", i, " skipping group index:", requestData.GroupIndex, " name:", md.Name)

					} else {

						groupData, err := json.Marshal(md)
						if err != nil {
							log.Error("Error reading groups: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
						}
						data, respCode, _ := auth.GetRestAPI("PUT", true, creds.URL+"/api/security/groups/"+md.Name, creds.Username, creds.Apikey, "", groupData, map[string]string{"Content-Type": "application/json"}, 0)
						log.Info("worker ", i, " finished group index:", requestData.GroupIndex, " name:", md.Name, " HTTP ", respCode)
						//201 created
						if respCode != 201 {

							log.Warn("some error occured on index ", requestData.GroupIndex, ":", data)
						}
					}
				}
				log.Debug("worker ", i, " finished job")
			}
		}(i)

	}

	//debug port
	go func() {
		http.ListenAndServe("0.0.0.0:8080", nil)
	}()
	for {
		var count0 = 0
		for workQueue.Len() == 0 {
			log.Info(" work queue is empty, sleeping for ", flags.WorkerSleepVar, " seconds...")
			time.Sleep(time.Duration(flags.WorkerSleepVar) * time.Second)
			count0++
			if count0 > 10 {
				log.Warn("Looks like nothing's getting put into the workqueue. You might want to enable -debug and take a look")
			}
			if workQueue.Len() > 0 {
				count0 = 0
			}
		}
		s := workQueue.Front().Value
		workQueue.Remove(workQueue.Front())
		ch <- s
	}
	close(ch)
	wg.Wait()
}

func standardDownload(creds auth.Creds, dlURL string, file string, configPath string, pkgRepoDlFolder string, repoVar string) {
	_, headStatusCode, _ := auth.GetRestAPI("HEAD", true, creds.URL+"/"+repoVar+"-cache/"+dlURL, creds.Username, creds.Apikey, "", nil, nil, 1)
	if headStatusCode == 200 {
		log.Debug("skipping, got 200 on HEAD request for %s\n", creds.URL+"/"+repoVar+"-cache/"+dlURL)
		return
	}

	log.Info("Downloading", creds.URL+"/"+repoVar+dlURL)
	auth.GetRestAPI("GET", true, creds.URL+"/"+repoVar+dlURL, creds.Username, creds.Apikey, configPath+pkgRepoDlFolder+"/"+file, nil, nil, 1)
	os.Remove(configPath + pkgRepoDlFolder + "/" + file)
}

//Test if remote repository exists and is a remote
func checkTypeAndRepoParams(creds auth.Creds, repoVar string) (string, string, string, string) {
	repoCheckData, repoStatusCode, _ := auth.GetRestAPI("GET", true, creds.URL+"/api/repositories/"+repoVar, creds.Username, creds.Apikey, "", nil, nil, 1)
	if repoStatusCode != 200 {
		log.Error("Repo", repoVar, "does not exist.")
		os.Exit(0)
	}
	var result map[string]interface{}
	json.Unmarshal([]byte(repoCheckData), &result)
	//TODO: hard code for now, mass upload of files
	if result["rclass"] == "local" && result["packageType"].(string) == "generic" {
		return result["packageType"].(string), "", "", ""
	} else if result["rclass"] != "remote" {
		log.Error(repoVar, "is a", result["rclass"], "repository and not a remote repository.")
		//maybe here.
		os.Exit(0)
	}
	if result["packageType"].(string) == "pypi" {
		return result["packageType"].(string), result["url"].(string), result["pyPIRegistryUrl"].(string), result["pyPIRepositorySuffix"].(string)
	}
	return result["packageType"].(string), result["url"].(string), "", ""
}

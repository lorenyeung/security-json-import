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

	//if user name is admin, this can be problematic as it will likely exist in the import.
	if flags.UsernameVar == "admin" || flags.UsernameVar == "access-admin" || flags.UsernameVar == "system" {
		log.Warn("Your username ", flags.UsernameVar, " is a common user that may get overwritten. We recommend recreating a unique admin level user for this program to work correctly.")
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

	//hardcode for now
	go func() {
		err := access.ReadSecurityJSON(workQueue, "/Users/loreny/security-json-convert/security.json", "/Users/loreny/security-json-convert/user-group-association.json", true, flags)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}()

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

				case "permissionsV2":
					md := requestData.PermissionV2
					log.Debug("worker ", i, " starting repo perm v2 index:", requestData.RepoPermissionIndex, " name:", md.Name)
					permissionData, err := json.Marshal(md)
					if err != nil {
						log.Error("Error marshaling repo perm v2: " + md.Name + " " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
						continue
					}
					log.Debug("worker ", i, " repo perm v2 JSON:", string(permissionData), "index ", requestData.RepoPermissionIndex)
					data, respPermCode, _ := auth.GetRestAPI("PUT", true, creds.URL+"/api/v2/security/permissions/"+md.Name, creds.Username, creds.Apikey, "", permissionData, map[string]string{"Content-Type": "application/json"}, 0)
					log.Info("worker ", i, " finished creating repo perm v2 index:", requestData.RepoPermissionIndex, " name:", md.Name, " HTTP ", respPermCode)
					if respPermCode != 200 {

						log.Warn("some error occured on repo perm v2 index ", requestData.RepoPermissionIndex, ":", string(data))
						os.Exit(1)
					}

				case "group":
					md := requestData.Group
					log.Debug("worker ", i, " starting group index:", requestData.GroupIndex, " name:", md.Name)
					if requestData.GroupIndex < flags.GroupSkipIndexVar {
						log.Info("worker ", i, " skipping group index:", requestData.GroupIndex, " name:", md.Name)

					} else {

						groupData, err := json.Marshal(md)
						if err != nil {
							log.Error("Error marshaling group: " + md.Name + " " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
							continue
						}
						log.Debug("worker ", i, " group JSON:", string(groupData), " index ", requestData.GroupIndex)
						data, respGroupCode, _ := auth.GetRestAPI("PUT", true, creds.URL+"/api/security/groups/"+md.Name, creds.Username, creds.Apikey, "", groupData, map[string]string{"Content-Type": "application/json"}, 0)
						log.Info("worker ", i, " finished creating group index:", requestData.GroupIndex, " name:", md.Name, " HTTP ", respGroupCode)
						//201 created
						if respGroupCode != 201 {
							log.Warn("some error occured on group index ", requestData.GroupIndex, ":", string(data))
						}
					}
				case "userFromGroups":
					md := requestData.User
					log.Info("worker ", i, " starting user index:", requestData.UserIndex, " name:", md.Name)
					if requestData.UserIndex < flags.UserSkipIndexVar {
						log.Info("worker ", i, " skipping user index:", requestData.UserIndex, " name:", md.Name)
					} else {
						//check if user exists
						data, respUserCode, _ := auth.GetRestAPI("GET", true, creds.URL+"/api/security/users/"+md.Name, creds.Username, creds.Apikey, "", nil, nil, 0)

						if respUserCode == 404 {
							log.Info("worker ", i, " did not find user ", md.Name, " creating now")
							userData, err := json.Marshal(md)
							if err != nil {
								log.Error("Error marshaling user: " + md.Name + " " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
								continue
							}
							log.Debug("worker ", i, " user JSON index ", requestData.UserIndex, ":", string(userData))
							_, respUserCode, _ := auth.GetRestAPI("PUT", true, creds.URL+"/api/security/users/"+md.Name, creds.Username, creds.Apikey, "", userData, map[string]string{"Content-Type": "application/json"}, 0)
							log.Info("worker ", i, " finished creating user index:", requestData.UserIndex, " name:", md.Name, " HTTP ", respUserCode)
						} else if respUserCode == 200 {
							//user exists
							var existingUserData access.UserImport
							err := json.Unmarshal(data, &existingUserData)
							if err != nil {
								log.Error("Error unmarshaling existing user: " + md.Name + " " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
								continue
							}
							combinedGroups := append(existingUserData.Groups, md.Groups...)
							md.Groups = combinedGroups
							userData, err := json.Marshal(md)
							if err != nil {
								log.Error("Error marshaling user: " + md.Name + " " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
								continue
							}
							log.Debug("worker ", i, " user JSON index ", requestData.UserIndex, ":", string(userData))
							data2, respUserCode, _ := auth.GetRestAPI("PUT", true, creds.URL+"/api/security/users/"+md.Name, creds.Username, creds.Apikey, "", userData, map[string]string{"Content-Type": "application/json"}, 0)
							log.Info("worker ", i, " finished updating user index:", requestData.UserIndex, " name:", md.Name, " HTTP ", respUserCode)
							if respUserCode != 201 {
								log.Warn("some error occured on user index ", requestData.UserIndex, ":", string(data2))
							}

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

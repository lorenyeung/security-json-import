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
	startTime := time.Now()

	flags := helpers.SetFlags()
	helpers.SetLogger(flags.LogLevelVar)

	stringFlags := map[string]string{"-user": flags.UsernameVar, "-apikey": flags.ApikeyVar, "-url": flags.URLVar, "-securityJSONFile": flags.SecurityJSONFileVar}

	var missing bool = false
	for i := range stringFlags {
		if stringFlags[i] == "" {
			log.Error(i + " cannot be empty")
			missing = true
		}
	}
	if !flags.SkipUserImportVar {
		if (flags.UsersWithGroupsVar == false && flags.UsersFromGroupsVar == false) || (flags.UsersWithGroupsVar == true && flags.UsersFromGroupsVar == true) {
			log.Error("When selecting user import source, please only pick one: -usersWithGroups or -usersFromGroups")
			missing = true
		}
		if flags.UserGroupAssocationFileVar == "" {
			log.Error("-userGroupAssocationFile cannot be empty")
			missing = true
		}
	}
	if missing {
		os.Exit(2)
	}
	//if user name is admin, this can be problematic as it will likely exist in the import.
	if flags.UsernameVar == "admin" || flags.UsernameVar == "access-admin" || flags.UsernameVar == "system" {
		log.Warn("Your username ", flags.UsernameVar, " is a common user that may get overwritten. We recommend recreating a unique admin level user for this program to work correctly.")
		os.Exit(2)
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
			os.Exit(1)
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
	requestQueue := list.New()
	failureQueue := list.New()

	//hardcode for now
	go func() {
		err := access.ReadSecurityJSON(workQueue, flags)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
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
					requestQueue.PushBack(s)
					md := requestData.Group
					log.Debug("worker ", i, " starting group index:", requestData.GroupIndex, " name:", md.Name)
					if requestData.GroupIndex < flags.SkipGroupIndexVar {
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
							failureQueue.PushBack(requestData)
						}
					}
					requestQueue.Remove(requestQueue.Front())
				case "permissionV2":
					requestQueue.PushBack(s)
					md := requestData.PermissionV2
					log.Debug("worker ", i, " starting permission v2 index:", requestData.PermissionIndex, " name:", md.Name)
					if requestData.PermissionIndex < flags.SkipPermissionIndexVar {
						log.Info("worker ", i, " skipping permission v2 index:", requestData.PermissionIndex, " name:", md.Name)
					} else {
						permissionData, err := json.Marshal(md)
						if err != nil {
							log.Error("Error marshaling permission v2: " + md.Name + " " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
							continue
						}
						log.Debug("worker ", i, " permission v2 JSON:", string(permissionData), "index ", requestData.PermissionIndex)
						data, respPermCode, _ := auth.GetRestAPI("PUT", true, creds.URL+"/api/v2/security/permissions/"+md.Name, creds.Username, creds.Apikey, "", permissionData, map[string]string{"Content-Type": "application/json"}, 0)
						log.Info("worker ", i, " finished creating permission v2 index:", requestData.PermissionIndex, " name:", md.Name, " HTTP ", respPermCode)
						if respPermCode != 200 {
							log.Warn("some error occured on permission v2 index ", requestData.PermissionIndex, ":", string(data))
							failureQueue.PushBack(requestData)
						}
					}
					requestQueue.Remove(requestQueue.Front())
				case "user":
					requestQueue.PushBack(s)
					md := requestData.User
					log.Info("worker ", i, " starting user index:", requestData.UserIndex, " name:", md.Name)
					if requestData.UserIndex < flags.SkipUserIndexVar {
						log.Info("worker ", i, " skipping user index:", requestData.UserIndex, " name:", md.Name)
					} else {
						forbiddenNames := map[string]string{"admin": "bad", "xray": "bad", "_internal": "bad", "anonymous": "bad"}
						if forbiddenNames[md.Name] == "bad" {
							log.Info("worker ", i, " skipping user index:", requestData.UserIndex, " name:", md.Name, " as it is internal")
							continue
						}

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
								failureQueue.PushBack(requestData)
							}
						}
					}
					requestQueue.Remove(requestQueue.Front())
				case "end":

					auth.GetRestAPI("GET", true, creds.URL+"/api/system/ping", creds.Username, creds.Apikey, "", nil, nil, 0)
					for requestQueue.Len() > 0 {
						log.Info("End detected, waiting for last few requests to go through. Request queue size ", requestQueue.Len())
						time.Sleep(time.Duration(flags.WorkerSleepVar) * time.Second)
					}
					endTime := time.Now()
					log.Info("Completed import in ", endTime.Sub(startTime), "")
					if failureQueue.Len() > 0 {
						log.Warn("There were ", failureQueue.Len(), " failures. The following imports failed:")
						for e := failureQueue.Front(); e != nil; e = e.Next() {
							// do something with e.Value
							value := e.Value.(access.ListTypes)
							switch value.AccessType {
							case "group":
								md := value.Group
								data, err := json.Marshal(md)
								if err != nil {
									log.Error("Error marshaling ", value.AccessType+": "+md.Name+" "+err.Error()+" "+helpers.Trace().Fn+":"+strconv.Itoa(helpers.Trace().Line))
									continue
								} else {
									fmt.Println(value.AccessType, md.Name, "data:", string(data))
								}
							case "permission":
								md := value.PermissionV2
								data, err := json.Marshal(md)
								if err != nil {
									log.Error("Error marshaling ", value.AccessType+": "+md.Name+" "+err.Error()+" "+helpers.Trace().Fn+":"+strconv.Itoa(helpers.Trace().Line))
									continue
								} else {
									fmt.Println(value.AccessType, md.Name, "data:", string(data))
								}
							case "user":
								md := value.User
								data, err := json.Marshal(md)
								if err != nil {
									log.Error("Error marshaling ", value.AccessType+": "+md.Name+" "+err.Error()+" "+helpers.Trace().Fn+":"+strconv.Itoa(helpers.Trace().Line))
									continue
								} else {
									fmt.Println(value.AccessType, md.Name, "data:", string(data))
								}
							}
						}
						fmt.Println("Do you want to retry these? (y/n)")
						if askForConfirmation() {
							for failureQueue.Len() > 0 {
								value := failureQueue.Front().Value.(access.ListTypes)
								log.Info("Re-queuing ", value.AccessType, " ", value.Name)

								workQueue.PushBack(value)
								failureQueue.Remove(failureQueue.Front())
							}
							var endTask access.ListTypes
							endTask.AccessType = "end"
							workQueue.PushBack(endTask)
						} else {
							os.Exit(0)
						}
					} else {
						os.Exit(0)
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
			log.Debug(" work queue is empty, sleeping for ", flags.WorkerSleepVar, " seconds...")
			time.Sleep(time.Duration(flags.WorkerSleepVar) * time.Second)
			count0++
			if count0 > 10 {
				log.Debug("Looks like nothing's getting put into the workqueue. You might want to enable -debug and take a look")
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

//https://gist.github.com/albrow/5882501
func askForConfirmation() bool {
	var response string
	_, err := fmt.Scanln(&response)
	if err != nil {
		log.Fatal(err)
	}
	okayResponses := []string{"y", "Y", "yes", "Yes", "YES"}
	nokayResponses := []string{"n", "N", "no", "No", "NO"}
	if containsString(okayResponses, response) {
		return true
	} else if containsString(nokayResponses, response) {
		return false
	} else {
		fmt.Println("Please type yes or no and then press enter:")
		return askForConfirmation()
	}
}

func posString(slice []string, element string) int {
	for index, elem := range slice {
		if elem == element {
			return index
		}
	}
	return -1
}

// containsString returns true iff slice contains element
func containsString(slice []string, element string) bool {
	return !(posString(slice, element) == -1)
}

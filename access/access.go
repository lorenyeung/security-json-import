package access

import (
	"container/list"
	"encoding/json"
	"errors"
	"io/ioutil"
	"security-json-import/helpers"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type Groups struct {
	Groups []GroupData `json:"groups"`
}

type GroupData struct {
	GroupName       string `json:"groupName"`
	Description     string `json:"description"`
	NewUserDefault  bool   `json:"newUserDefault"`
	Realm           string `json:"realm"`
	AdminPrivileges bool   `json:"adminPrivileges"`
	External        bool   `json:"external"`
}
type GroupImport struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	AutoJoin        bool   `json:"autoJoin"`
	Realm           string `json:"realm"`
	AdminPrivileges bool   `json:"adminPrivileges"`
}

type UserImport struct {
	Name                     string   `json:"name"`
	Email                    string   `json:"email"`
	Password                 string   `json:"password"`
	Admin                    bool     `json:"admin"`
	ProfileUpdatable         bool     `json:"profileUpdatable"`
	DisableUIAccess          bool     `json:"disableUIAccess"`
	InternalPasswordDisabled bool     `json:"internalPasswordDisabled"`
	Groups                   []string `json:"groups"`
	WatchManager             bool     `json:"watchManager"`
	PolicyManager            bool     `json:"policyManager"`
}

type RepoPermissions struct {
	RepoAcls []PermissionsAcls `json:"repoAcls"`
}

type BuildPermissions struct {
	BuildAcls []PermissionsAcls `json:"buildAcls"`
}

type PermissionsAcls struct {
	Aces             []PermissionsAces `json:"aces"`
	MutableAces      []PermissionsAces `json:"mutableAces"`
	UpdatedBy        string            `json:"updatedBy"`
	AccessIdentifier string            `json:"accessIdentifier"`
	PermissionTarget struct {
		Name            string   `json:"name"`
		Includes        []string `json:"includes"`
		Excludes        []string `json:"excludes"`
		RepoKeys        []string `json:"repoKeys"`
		IncludesPattern string   `json:"includesPattern"`
		ExcludesPattern string   `json:"excludesPattern"`
	} `json:"permissionTarget"`
}
type PermissionsAces struct {
	Principal               string   `json:"principal"`
	Group                   bool     `json:"group"`
	Mask                    int      `json:"mask"`
	PermissionsAsString     []string `json:"permissionsAsString"`
	PermissionsDisplayNames []string `json:"permissionsDisplayNames"`
	PermissionsUiNames      []string `json:"permissionsUiNames"`
}

type PermissionV2Import struct {
	Name string `json:"name"`
	Repo struct {
		IncludePatterns []string                  `json:"include-patterns"`
		ExcludePatterns []string                  `json:"exclude-patterns"`
		Repositories    []string                  `json:"repositories"`
		Actions         PermissionV2ActionsImport `json:"actions,omitempty"`
	} `json:"repo,omitempty"`
	Build struct {
		IncludePatterns []string                  `json:"include-patterns"`
		ExcludePatterns []string                  `json:"exclude-patterns"`
		Repositories    []string                  `json:"repositories"`
		Actions         PermissionV2ActionsImport `json:"actions,omitempty"`
	} `json:"build,omitempty"`
}

type PermissionV2ActionsImport struct {
	Users  map[string][]string `json:"users,omitempty"`
	Groups map[string][]string `json:"groups,omitempty"`
}

type PermissionImport struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	AutoJoin        string `json:"autoJoin"`
	Realm           string `json:"realm"`
	AdminPrivileges string `json:"adminPrivileges"`
}

type CreateUsersFromGroupsJSON struct {
	Groups []CreateUsersFromGroupsDataJSON `json:"groups"`
}

type CreateUsersFromGroupsDataJSON struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	AutoJoin        bool     `json:"autoJoin"`
	Realm           string   `json:"realm"`
	AdminPrivileges bool     `json:"adminPrivileges"`
	UserNames       []string `json:"userNames"`
}

type ListTypes struct {
	Group                GroupImport
	User                 UserImport
	Permission           PermissionImport
	PermissionV2         PermissionV2Import
	AccessType           string
	GroupIndex           int
	RepoPermissionIndex  int
	BuildPermissionIndex int
	UserIndex            int
}

func ReadSecurityJSON(workQueue *list.List, securityJSONPath string, groupsWithUsersListJSONPath string, groupsWithUsersList bool, flags helpers.Flags) error {

	//TODO: this reads whole file into memory, be wary of OOM
	log.Info("reading security json")
	data, err := ioutil.ReadFile(securityJSONPath)
	if err != nil {
		log.Error("Error reading security json" + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		return errors.New("Error reading security json" + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
	}

	//groups
	if !flags.SkipGroupImportVar {
		ReadGroups(workQueue, data)
	}

	//users
	if !flags.SkipUserImportVar {
		if !strings.Contains(flags.UserEmailDomainVar, "@") {
			log.Warn("missing @ for email field, preppending @")
			flags.UserEmailDomainVar = "@" + flags.UserEmailDomainVar
		}
		if flags.groupsWithUsersList {
			//TODO check if art > 6.13.0 or not
			data2, err := ioutil.ReadFile(groupsWithUsersListJSONPath)
			if err != nil {
				log.Error("Error reading groups with users list json: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
				return errors.New("Error reading groups with users list json: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
			}
			CreateUsersFromGroups(workQueue, data2, flags.UserEmailDomainVar)
		}
	}

	//permission targets
	if !flags.SkipPermissionImportVar {
		ReadRepoPermissionAcls(workQueue, data)
		ReadBuildPermissionAcls(workQueue, data)
	}
	return nil
}

func ReadGroups(workQueue *list.List, data []byte) error {
	var result Groups
	err := json.Unmarshal(data, &result)
	if err != nil {
		log.Error("Error reading groups: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		return err
	}
	log.Info("reading groups")
	log.Info("Number of groups:", len(result.Groups))

	for i := range result.Groups {
		var data ListTypes
		data.AccessType = "group"
		var groupData GroupImport
		groupData.Name = result.Groups[i].GroupName
		groupData.Description = result.Groups[i].Description
		groupData.AutoJoin = result.Groups[i].NewUserDefault
		groupData.Realm = result.Groups[i].Realm
		groupData.AdminPrivileges = result.Groups[i].AdminPrivileges
		data.GroupIndex = i
		data.Group = groupData
		workQueue.PushBack(data)
	}
	return nil
}

func ReadRepoPermissionAcls(workQueue *list.List, data []byte) error {
	var repoPermissionData RepoPermissions
	err := json.Unmarshal(data, &repoPermissionData)
	if err != nil {
		log.Error("Error reading repo permissions: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		return err
	}
	log.Info("reading repo permissions")
	log.Info("Number of Aces:", len(repoPermissionData.RepoAcls))
	CreatePermissionQueueObject(workQueue, repoPermissionData.RepoAcls)
	return nil
}

func ReadBuildPermissionAcls(workQueue *list.List, data []byte) error {
	var result BuildPermissions
	err := json.Unmarshal(data, &result)
	if err != nil {
		log.Error("Error reading build permissions: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		return err
	}
	log.Info("reading build permissions")
	log.Info("Number of Aces:", len(result.BuildAcls))
	CreatePermissionQueueObject(workQueue, result.BuildAcls)
	return nil
}

func CreatePermissionQueueObject(workQueue *list.List, repoAcls []PermissionsAcls) error {
	for i := range repoAcls {
		//check if v2 if > 6.6?
		var permissionData PermissionV2Import
		var data ListTypes
		data.AccessType = "permissionsV2"
		permissionData.Name = repoAcls[i].PermissionTarget.Name
		permissionData.Repo.IncludePatterns = repoAcls[i].PermissionTarget.Includes
		permissionData.Repo.ExcludePatterns = repoAcls[i].PermissionTarget.Excludes
		permissionData.Repo.Repositories = repoAcls[i].PermissionTarget.RepoKeys
		for j := range repoAcls[i].Aces {
			if repoAcls[i].Aces[j].Group {
				if permissionData.Repo.Actions.Groups == nil {
					permissionData.Repo.Actions.Groups = make(map[string][]string)
				}
				permissionData.Repo.Actions.Groups[repoAcls[i].Aces[j].Principal] = repoAcls[i].Aces[j].PermissionsDisplayNames
			} else {
				if permissionData.Repo.Actions.Users == nil {
					permissionData.Repo.Actions.Users = make(map[string][]string)
				}
				permissionData.Repo.Actions.Users[repoAcls[i].Aces[j].Principal] = repoAcls[i].Aces[j].PermissionsDisplayNames
			}
		}
		data.RepoPermissionIndex = i
		data.PermissionV2 = permissionData
		workQueue.PushBack(data)
	}
	return nil
}

func CreateUsersFromGroups(workQueue *list.List, data []byte, UserEmailDomain string) error {
	var result CreateUsersFromGroupsJSON
	err := json.Unmarshal(data, &result)
	if err != nil {
		log.Warn("Error reading users from group: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		//return err
	}
	log.Info("reading user list from groups")
	log.Info("Number of Users:", len(result.Groups))

	userCount := 0
	for i := range result.Groups {
		for j := range result.Groups[i].UserNames {
			var data ListTypes
			data.AccessType = "userFromGroups"
			var userData UserImport
			userData.Name = result.Groups[i].UserNames[j]
			userData.Email = result.Groups[i].UserNames[j] + UserEmailDomain
			userData.Password = "password"
			userData.ProfileUpdatable = true
			userData.Groups = []string{result.Groups[i].Name}
			data.UserIndex = userCount
			data.User = userData
			workQueue.PushBack(data)
			userCount++
		}
	}

	return nil
}

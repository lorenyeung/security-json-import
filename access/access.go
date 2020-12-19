package access

import (
	"container/list"
	"encoding/json"
	"errors"
	"io/ioutil"
	"security-json-import/auth"
	"security-json-import/helpers"
	"strconv"
	"strings"

	"github.com/Masterminds/semver"
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
	Groups                   []string `json:"groups,omitempty"`
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

type PermissionImport struct {
	Name            string                     `json:"name"`
	IncludePatterns []string                   `json:"include-patterns,omitempty"`
	ExcludePatterns []string                   `json:"exclude-patterns,omitempty"`
	Repositories    []string                   `json:"repositories"`
	Principals      PermissionPrincipalsImport `json:"principals,omitempty"`
}

type PermissionPrincipalsImport struct {
	Users  map[string][]string `json:"users,omitempty"`
	Groups map[string][]string `json:"groups,omitempty"`
}

type PermissionV2Import struct {
	Name  string                  `json:"name"`
	Repo  *PermissionDataV2Import `json:"repo,omitempty"`
	Build *PermissionDataV2Import `json:"build,omitempty"`
}

type PermissionDataV2Import struct {
	IncludePatterns []string                  `json:"include-patterns,omitempty"`
	ExcludePatterns []string                  `json:"exclude-patterns,omitempty"`
	Repositories    []string                  `json:"repositories"`
	Actions         PermissionV2ActionsImport `json:"actions,omitempty"`
}

type PermissionV2ActionsImport struct {
	Users  map[string][]string `json:"users,omitempty"`
	Groups map[string][]string `json:"groups,omitempty"`
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

type CreateUsersWithGroupsJSON struct {
	Users []CreateUsersWithGroupsDataJSON `json:"users"`
}

type CreateUsersWithGroupsDataJSON struct {
	Name                     string   `json:"name"`
	Email                    string   `json:"email"`
	Admin                    bool     `json:"admin"`
	ProfileUpdatable         bool     `json:"profileUpdatable"`
	DisableUIAccess          bool     `json:"disableUIAccess"`
	InternalPasswordDisabled bool     `json:"internalPasswordDisabled"`
	Groups                   []string `json:"groups,omitempty"`
	OfflineMode              bool     `json:"offlineMode"`
}

type ListTypes struct {
	AccessType      string
	Group           GroupImport
	Permission      PermissionImport
	PermissionV2    PermissionV2Import
	User            UserImport
	GroupIndex      int
	PermissionIndex int
	UserIndex       int
	Name            string
}
type ArtifactoryVersion struct {
	Version  string   `json:"version"`
	Revision string   `json:"revision"`
	Addons   []string `json:"addons"`
	License  string   `json:"license"`
}

type ArtifactoryError struct {
	Errors []ArtifactoryErrorDetail `json:"errors"`
}

type ArtifactoryErrorDetail struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func ReadSecurityJSON(workQueue *list.List, flags helpers.Flags) error {

	//get art version
	var artVer ArtifactoryVersion
	data, _, _, getErr := auth.GetRestAPI("GET", true, flags.URLVar+"/api/system/version", flags.UsernameVar, flags.ApikeyVar, "", nil, nil, 0, flags, nil)
	if getErr != nil {
		return getErr
	}
	err := json.Unmarshal(data, &artVer)
	if err != nil {
		return err
	}

	//TODO: this reads whole file into memory, be wary of OOM
	log.Info("reading security json")
	data, err = ioutil.ReadFile(flags.SecurityJSONFileVar)
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
		data2, err := ioutil.ReadFile(flags.UserGroupAssocationFileVar)
		if err != nil {
			log.Error("Error reading groups with users list json: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
			return errors.New("Error reading groups with users list json: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		}
		if flags.UsersFromGroupsVar {
			//check if art > 6.13.0 or not
			c, err := semver.NewConstraint(">= 6.13.0")
			if err != nil {
				return err
			}
			v, err := semver.NewVersion(artVer.Version)
			if err != nil {
				return err
			}
			a := c.Check(v)
			if !a {
				log.Warn("The source must be atleast 6.13.0 to get Users from Groups. You're importing into ", artVer.Version, " which does not match this. Proceed with caution")
			}
			CreateUsersFromGroups(workQueue, data2, flags.UserEmailDomainVar)
		} else if flags.UsersWithGroupsVar {
			CreateUsersWithGroups(workQueue, data2)
		}
	}

	//permission targets
	if !flags.SkipPermissionImportVar {

		c, err := semver.NewConstraint(">= 6.6.0")
		if err != nil {
			return err
		}
		v, err := semver.NewVersion(artVer.Version)
		if err != nil {
			return err
		}
		a := c.Check(v)
		if !a {
			log.Info(artVer.Version, " detected, using v1")
			ReadPermissionAcls(workQueue, data)
		} else {
			log.Info(artVer.Version, " detected, using v2")
			length, _ := ReadRepoPermissionV2Acls(workQueue, data)
			ReadBuildPermissionV2Acls(workQueue, data, length)
		}
	}
	var endTask ListTypes
	endTask.AccessType = "end"
	workQueue.PushBack(endTask)
	return nil
}

func ReadGroups(workQueue *list.List, data []byte) error {
	var result Groups
	err := json.Unmarshal(data, &result)
	if err != nil {
		log.Error("Error reading groups: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		return err
	}
	log.Info("Reading groups")
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
		data.Name = result.Groups[i].GroupName
		data.Group = groupData
		workQueue.PushBack(data)
	}
	return nil
}

func ReadPermissionAcls(workQueue *list.List, data []byte) error {
	var repoPermissionData RepoPermissions
	err := json.Unmarshal(data, &repoPermissionData)
	if err != nil {
		log.Error("Error reading repo permissions: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		return err
	}
	log.Info("Number of repo permissions:", len(repoPermissionData.RepoAcls))
	CreatePermissionQueueObject(workQueue, repoPermissionData.RepoAcls)
	return nil
}

func ReadRepoPermissionV2Acls(workQueue *list.List, data []byte) (int, error) {
	var repoPermissionData RepoPermissions
	err := json.Unmarshal(data, &repoPermissionData)
	if err != nil {
		log.Error("Error reading repo permissions v2: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		return 0, err
	}
	log.Info("Number of repo permissions v2:", len(repoPermissionData.RepoAcls))
	CreatePermissionV2QueueObject(workQueue, repoPermissionData.RepoAcls, "repository", 0)
	return len(repoPermissionData.RepoAcls), nil
}

func ReadBuildPermissionV2Acls(workQueue *list.List, data []byte, length int) error {
	var result BuildPermissions
	err := json.Unmarshal(data, &result)
	if err != nil {
		log.Error("Error reading build permissions v2: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		return err
	}
	log.Info("Number of build permissions v2:", len(result.BuildAcls))
	//need to check if permission target already exists, and if so ammend to it.
	CreatePermissionV2QueueObject(workQueue, result.BuildAcls, "build", length)
	return nil
}

func CreatePermissionQueueObject(workQueue *list.List, acls []PermissionsAcls) error {
	for i := range acls {
		var permissionImport PermissionImport
		var data ListTypes
		data.AccessType = "permission"
		//noSpaceName := strings.ReplaceAll(acls[i].PermissionTarget.Name, " ", "%20")
		permissionImport.IncludePatterns = acls[i].PermissionTarget.Includes
		permissionImport.ExcludePatterns = acls[i].PermissionTarget.Excludes
		permissionImport.Repositories = acls[i].PermissionTarget.RepoKeys
		permissionImport.Name = acls[i].PermissionTarget.Name
		//need check for "" repo list, ANY *
		for j := range acls[i].Aces {
			//TODO verify that aces and mutableAces are the same
			if acls[i].Aces[j].Group {
				if permissionImport.Principals.Groups == nil {
					permissionImport.Principals.Groups = make(map[string][]string)
				}
				permissionImport.Principals.Groups[acls[i].Aces[j].Principal] = acls[i].Aces[j].PermissionsAsString
			} else {
				if permissionImport.Principals.Users == nil {
					permissionImport.Principals.Users = make(map[string][]string)
				}
				permissionImport.Principals.Users[acls[i].Aces[j].Principal] = acls[i].Aces[j].PermissionsAsString
			}
		}
		data.PermissionIndex = i
		data.Name = acls[i].PermissionTarget.Name

		data.Permission = permissionImport
		workQueue.PushBack(data)
	}
	return nil
}

func CreatePermissionV2QueueObject(workQueue *list.List, acls []PermissionsAcls, PermissionType string, length int) error {

	for i := range acls {
		//check if v2 if > 6.6?
		var permissionImport PermissionV2Import
		var permissionData PermissionDataV2Import
		var data ListTypes
		data.AccessType = "permissionV2"
		noSpaceName := strings.ReplaceAll(acls[i].PermissionTarget.Name, " ", "%20")
		permissionImport.Name = acls[i].PermissionTarget.Name
		if PermissionType == "repository" {
			if permissionImport.Repo == nil {
				permissionImport.Repo = &PermissionDataV2Import{}
			}
		}
		if PermissionType == "build" {
			if permissionImport.Build == nil {
				permissionImport.Build = &PermissionDataV2Import{}
			}
		}

		permissionData.IncludePatterns = acls[i].PermissionTarget.Includes
		permissionData.ExcludePatterns = acls[i].PermissionTarget.Excludes
		permissionData.Repositories = acls[i].PermissionTarget.RepoKeys
		//need check for "" repo list, ANY *
		for j := range acls[i].Aces {
			//TODO verify that aces and mutableAces are the same
			if acls[i].Aces[j].Group {
				if permissionData.Actions.Groups == nil {
					permissionData.Actions.Groups = make(map[string][]string)
				}
				permissionData.Actions.Groups[acls[i].Aces[j].Principal] = acls[i].Aces[j].PermissionsDisplayNames
			} else {
				if permissionData.Actions.Users == nil {
					permissionData.Actions.Users = make(map[string][]string)
				}
				permissionData.Actions.Users[acls[i].Aces[j].Principal] = acls[i].Aces[j].PermissionsDisplayNames
			}
		}
		data.PermissionIndex = i + length
		data.Name = noSpaceName
		if PermissionType == "repository" {
			permissionImport.Repo = &permissionData
		}
		if PermissionType == "build" {
			permissionImport.Build = &permissionData
		}

		data.PermissionV2 = permissionImport
		workQueue.PushBack(data)
	}
	return nil
}

func CreateUsersFromGroups(workQueue *list.List, data []byte, UserEmailDomain string) error {
	var result CreateUsersFromGroupsJSON
	err := json.Unmarshal(data, &result)
	if err != nil {
		log.Warn("Error reading users from group: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
	}
	log.Info("Number of users from groups list:", len(result.Groups))

	userCount := 0
	for i := range result.Groups {
		for j := range result.Groups[i].UserNames {
			var data ListTypes
			data.AccessType = "user"
			var userData UserImport
			userData.Name = result.Groups[i].UserNames[j]
			if strings.Contains(userData.Name, "@") {
				userData.Email = result.Groups[i].UserNames[j]
			} else {
				userData.Email = result.Groups[i].UserNames[j] + UserEmailDomain
			}
			userData.Password = "password"
			userData.ProfileUpdatable = true
			userData.Groups = []string{result.Groups[i].Name}
			data.UserIndex = userCount
			data.Name = result.Groups[i].UserNames[j]
			data.User = userData
			workQueue.PushBack(data)
			userCount++
		}
	}
	return nil
}

func CreateUsersWithGroups(workQueue *list.List, data []byte) error {
	var result CreateUsersWithGroupsJSON
	err := json.Unmarshal(data, &result)
	if err != nil {
		log.Warn("Error reading users with groups: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
	}
	log.Info("Number of users:", len(result.Users))

	for i := range result.Users {
		var data ListTypes
		data.AccessType = "user"
		var userData UserImport
		userData.Name = result.Users[i].Name
		userData.Email = result.Users[i].Email
		userData.Password = "password"
		userData.ProfileUpdatable = true
		userData.Groups = result.Users[i].Groups
		userData.DisableUIAccess = result.Users[i].DisableUIAccess
		userData.Admin = result.Users[i].Admin
		userData.InternalPasswordDisabled = result.Users[i].InternalPasswordDisabled
		userData.ProfileUpdatable = result.Users[i].ProfileUpdatable
		data.UserIndex = i
		data.Name = result.Users[i].Name
		data.User = userData
		workQueue.PushBack(data)
	}
	return nil
}

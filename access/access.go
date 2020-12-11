package access

import (
	"container/list"
	"encoding/json"
	"errors"
	"io/ioutil"
	"security-json-import/helpers"
	"strconv"

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
	Name            string `json:"name"`
	Description     string `json:"description"`
	AutoJoin        string `json:"autoJoin"`
	Realm           string `json:"realm"`
	AdminPrivileges string `json:"adminPrivileges"`
}

type RepoPermissions struct {
	RepoAcls []RepoPermissionsAcls `json:"repoAcls"`
}

type RepoPermissionsAcls struct {
	Aces             []RepoPermissionsAces `json:"aces"`
	MutableAces      []RepoPermissionsAces `json:"mutableAces"`
	UpdatedBy        string                `json:"updatedBy"`
	AccessIdentifier string                `json:"accessIdentifier"`
	PermissionTarget struct {
		Name            string   `json:"name"`
		Includes        []string `json:"includes"`
		Excludes        []string `json:"excludes"`
		RepoKeys        []string `json:"repoKeys"`
		IncludesPattern string   `json:"includesPattern"`
		ExcludesPattern string   `json:"excludesPattern"`
	} `json:"permissionTarget"`
}
type RepoPermissionsAces struct {
	Principal               string   `json:"principal"`
	Group                   bool     `json:"group"`
	Mask                    int      `json:"mask"`
	PermissionsAsString     []string `json:"permissionsAsString"`
	PermissionsDisplayNames []string `json:"permissionsDisplayNames"`
	PermissionsUiNames      []string `json:"permissionsUiNames"`
}

type RepoPermissionImport struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	AutoJoin        string `json:"autoJoin"`
	Realm           string `json:"realm"`
	AdminPrivileges string `json:"adminPrivileges"`
}

type BuildPermissions struct {
	BuildAcls []BuildPermissionsAcls `json:"buildAcls"`
}

type BuildPermissionsAcls struct {
	Aces             []BuildPermissionsAces `json:"aces"`
	MutableAces      []BuildPermissionsAces `json:"mutableAces"`
	UpdatedBy        string                 `json:"updatedBy"`
	AccessIdentifier string                 `json:"accessIdentifier"`
	PermissionTarget struct {
		Name            string   `json:"name"`
		Includes        []string `json:"includes"`
		Excludes        []string `json:"excludes"`
		RepoKeys        []string `json:"repoKeys"`
		IncludesPattern string   `json:"includesPattern"`
		ExcludesPattern string   `json:"excludesPattern"`
	} `json:"permissionTarget"`
}
type BuildPermissionsAces struct {
	Principal               string   `json:"principal"`
	Group                   bool     `json:"group"`
	Mask                    int      `json:"mask"`
	PermissionsAsString     []string `json:"permissionsAsString"`
	PermissionsDisplayNames []string `json:"permissionsDisplayNames"`
	PermissionsUiNames      []string `json:"permissionsUiNames"`
}

type BuildPermissionImport struct {
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
	RepoPermission       RepoPermissionImport
	BuildPermission      BuildPermissionImport
	AccessType           string
	groupIndex           string
	repoPermissionIndex  string
	buildPermissionIndex string
	userIndex            string
}

func ReadSecurityJSON(workQueue *list.List, securityJSONPath string, groupsWithUsersListJSONPath string, groupsWithUsersList bool) error {

	//TODO: this reads whole file into memory, be wary of OOM
	log.Info("reading security json")
	data, err := ioutil.ReadFile(securityJSONPath)
	if err != nil {
		log.Error("Error reading security json" + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		return errors.New("Error reading security json" + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
	}
	ReadGroups(workQueue, data)
	ReadRepoPermissionAcls(data)
	ReadBuildPermissionAcls(data)

	if groupsWithUsersList {
		data2, err := ioutil.ReadFile(groupsWithUsersListJSONPath)
		if err != nil {
			log.Error("Error reading groups with users list json: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
			return errors.New("Error reading groups with users list json: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		}
		CreateUsersFromGroups(data2)
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
		data.Group = groupData
		workQueue.PushBack(data)
	}

	//curl localhost:8081/artifactory/api/security/groups/$name -XPUT -H "content-type: application/json" -u admin:password
	//-d '{"name":"'$name'","description":"'$description'","autoJoin":'$newUserDefault',"realm":"'$realm'","adminPrivileges":'$adminPrivileges'}'
	return nil
}

func ReadRepoPermissionAcls(data []byte) error {
	var result RepoPermissions
	err := json.Unmarshal(data, &result)
	if err != nil {
		log.Error("Error reading repo permissions: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		return err
	}
	log.Info("reading repo permissions")
	log.Info("Number of Aces:", len(result.RepoAcls))

	// for i := range result.RepoAcls {
	// 	fmt.Println(result.RepoAcls[i].PermissionTarget.Name)
	// }
	return nil
}

func ReadBuildPermissionAcls(data []byte) error {
	var result BuildPermissions
	err := json.Unmarshal(data, &result)
	if err != nil {
		log.Error("Error reading build permissions: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		return err
	}
	log.Info("reading repo permissions")
	log.Info("Number of Aces:", len(result.BuildAcls))
	return nil
}

func CreateUsersFromGroups(data []byte) error {
	var result CreateUsersFromGroupsJSON
	err := json.Unmarshal(data, &result)
	if err != nil {
		log.Warn("Error reading users from group: " + err.Error() + " " + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
		//return err
	}
	log.Info("reading user list from groups")
	log.Info("Number of Users:", len(result.Groups))
	return nil
}

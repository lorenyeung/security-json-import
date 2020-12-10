package access

import (
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
	NewUserDefault  string `json:"newUserDefault"`
	Realm           string `json:"realm"`
	AdminPrivileges string `json:"adminPrivileges"`
	External        string `json:"external"`
}
type GroupImport struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	AutoJoin        string `json:"autoJoin"`
	Realm           string `json:"realm"`
	AdminPrivileges string `json:"adminPrivileges"`
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
	PermissionsUiNames      string   `json:"permissionsUiNames"`
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
	PermissionsUiNames      string   `json:"permissionsUiNames"`
}

type BuildPermissionImport struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	AutoJoin        string `json:"autoJoin"`
	Realm           string `json:"realm"`
	AdminPrivileges string `json:"adminPrivileges"`
}

type ListTypes struct {
	Group           GroupImport
	User            UserImport
	RepoPermission  RepoPermissionImport
	BuildPermission BuildPermissionImport
	accessType      string
}

func ReadSecurityJSON(path string) error {

	//TODO: this reads whole file into memory, be wary of OOM
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return errors.New("Error reading security json" + err.Error() + helpers.Trace().Fn + ":" + strconv.Itoa(helpers.Trace().Line))
	}
	ReadGroups(data)
	ReadRepoPermissionAcls(data)
	ReadBuildPermissionAcls(data)

	return nil
}

func ReadGroups(data []byte) {
	var result Groups
	json.Unmarshal(data, &result)
	log.Info("reading groups")
	log.Info("Number of groups:", len(result.Groups))

	// for i := range result.Groups {
	// 	fmt.Println(result.Groups[i].GroupName)
	// }

	//curl localhost:8081/artifactory/api/security/groups/$name -XPUT -H "content-type: application/json" -u admin:password
	//-d '{"name":"'$name'","description":"'$description'","autoJoin":'$newUserDefault',"realm":"'$realm'","adminPrivileges":'$adminPrivileges'}'
}

func ReadRepoPermissionAcls(data []byte) {
	var result RepoPermissions
	json.Unmarshal(data, &result)
	log.Info("reading repo permissions")
	log.Info("Number of Aces:", len(result.RepoAcls))

	// for i := range result.RepoAcls {
	// 	fmt.Println(result.RepoAcls[i].PermissionTarget.Name)
	// }
}

func ReadBuildPermissionAcls(data []byte) {
	var result BuildPermissions
	json.Unmarshal(data, &result)
	log.Info("reading repo permissions")
	log.Info("Number of Aces:", len(result.BuildAcls))

}

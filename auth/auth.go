package auth

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go-pkgdl/helpers"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"golang.org/x/crypto/ssh/terminal"
)

//Creds struct for creating download.json
type Creds struct {
	URL        string
	Username   string
	Apikey     string
	DlLocation string
}

//StorageDataJSON storage summary JSON
type StorageDataJSON struct {
	StorageSummary struct {
		FileStoreSummary struct {
			UsedSpace string `json:"usedSpace"`
			FreeSpace string `json:"freeSpace"`
		} `json:"fileStoreSummary"`
		RepositoriesSummaryList []struct {
			RepoKey string `json:"repoKey"`
		} `json: "repositoriesSummaryList"`
	} `json:"storageSummary"`
}

// VerifyAPIKey for errors
func VerifyAPIKey(urlInput, userName, apiKey string) bool {
	log.Debug("starting VerifyAPIkey request. Testing:", userName)
	//TODO need to sanitize invalid url strings, esp in custom flag
	data, _, _ := GetRestAPI("GET", true, urlInput+"/api/system/ping", userName, apiKey, "", nil, nil, 1)
	if string(data) == "OK" {
		log.Debug("finished VerifyAPIkey request. Credentials are good to go.")
		return true
	}
	log.Warn("Received unexpected response:", string(data), " against ", urlInput+"/api/system/ping. Double check your URL and credentials.")
	return false
}

// GenerateDownloadJSON (re)generate download JSON. Tested.
func GenerateDownloadJSON(configPath string, regen bool, masterKey string) Creds {
	var creds Creds
	if regen {
		creds = GetDownloadJSON(configPath, masterKey)
	}
	var urlInput, userName, apiKey string
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Enter your url [%s]: ", creds.URL)
		urlInput, _ = reader.ReadString('\n')
		urlInput = strings.TrimSuffix(urlInput, "\n")
		if urlInput == "" {
			urlInput = creds.URL
		}
		if !strings.HasPrefix(urlInput, "http") {
			fmt.Println("Please enter a HTTP(s) protocol")
			continue
		}
		if strings.HasSuffix(urlInput, "/") {
			log.Debug("stripping trailing /")
			urlInput = strings.TrimSuffix(urlInput, "/")
		}
		fmt.Printf("Enter your username [%s]: ", creds.Username)
		userName, _ = reader.ReadString('\n')
		userName = strings.TrimSuffix(userName, "\n")
		if userName == "" {
			userName = creds.Username
		}
		fmt.Print("Enter your API key/Password: ")
		apiKeyByte, _ := terminal.ReadPassword(0)
		apiKey = string(apiKeyByte)
		println()
		if VerifyAPIKey(urlInput, userName, apiKey) {
			break
		} else {
			fmt.Println("Something seems wrong, please try again.")
		}
	}
	dlLocationInput := configPath
	return writeFileDownloadJSON(configPath, urlInput, userName, apiKey, dlLocationInput, masterKey)
}

func writeFileDownloadJSON(configPath, urlInput, userName, apiKey, dlLocationInput, masterKey string) Creds {
	data := Creds{
		URL:        Encrypt(urlInput, masterKey),
		Username:   Encrypt(userName, masterKey),
		Apikey:     Encrypt(apiKey, masterKey),
		DlLocation: Encrypt(dlLocationInput, masterKey),
	}
	//should probably encrypt data here
	fileData, err := json.Marshal(data)
	helpers.Check(err, true, "The JSON marshal", helpers.Trace())
	err2 := ioutil.WriteFile(configPath, fileData, 0600)
	helpers.Check(err2, true, "The JSON write", helpers.Trace())

	data2 := Creds{
		URL:        urlInput,
		Username:   userName,
		Apikey:     apiKey,
		DlLocation: dlLocationInput,
	}

	return data2
}

//GetDownloadJSON get data from DownloadJSON
func GetDownloadJSON(fileLocation string, masterKey string) Creds {
	var result map[string]interface{}
	var resultData Creds
	file, err := os.Open(fileLocation)
	if err != nil {
		log.Error("error:", err)
		resultData = GenerateDownloadJSON(fileLocation, false, masterKey)
	} else {
		//should decrypt here
		defer file.Close()
		byteValue, _ := ioutil.ReadAll(file)
		json.Unmarshal([]byte(byteValue), &result)
		resultData.URL = Decrypt(result["URL"].(string), masterKey)
		resultData.Username = Decrypt(result["Username"].(string), masterKey)
		resultData.Apikey = Decrypt(result["Apikey"].(string), masterKey)
		resultData.DlLocation = Decrypt(result["DlLocation"].(string), masterKey)
	}
	return resultData
}

//
func StorageCheck(creds Creds, warning float64, threshold float64) {
	data, statusCode, _ := GetRestAPI("GET", true, creds.URL+"/api/storageinfo", creds.Username, creds.Apikey, "", nil, nil, 1)
	if statusCode != 200 {
		log.Warn("Received bad status code ", statusCode, " trying to get storage info. Proceed with caution")
		return
	}
	//may need to trigger async calculation for newer versions
	log.Debug("Triggering async POST to update summary page")
	GetRestAPI("POST", true, creds.URL+"/api/storageinfo/calculate", creds.Username, creds.Apikey, "", nil, nil, 1)

	var storageData StorageDataJSON
	err := json.Unmarshal(data, &storageData)
	helpers.Check(err, false, "check failed", helpers.Trace())
	log.Debug("free:", storageData.StorageSummary.FileStoreSummary.FreeSpace, " used:", storageData.StorageSummary.FileStoreSummary.UsedSpace)
	used := strings.Split(storageData.StorageSummary.FileStoreSummary.UsedSpace, "(")
	log.Debug("useage results:", used)
	if len(used) > 2 {
		usedpc := strings.TrimRight(used[1], "%)")
		i, err := strconv.ParseFloat(usedpc, 32)
		if err != nil {
			log.Warn(err)
			return
		}
		if i >= threshold {
			log.Panic("Summary reporting that disk hit threshold ", warning, "% usage, (", used[1], " killing all downloads")
			os.Exit(1)

		} else if i >= warning {
			log.Warn("Summary reporting that disk is over warning ", warning, "% usage, (", used[1], " proceed with caution")
		}
	} else {
		log.Warn("storage check returned:", used)
	}

}

//GetRestAPI GET rest APIs response with error handling
func GetRestAPI(method string, auth bool, urlInput, userName, apiKey, providedfilepath string, jsonBody []byte, header map[string]string, retry int) ([]byte, int, http.Header) {
	if retry > 5 {
		log.Warn("Exceeded retry limit, cancelling further attempts")
		return nil, 0, nil
	}

	body := new(bytes.Buffer)
	//PUT upload file
	if method == "PUT" && providedfilepath != "" {
		//req.Header.Set()
		file, err := os.Open(providedfilepath)
		helpers.Check(err, false, "open", helpers.Trace())
		defer file.Close()

		writer := multipart.NewWriter(body)

		part, err := writer.CreateFormFile("file", filepath.Base(providedfilepath))
		helpers.Check(err, false, "create", helpers.Trace())
		io.Copy(part, file)
		err = writer.Close()
		helpers.Check(err, false, "writer close", helpers.Trace())
	} else if method == "PUT" && jsonBody != nil {
		body = bytes.NewBuffer(jsonBody)
	}

	client := http.Client{}
	req, err := http.NewRequest(method, urlInput, body)
	if auth {
		req.SetBasicAuth(userName, apiKey)
	}
	for x, y := range header {
		log.Debug("Recieved extra header:", x+":"+y)
		req.Header.Set(x, y)
	}

	if err != nil {
		log.Warn("The HTTP request failed with error", err)
	} else {

		resp, err := client.Do(req)
		helpers.Check(err, false, "The HTTP response", helpers.Trace())

		if err != nil {
			return nil, 0, nil
		}
		// need to account for 403s with xray, or other 403s, 429? 204 is bad too (no content for docker)
		switch resp.StatusCode {
		case 200:
			log.Debug("Received ", resp.StatusCode, " OK on ", method, " request for ", urlInput, " continuing")
		case 201:
			if method == "PUT" {
				log.Debug("Received ", resp.StatusCode, " ", method, " request for ", urlInput, " continuing")
			}
		case 403:
			log.Error("Received ", resp.StatusCode, " Forbidden on ", method, " request for ", urlInput, " continuing")
			// should we try retry here? probably not
		case 404:
			log.Debug("Received ", resp.StatusCode, " Not Found on ", method, " request for ", urlInput, " continuing")
		case 429:
			log.Error("Received ", resp.StatusCode, " Too Many Requests on ", method, " request for ", urlInput, ", sleeping then retrying, attempt ", retry)
			time.Sleep(10 * time.Second)
			GetRestAPI(method, auth, urlInput, userName, apiKey, providedfilepath, jsonBody, header, retry+1)
		case 204:
			if method == "GET" {
				log.Error("Received ", resp.StatusCode, " No Content on ", method, " request for ", urlInput, ", sleeping then retrying")
				time.Sleep(10 * time.Second)
				GetRestAPI(method, auth, urlInput, userName, apiKey, providedfilepath, jsonBody, header, retry+1)
			} else {
				log.Debug("Received ", resp.StatusCode, " OK on ", method, " request for ", urlInput, " continuing")
			}
		case 500:
			log.Error("Received ", resp.StatusCode, " Internal Server error on ", method, " request for ", urlInput, " failing out")
			return nil, 0, nil
		default:
			log.Warn("Received ", resp.StatusCode, " on ", method, " request for ", urlInput, " continuing")
		}
		//Mostly for HEAD requests
		statusCode := resp.StatusCode
		headers := resp.Header

		if providedfilepath != "" && method == "GET" {
			// Create the file
			out, err := os.Create(providedfilepath)
			helpers.Check(err, false, "File create:"+providedfilepath, helpers.Trace())
			defer out.Close()

			//done := make(chan int64)
			//go helpers.PrintDownloadPercent(done, filepath, int64(resp.ContentLength))
			_, err = io.Copy(out, resp.Body)
			helpers.Check(err, false, "The file copy:"+providedfilepath, helpers.Trace())
		} else {
			//maybe skip the download or retry if error here, like EOF
			data, err := ioutil.ReadAll(resp.Body)
			helpers.Check(err, false, "Data read:"+urlInput, helpers.Trace())
			if err != nil {
				log.Warn("Data Read on ", urlInput, " failed with:", err, ", sleeping then retrying, attempt:", retry)
				time.Sleep(10 * time.Second)

				GetRestAPI(method, auth, urlInput, userName, apiKey, providedfilepath, jsonBody, header, retry+1)
			}

			return data, statusCode, headers
		}
	}
	return nil, 0, nil
}

//CreateHash self explanatory
func CreateHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

//Encrypt self explanatory
func Encrypt(dataString string, passphrase string) string {
	data := []byte(dataString)
	block, _ := aes.NewCipher([]byte(CreateHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	helpers.Check(err, true, "Cipher", helpers.Trace())
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.RawURLEncoding.EncodeToString([]byte(ciphertext))
}

//Decrypt self explanatory
func Decrypt(dataString string, passphrase string) string {
	data, _ := base64.RawURLEncoding.DecodeString(dataString)

	key := []byte(CreateHash(passphrase))
	block, err := aes.NewCipher(key)
	helpers.Check(err, true, "Cipher", helpers.Trace())
	gcm, err := cipher.NewGCM(block)
	helpers.Check(err, true, "Cipher GCM", helpers.Trace())
	// TODO if decrypt failure
	//	if err != nil {
	// 	GenerateDownloadJSON(fileLocation, false, passphrase)
	// }
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	helpers.Check(err, true, "GCM open", helpers.Trace())
	return string(plaintext)
}

//VerifyMasterKey self explanatory
func VerifyMasterKey(configPath string) string {
	_, err := os.Open(configPath)
	var token string
	if err != nil {
		log.Warn("Finding master key failed with error %s\n", err)
		data, err := generateRandomBytes(32)
		helpers.Check(err, true, "Generating new master key", helpers.Trace())
		err2 := ioutil.WriteFile(configPath, []byte(base64.URLEncoding.EncodeToString(data)), 0600)
		helpers.Check(err2, true, "Master key write", helpers.Trace())
		log.Info("Successfully generated master key")
		token = base64.URLEncoding.EncodeToString(data)
	} else {
		dat, err := ioutil.ReadFile(configPath)
		helpers.Check(err, true, "Reading master key", helpers.Trace())
		token = string(dat)
	}
	return token
}

func generateRandomString(s int) (string, error) {
	b, err := generateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}
	return b, nil
}

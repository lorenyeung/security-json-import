package auth

import (
	"bytes"
	"go-pkgdl/helpers"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

//Creds struct for creating download.json
type Creds struct {
	URL      string
	Username string
	Apikey   string
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

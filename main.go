package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var mapHashes map[string]map[int]string = make(map[string]map[int]string)

var transport *http.Transport = &http.Transport{
	MaxIdleConnsPerHost: 10,
}

type ResponseStruct struct {
	Code string `json:"code"`
	Message string `json:"message"`
	Status int `json:"status"`
}

func writeResponse(res http.ResponseWriter, status int, code, message string) {
	jsonResp := &ResponseStruct{
		Status: status,
		Code: code,
		Message: message,
	}

	out, err := json.Marshal(jsonResp)
	if err != nil {
		res.WriteHeader(500)
		res.Write([]byte("{'status':500, 'code': 'bad json marshaling', message: '" + err.Error() + "'"))
		return
	}

	res.WriteHeader(status)
	res.Write(out)
}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out: os.Stdout,
		NoColor: false,
		TimeFormat: time.RFC3339,
	})

	authStruct, err := b2Auth(os.Getenv("B2_ACCESS_KEY"), os.Getenv("B2_SECRET_KEY"))
	if err != nil {
		log.Fatal().Err(err).Msg("authorization error")
	}

	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		reqLog := log.With().
			Str("remote_ip", req.RemoteAddr).
			Str("host", req.Host).
			Str("method", req.Method).
			Str("path", req.URL.Path).
			Str("user_agent", req.UserAgent()).
			Interface("headers", req.Header).
			Logger()

		defer req.Body.Close()

		switch req.Method {
		case "PUT":
			incomingPart, err := ioutil.ReadAll(req.Body)
			if err != nil {
				reqLog.Error().Err(err).Msg("writing bad_request_body error")
				writeResponse(res, 500, "bad_request_body", err.Error())
				return
			}

			if len(incomingPart) == 0 {
				if req.URL.Query().Get("uploadId") != "" && req.URL.Query().Get("partNumber") != "" {
					partN, err := strconv.Atoi(req.URL.Query().Get("partNumber"))
					if err != nil {
						reqLog.Error().Err(err).Msg("writing number_conversion_err")
						writeResponse(res, 500, "number_conversion_err", err.Error())
						return
					}

					if _, ok := mapHashes[req.URL.Query().Get("uploadId")]; ok {
						if _, alsoOk := mapHashes[req.URL.Query().Get("uploadId")][partN]; alsoOk {
							res.WriteHeader(200)
							res.Write([]byte{})
							return
						}
					}
				}

				res.WriteHeader(404)
				res.Write([]byte{})
				return

			} else {
				if req.URL.Query().Get("uploadId") != "" && req.URL.Query().Get("partNumber") != "" {
					partInt, err := strconv.Atoi(req.URL.Query().Get("partNumber"))
					if err != nil {
						reqLog.Error().Err(err).Msg("writing number_conversion_err")
						writeResponse(res, 500, "number_conversion_err", err.Error())
						return
					}

					code, err := b2UploadPart(authStruct, req.URL.Query().Get("uploadId"), partInt, req.Body, req.Header.Get("Content-Length"), req.Header.Get("Content-Type"))
					if err != nil {
						reqLog.Error().Err(err).Msg("writing upload_part_error")
						writeResponse(res, code, "upload_part_error", err.Error())
						return
					}

				} else {
					code, err := b2Upload(authStruct, req.RequestURI, req.Body, req.Header.Get("Content-Length"), req.Header.Get("Content-Type"))
					if err != nil {
						reqLog.Error().Err(err).Msg("writing upload_error")
						writeResponse(res, code, "upload_error", err.Error())
						return
					}
				}
			}

			res.WriteHeader(200)
			res.Write([]byte{})

		case "POST":
			if req.URL.Query().Get("uploads") != "" {
				code, resp, err := b2StartLargeUpload(authStruct, req.RequestURI)
				if err != nil {
					writeResponse(res, code, "start_large_upload_error", err.Error())
					return
				}

				if code == 200 {
					out, err := xml.Marshal(struct {
						XMLName xml.Name `xml:"InitiateMultipartUploadResult"`
						Xmlns string `xml:"xmlns,attr"`
						UploadId string `xml:"UploadId"`
					}{
						Xmlns: "https://s3.amazonaws.com/doc/2006-03-1/",
						UploadId: resp.FileId,
					})
					if err != nil {
						reqLog.Error().Err(err).Msg("writing xml_marshal_error (start_large_upload)")
						writeResponse(res, 500, "xml_marshal_error", err.Error())
					} else {
						res.WriteHeader(code)
						res.Write(out)
					}

				} else {
					reqLog.Error().Err(err).Msg("writing unexpected_code")
					writeResponse(res, code, "unexpected_code", "")
				}
			} else {
				code, err := b2FinishLargeFile(authStruct, req.URL.Query().Get("uploadId"))
				if err != nil {
					reqLog.Error().Err(err).Msg("writing finish_large_file_error")
					writeResponse(res, code, "finish_large_file_error", err.Error())
					return
				}

				out, err := xml.Marshal(struct {
					XMLName xml.Name `xml:"CompleteMultipartUploadResult"`
					Xmlns string `xml:"xmlns,attr"`
					Location string `xml:"Location"`
				}{
					Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
					Location: "",
				})
				if err != nil {
					reqLog.Error().Err(err).Msg("writing xml_marshal_error (finish_large_file)")
					writeResponse(res, 500, "xml_marshal_error", err.Error())
				} else {
					res.WriteHeader(code)
					res.Write(out)
				}
			}

		case "DELETE":
			code, err := b2Delete(authStruct, req.RequestURI)
			if err != nil {
				reqLog.Error().Err(err).Msg("writing delete_error")
				writeResponse(res, code, "delete_error", err.Error())
				return
			}

			res.WriteHeader(200)
			res.Write([]byte{})

		case "HEAD":
			res.WriteHeader(200)
			res.Write([]byte{})
		}
	})

	bind := os.Getenv("B2_BIND")
	if bind == "" {
		bind = ":9000"
	}

	log.Info().Msgf("listening on: %s", bind)

	if err := http.ListenAndServe(bind, nil); err != nil {
		log.Error().Err(err).Msg("http server shutting down")
	}
}

func b2ApiCall(auth, method, url string, bodyJson []byte) (*http.Response, error) {
	var req *http.Request
	var err error

	if bodyJson != nil {
		req, err = http.NewRequest(method, url, bytes.NewBuffer(bodyJson))
		if err != nil {
			return nil, err
		}
	} else {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			return nil, err
		}
	}

	req.Header.Set("Authorization", auth)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: transport,
	}

	res, err := client.Do(req)

	if err != nil {
		return nil, err
	} else {
		return res, nil
	}
}

type B2AuthorizeAccountJSON struct {
	AbsoluteMinimumPartSize int `json:"absoluteMinimumPartSize"`
	AccountId string `json:"accountId"`
	Allowed struct {
		BucketId string `json:"bucketId"`
		BucketName string `json:"bucketName"`
		Capabilities []string `json:"capabilities"`
		NamePrefix string `json:"namePrefix"`
	} `json:"allowed"`
	ApiUrl string `json:"apiUrl"`
	AuthorizationToken string `json:"authorizationToken"`
	DownloadUrl string `json:"downloadUrl"`
	RecommendedPartSize int `json:"recommendedPartSize"`

	Code string `json:"code"`
	Message string `json:"message"`
	Status int `json:"status"`
}

func b2Auth(id, key string) (*B2AuthorizeAccountJSON, error) {
	authToken := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", id, key)))
	res, err := b2ApiCall("Basic " + authToken, "GET", "https://api.backblazeb2.com/b2api/v2/b2_authorize_account", nil)
	if err != nil {
		return nil, err
	}

	var result *B2AuthorizeAccountJSON

	if err := json.NewDecoder(res.Body).Decode(&result); err == nil || err == io.EOF {
		if result.Code != "" {
			return nil, errors.New(fmt.Sprintf("error code %s: %s", result.Code, result.Message))
		}

		return result, nil
	} else {
		return nil, err
	}
}

type B2HideFileJSON struct {
	AccountId string `json:"accountId"`
	Action string `json:"action"`
	BucketId string `json:"bucketId"`
	ContentLength int `json:"contentLength"`
	ContentSha1 string `json:"contentSha1"`
	ContentType string `json:"contentType"`
	FileId string `json:"fileId"`
	FileInfo map[string]interface{} `json:"fileInfo"`
	FileName string `json:"fileName"`
	Size int `json:"size"`
	UploadTimestamp int `json:"uploadTimestamp"`

	Code string `json:"code"`
	Message string `json:"message"`
	Status int `json:"status"`
}

func b2HideFile(authJson *B2AuthorizeAccountJSON, path string) (int, *B2HideFileJSON, error) {
	postMap := map[string]interface{}{
		"bucketId": authJson.Allowed.BucketId,
		"fileName": strings.Replace(path, "/" + authJson.Allowed.BucketName + "/", "", 1),
	}

	postBody, err := json.Marshal(postMap)
	if err != nil {
		return 500, nil, err
	}

	res, err := b2ApiCall(authJson.AuthorizationToken, "POST", fmt.Sprintf("%s/b2api/v2/b2_hide_file", authJson.ApiUrl), postBody)
	if err != nil {
		return 500, nil, err
	}

	var result *B2HideFileJSON

	if err := json.NewDecoder(res.Body).Decode(&result); err == nil || err == io.EOF {
		if result.Code != "" || result.Message != "" {
			return result.Status, nil, errors.New(fmt.Sprintf("error code %s: %s", result.Code, result.Message))
		}

		return res.StatusCode, result, nil
	} else {
		return 500, nil, err
	}
}

func b2Delete(authJson *B2AuthorizeAccountJSON, path string) (int, error) {
	code, hideFileJson, err := b2HideFile(authJson, path)
	if err != nil {
		return 500, err
	}

	if code == 200 {
		postMap := map[string]interface{}{
			"fileName": hideFileJson.FileName,
			"fileId": hideFileJson.FileId,
		}

		postBody, err := json.Marshal(postMap)
		if err != nil {
			return 500, err
		}

		res, err := b2ApiCall(authJson.AuthorizationToken, "POST", fmt.Sprintf("%s/b2api/v2/b2_delete_file_version", authJson.ApiUrl), postBody)
		if err != nil {
			return 500, err
		}

		return res.StatusCode, nil
	} else {
		return code, nil
	}
}

type B2GetUploadUrlJSON struct {
	BucketId string `json:"bucketId"`
	UploadUrl string `json:"uploadUrl"`
	AuthorizationToken string `json:"authorizationToken"`

	Code string `json:"code"`
	Message string `json:"message"`
	Status int `json:"status"`
}

func b2GetUploadUrl(authJson *B2AuthorizeAccountJSON) (*B2GetUploadUrlJSON, error) {
	postMap := map[string]string {
		"bucketId": authJson.Allowed.BucketId,
	}

	postBody, err := json.Marshal(postMap)
	if err != nil {
		return nil, err
	}

	res, err := b2ApiCall(authJson.AuthorizationToken, "POST", fmt.Sprintf("%s/b2api/v2/b2_get_upload_url", authJson.ApiUrl), postBody)
	if err != nil {
		return nil, err
	}

	var result *B2GetUploadUrlJSON

	if err := json.NewDecoder(res.Body).Decode(&result); err == nil || err == io.EOF {
		if result.Code != "" || result.Message != "" {
			return nil, errors.New(fmt.Sprintf("error code %s: %s", result.Code, result.Message))
		}

		return result, nil
	} else {
		return nil, err
	}
}

func b2Upload(authJson *B2AuthorizeAccountJSON, path string, body io.ReadCloser, length string, cType string) (int, error) {
	defer body.Close()

	uploadJson, err := b2GetUploadUrl(authJson)
	if err != nil {
		return 500, err
	}

	bodyBinary, err := ioutil.ReadAll(body)
	if err != nil {
		return 500, err
	}

	if cType == "" {
		cType = "b2/x-auto"
	}

	if length == "" {
		length = string(len(bodyBinary))
	}

	req, err := http.NewRequest("POST", uploadJson.UploadUrl, bytes.NewBuffer(bodyBinary))
	if err != nil {
		return 500, err
	}

	req.Header.Set("Authorization", uploadJson.AuthorizationToken)
	req.Header.Set("X-Bz-File-Name", strings.Replace(path, fmt.Sprintf("/%s/", authJson.Allowed.BucketName), "", 1))
	req.Header.Set("Content-Type", cType)
	req.Header.Set("X-Bz-Content-Sha1", hex.EncodeToString(sha1.New().Sum(bodyBinary)))

	if length != "" {
		req.Header.Set("Content-Length", length)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: transport,
	}

	res, err := client.Do(req)

	if err != nil {
		return 500, err
	}

	return res.StatusCode, nil
}

type B2GetUploadPartUrlJSON struct {
	AuthorizationToken string `json:"authorizationToken"`
	FileId string `json:"fileId"`
	UploadUrl string `json:"uploadUrl"`

	Code string `json:"code"`
	Message string `json:"message"`
	Status int `json:"status"`
}

func b2GetUploadPartUrl(authJson *B2AuthorizeAccountJSON, fileId string) (*B2GetUploadPartUrlJSON, error) {
	postMap := map[string]string {
		"fileId": fileId,
	}

	postBody, err := json.Marshal(postMap)
	if err != nil {
		return nil, err
	}

	res, err := b2ApiCall(authJson.AuthorizationToken, "POST", fmt.Sprintf("%s/b2api/v2/b2_get_upload_part_url", authJson.ApiUrl), postBody)
	if err != nil {
		return nil, err
	}

	var result *B2GetUploadPartUrlJSON

	if err := json.NewDecoder(res.Body).Decode(&result); err == nil || err == io.EOF {
		if result.Code != "" || result.Message != "" {
			return nil, errors.New(fmt.Sprintf("error code %s: %s", result.Code, result.Message))
		}

		return result, nil
	} else {
		return nil, err
	}
}

type B2UploadPartJSON struct {
	ContentLength int `json:"contentLength"`
	ContentSha1 string `json:"contentSha1"`
	FileId string `json:"fileId"`
	PartNumber int `json:"partNumber"`

	Code string `json:"code"`
	Message string `json:"message"`
	Status int `json:"status"`
}

func b2UploadPart(authJson *B2AuthorizeAccountJSON, uploadId string, partNumber int, body io.ReadCloser, length string, cType string) (int, error) {
	defer body.Close()

	partUpload, err := b2GetUploadPartUrl(authJson, uploadId)
	if err != nil {
		return 500, err
	}

	bodyBinary, err := ioutil.ReadAll(body)
	if err != nil {
		return 500, err
	}

	if cType == "" {
		cType = "b2/x-auto"
	}

	if length == "" {
		length = string(len(bodyBinary))
	}

	req, err := http.NewRequest("POST", partUpload.UploadUrl, bytes.NewBuffer(bodyBinary))
	if err != nil {
		return 500, err
	}

	req.Header.Set("Authorization", partUpload.AuthorizationToken)
	req.Header.Set("Content-Type", cType)
	req.Header.Set("X-Bz-Content-Sha1", hex.EncodeToString(sha1.New().Sum(bodyBinary)))

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: transport,
	}

	res, err := client.Do(req)

	if err != nil {
		return 500, err
	}

	if res.StatusCode == 200 {
		var result B2UploadPartJSON

		if err := json.NewDecoder(res.Body).Decode(&result); err != io.EOF && err != nil {
			return 500, err
		}

		if result.Code != "" || result.Message != "" {
			return result.Status, errors.New(fmt.Sprintf("error code %s: %s", result.Code, result.Message))
		}

		if _, ok := mapHashes[result.FileId]; !ok {
			mapHashes[result.FileId] = make(map[int]string)
		}

		mapHashes[result.FileId][result.PartNumber] = result.ContentSha1
	}

	return res.StatusCode, nil
}

type B2StartLargeFileJSON struct {
	AccountId string `json:"accountId"`
	Action string `json:"action"`
	BucketId string `json:"bucketId"`
	ContentLength int `json:"contentLength"`
	ContentSha1 string `json:"contentSha1"`
	ContentType string `json:"contentType"`
	FileId string `json:"fileId"`
	FileInfo map[string]interface{} `json:"fileInfo"`
	FileName string `json:"fileName"`
	UploadTimestamp int `json:"uploadTimestamp"`

	Code string `json:"code"`
	Message string `json:"message"`
	Status int `json:"status"`
}

func b2StartLargeUpload(authJson *B2AuthorizeAccountJSON, path string) (int, *B2StartLargeFileJSON, error) {
	postMap := map[string]string {
		"fileName": strings.Replace(path, "/" + authJson.Allowed.BucketName + "/", "", 1),
		"bucketId": authJson.Allowed.BucketId,
		"contentType": "b2/x-auto",
	}

	postBody, err := json.Marshal(postMap)
	if err != nil {
		return 500, nil, err
	}

	res, err := b2ApiCall(authJson.AuthorizationToken, "POST", fmt.Sprintf("%s/b2api/v2/b2_start_large_file", authJson.ApiUrl), postBody)
	if err != nil {
		return 500, nil, err
	}

	var result *B2StartLargeFileJSON

	if err := json.NewDecoder(res.Body).Decode(&result); err != io.EOF && err != nil {
		return 500, nil, err
	}

	if result.Code != "" || result.Message != "" {
		return result.Status, nil, errors.New(fmt.Sprintf("error code %s: %s", result.Code, result.Message))
	}

	return res.StatusCode, result, nil
}

func getShaSums(uploadId string) []string {
	shaSums := []string{}

	obj, ok := mapHashes[uploadId]
	if !ok || len(obj) == 0 {
		return shaSums
	}

	ids := make([]int, 0, len(obj))
	for id := range obj {
		ids = append(ids, id)
	}

	sort.Ints(ids)

	for sId := range ids {
		shaSums = append(shaSums, obj[sId])
	}

	return shaSums
}

type B2FinishLargeFileJSON struct {
	FileId string `json:"fileId"`
	PartSha1Array []string `json:"partSha1Array"`

	Code string `json:"code"`
	Message string `json:"message"`
	Status int `json:"status"`
}

func b2FinishLargeFile(authJson *B2AuthorizeAccountJSON, uploadId string) (int, error) {
	postStruct := &B2FinishLargeFileJSON{
		FileId: uploadId,
		PartSha1Array: getShaSums(uploadId),
	}

	postBody, err := json.Marshal(postStruct)
	if err != nil {
		return 500, err
	}

	call, err := b2ApiCall(authJson.AuthorizationToken, "POST", fmt.Sprintf("%s/b2api/v2/b2_finish_large_file", authJson.ApiUrl), postBody)
	if err != nil {
		return 500, err
	}

	return call.StatusCode, nil
}
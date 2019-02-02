package main

import (
	"bytes"
	"context"
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
	"os/signal"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/labstack/echo"
)

var mapHashes map[string]map[int]string = make(map[string]map[int]string)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out: os.Stdout,
		NoColor: false,
		TimeFormat: time.RFC3339,
	})

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	authStruct, err := b2Auth(os.Getenv("B2_ACCESS_KEY"), os.Getenv("B2_SECRET_KEY"))
	if err != nil {
		log.Fatal().Err(err).Msg("authorization error")
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			res := c.Response()

			start := time.Now()
			if err := next(c); err != nil {
				c.Error(err)
			}
			stop := time.Now()

			log.Info().
				Str("id", req.Header.Get(echo.HeaderXRequestID)).
				Str("remote_ip", c.RealIP()).
				Str("host", req.Host).
				Str("uri", req.RequestURI).
				Str("method", req.Method).
				Str("path", req.URL.Path).
				Str("referer", req.Referer()).
				Str("user_agent", req.UserAgent()).
				Int("status", res.Status).
				Str("page_time_ms", strconv.FormatInt(int64(stop.Sub(start)), 10)).
				Str("content_length", req.Header.Get(echo.HeaderContentLength)).
				Str("query_params", c.QueryParams().Encode()).
				Msg("")

			return nil
		}
	})

	e.PUT("/:path", func(c echo.Context) error {
		defer c.Request().Body.Close()

		if c.Request().ContentLength == 0 {
			if c.QueryParam("uploadId") != "" && c.QueryParam("partNumber") != "" {
				partN, err := strconv.Atoi(c.QueryParam("partNumber"))
				if err != nil {
					return err
				}

				if _, ok := mapHashes[c.QueryParam("uploadId")]; ok {
					if _, alsoOk := mapHashes[c.QueryParam("uploadId")][partN]; alsoOk {
						return c.JSONBlob(200, []byte{})
					}
				}
			}

			return c.JSONBlob(404, []byte{})

		} else {
			if c.QueryParam("uploadId") != "" && c.QueryParam("partNumber") != "" {
				partInt, err := strconv.Atoi(c.QueryParam("partNumber"))
				if err != nil {
					return err
				}

				incomingPartBytes, err := ioutil.ReadAll(c.Request().Body)
				if err != nil {
					return err
				}

				code, err := b2UploadPart(authStruct, c.QueryParam("uploadId"), partInt, incomingPartBytes)
				if err != nil {
					c.Response().Status = code
					return err
				}

				return c.JSONBlob(code, []byte{})

			} else {
				incomingBytes, err := ioutil.ReadAll(c.Request().Body)
				if err != nil {
					return err
				}

				code, err := b2Upload(authStruct, c.Param("path"), incomingBytes)
				if err != nil {
					c.Response().Status = code
					return err
				}

				return c.JSONBlob(code, []byte{})
			}
		}
	})

	e.POST("/:path", func(c echo.Context) error {
		defer c.Request().Body.Close()

		if c.QueryParam("uploads") != "" {
			code, res, err := b2StartLargeUpload(authStruct, c.Param("path"))
			if err != nil {
				c.Response().Status = code
				return err
			}

			if code == 200 {
				return c.XMLPretty(code, struct {
					XMLName xml.Name `xml:"InitiateMultipartUploadResult"`
					Xmlns string `xml:"xmlns,attr"`
					UploadId string `xml:"UploadId"`
				}{
					Xmlns: "https://s3.amazonaws.com/doc/2006-03-1/",
					UploadId: res.FileId,
				}, "  ")

			} else {
				return c.XMLBlob(code, []byte{})
			}
		} else {
			code, err := b2FinishLargeFile(authStruct, c.QueryParam("uploadId"))
			if err != nil {
				c.Response().Status = code
				return err
			}

			return c.XMLPretty(code, struct {
				XMLName xml.Name `xml:"CompleteMultipartUploadResult"`
				Xmlns string `xml:"xmlns,attr"`
				Location string `xml:"Location"`
			}{
				Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
				Location: "",
			}, "  ")
		}
	})

	e.DELETE("/:path", func(c echo.Context) error {
		code, err := b2Delete(authStruct, c.Param("path"))
		if err != nil {
			c.Response().Status = code
			return err
		}

		return c.JSONBlob(code, []byte{})
	})

	e.HEAD("/:path", func(c echo.Context) error {
		return c.JSONBlob(200, []byte{})
	})

	go func() {
		bind := os.Getenv("B2_BIND")
		if bind == "" {
			bind = ":9000"
		}

		log.Info().Msgf("listening on: %s", bind)

		if err := e.Start(bind); err != nil {
			log.Error().Err(err).Msg("shutting down:")
			os.Exit(0)
		}
	}()

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Second)
	defer cancel()

	if err := e.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("forcefully shutting down:")
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

func b2Upload(authJson *B2AuthorizeAccountJSON, path string, body []byte) (int, error) {
	uploadJson, err := b2GetUploadUrl(authJson)
	if err != nil {
		return 500, err
	}

	req, err := http.NewRequest("POST", uploadJson.UploadUrl, bytes.NewBuffer(body))
	if err != nil {
		return 500, err
	}

	req.Header.Set("Authorization", uploadJson.AuthorizationToken)
	req.Header.Set("X-Bz-File-Name", strings.Replace(path, fmt.Sprintf("/%s/", authJson.Allowed.BucketName), "", 1))
	req.Header.Set("Content-Type", "b2/x-auto")
	req.Header.Set("X-Bz-Content-Sha1", hex.EncodeToString(sha1.New().Sum(body)))

	client := &http.Client{
		Timeout: 30 * time.Second,
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

func b2UploadPart(authJson *B2AuthorizeAccountJSON, uploadId string, partNumber int, body []byte) (int, error) {
	partUpload, err := b2GetUploadPartUrl(authJson, uploadId)
	if err != nil {
		return 500, err
	}

	req, err := http.NewRequest("POST", partUpload.UploadUrl, bytes.NewBuffer(body))
	if err != nil {
		return 500, err
	}

	req.Header.Set("Authorization", partUpload.AuthorizationToken)
	req.Header.Set("Content-Type", "b2/x-auto")
	req.Header.Set("X-Bz-Content-Sha1", hex.EncodeToString(sha1.New().Sum(body)))

	client := &http.Client{
		Timeout: 30 * time.Second,
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
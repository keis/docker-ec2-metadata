package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	awsMetaHost = "169.254.169.254"
	//awsMetaHost = "127.0.0.1"
)

var (
	reCredentials *regexp.Regexp  = regexp.MustCompile("^/.+/meta-data/iam/security-credentials/(.*)$")
	httpTransport *http.Transport = &http.Transport{}
)

var (
	errNoRole   = errors.New("no role defined for container")
	errNoCreds  = errors.New("no credentials defined for role")
	errAWSError = errors.New("an unexpected error occurred communicating with Amazon")
)

type IAMCredentials struct {
	Code        string
	Type        string
	LastUpdated time.Time
	RoleCredentials
}

func intercept(c *appContext, w http.ResponseWriter, r *http.Request, reqRole string) (int, error) {
	//NewGET(awsMetaHost + "/" + apiVersion + "/meta-data/iam/security-credentials/")
	//resp, err := httpTransport.RoundTrip(r)

	role := c.cMgr.IPRole(remoteIP(r.RemoteAddr))
	if role == nil {
		log.Println(r.RemoteAddr, errNoRole)
		return http.StatusInternalServerError, errNoRole
	}

	if len(reqRole) == 0 {
		w.Write([]byte(role.Name))
		return http.StatusOK, nil
	}

	if !strings.HasPrefix(reqRole, role.Name) || (len(reqRole) > len(role.Name) && reqRole[len(role.Name)-1] != '/') {
		// An idiosyncrasy of the standard EC2 metadata service:
		// Subpaths of the role name are ignored. So long as the correct role name is provided,
		// it can be followed by a slash and anything after the slash is ignored.
		w.WriteHeader(http.StatusNotFound)
	} else {
		credentials := c.rMgr.RoleCredentials(role)
		if credentials == nil {
			return http.StatusInternalServerError, errNoCreds
		}
		resp, err := json.Marshal(&IAMCredentials{
			Code:            "Success",
			Type:            "AWS-HMAC",
			LastUpdated:     time.Now(),
			RoleCredentials: *credentials,
		})

		if err != nil {
			log.Println("Error marshaling credentials: ", err)
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.Write(resp)
		}
	}
	return http.StatusOK, nil
}

func passThrough(w http.ResponseWriter, r *http.Request) (int, error) {
	resp, err := httpTransport.RoundTrip(r)
	if err != nil {
		return http.StatusInternalServerError, errAWSError
	}

	//copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Println("Error copying response content from EC2 metadata service: ", err)
	}
	return http.StatusOK, nil
}

func copyHeaders(dst, src http.Header) {
	for k, _ := range dst {
		dst.Del(k)
	}

	for k, v := range src {
		vCopy := make([]string, len(v))
		copy(vCopy, v)
		dst[k] = vCopy
	}
}

func remoteIP(addr string) string {
	index := strings.Index(addr, ":")

	if index < 0 {
		return addr
	} else {
		return addr[:index]
	}
}

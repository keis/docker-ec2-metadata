package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"log"
	"sync"
	"time"
)

const (
	minRefreshTime = 40 * time.Minute
)

type RoleCredentials struct {
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      time.Time
}

func (r *RoleCredentials) NeedRefresh() bool {
	return r.Expiration.Sub(time.Now()) < minRefreshTime
}

func (r *RoleCredentials) Expired() bool {
	return time.Now().After(r.Expiration)
}

type CredentialMap struct {
	lock sync.RWMutex
	data map[string]RoleCredentials
}

func (cm *CredentialMap) Del(k string) {
	cm.lock.Lock()
	delete(cm.data, k)
	cm.lock.Unlock()
}

func (cm *CredentialMap) Get(k string) *RoleCredentials {
	cm.lock.RLock()
	cred, ok := cm.data[k]
	cm.lock.RUnlock()
	if !ok {
		return nil
	}
	return &cred
}

func (cm *CredentialMap) Set(k string, v *RoleCredentials) *RoleCredentials {
	cm.lock.Lock()
	cm.data[k] = *v
	cm.lock.Unlock()
	return v
}

type RoleManager struct {
	session *session.Session
	creds   CredentialMap
}

func NewRoleManager() (*RoleManager, error) {
	mgr := &RoleManager{
		session: session.New(),
		creds:   CredentialMap{data: make(map[string]RoleCredentials)},
	}

	return mgr, nil
}

func (rm *RoleManager) RoleCredentials(r *RoleARN) *RoleCredentials {
	cred := rm.creds.Get(r.String())
	if cred != nil {
		if !cred.NeedRefresh() {
			log.Printf("Using cached credentials for role '%s'\n", r)
			return cred
		}
		if cred.Expired() {
			rm.creds.Del(r.String())
			cred = nil
		}
	}
	log.Printf("Credentials request: role=%s\n", r)
	sessionName := fmt.Sprintf("Proxy_%s", r.Name)
	stsClient := sts.New(rm.session, &aws.Config{Region: aws.String("eu-west-1")})
	resp, err := stsClient.AssumeRole(&sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(3600), // Max is 1 hour
		ExternalId:      nil,             // Empty string means not applicable
		Policy:          nil,             // Empty string means not applicable
		RoleArn:         aws.String(r.String()),
		RoleSessionName: aws.String(sessionName),
	})
	if err != nil {
		return cred
	}
	cred = &RoleCredentials{
		string(*resp.Credentials.AccessKeyId),
		string(*resp.Credentials.SecretAccessKey),
		string(*resp.Credentials.SessionToken),
		*resp.Credentials.Expiration,
	}
	return rm.creds.Set(r.String(), cred)
}

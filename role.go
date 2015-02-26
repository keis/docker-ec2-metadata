package main

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

var (
	reRoleARN *regexp.Regexp = regexp.MustCompile("^arn:aws:iam::([0-9]+):role/([^:]+/)?([^:]+?)$")

	// ErrInvalidARN error is returned for invalid ARN strings
	ErrInvalidARN = errors.New("invalid ARN")
)

type RoleARN struct {
	AccountID int
	Path      string
	Name      string
}

func (r *RoleARN) String() string {
	return fmt.Sprintf("arn:aws:iam::%d:role%s%s", r.AccountID, r.Path, r.Name)
}

func NewRoleARN(arn string) (*RoleARN, error) {
	result := reRoleARN.FindStringSubmatch(arn)

	if result == nil {
		return nil, ErrInvalidARN
	}
	id, err := strconv.Atoi(result[1])
	if err != nil {
		return nil, ErrInvalidARN
	}
	result[2] = "/" + result[2]
	ra := RoleARN{
		AccountID: id,
		Path:      result[2],
		Name:      result[3],
	}
	return &ra, nil
}

type RoleCredentials struct {
	AccessKey  string
	SecretKey  string
	Token      string
	Expiration time.Time
}

func (r *RoleCredentials) Expired() bool {
	return time.Now().After(r.Expiration)
}

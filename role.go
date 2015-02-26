package main

import (
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/gen/sts"
)

var (
	roleArnRegex *regexp.Regexp = regexp.MustCompile(`^arn:aws:iam::(\d+):role/([^:]+/)?([^:]+?)$`)
)

type RoleArn struct {
	value     string
	path      string
	name      string
	accountId string
}

func NewRoleArn(value string) (RoleArn, error) {
	result := roleArnRegex.FindStringSubmatch(value)

	if result == nil {
		return RoleArn{}, errors.New("invalid role ARN")
	}

	return RoleArn{value, "/" + result[2], result[3], result[1]}, nil
}

func (t RoleArn) RoleName() string {
	return t.name
}

func (t RoleArn) Path() string {
	return t.path
}

func (t RoleArn) AccountId() string {
	return t.accountId
}

func (t RoleArn) String() string {
	return t.value
}

func (t RoleArn) Empty() bool {
	return len(t.value) == 0
}

type RoleCredentials struct {
	AccessKey  string
	SecretKey  string
	Token      string
	Expiration time.Time
}

func (t *RoleCredentials) ExpiredNow() bool {
	return t.ExpiredAt(time.Now())
}

func (t *RoleCredentials) ExpiredAt(at time.Time) bool {
	return at.After(t.Expiration)
}

func AssumeRole(auth aws.CredentialsProvider, roleArn, sessionName string) (*RoleCredentials, error) {
	stsClient := sts.New(auth, "eu-west-1b", &http.Client{})
	resp, err := stsClient.AssumeRole(&sts.AssumeRoleRequest{
		DurationSeconds: aws.Integer(3600), // Max is 1 hour
		ExternalID:      nil,               // Empty string means not applicable
		Policy:          nil,               // Empty string means not applicable
		RoleARN:         aws.String(roleArn),
		RoleSessionName: aws.String(sessionName),
	})

	if err != nil {
		return nil, err
	}

	return &RoleCredentials{
		string(*resp.Credentials.AccessKeyID),
		string(*resp.Credentials.SecretAccessKey),
		string(*resp.Credentials.SessionToken),
		resp.Credentials.Expiration,
	}, nil
}

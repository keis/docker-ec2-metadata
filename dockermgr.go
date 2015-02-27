package main

import (
	"errors"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fsouza/go-dockerclient"
)

const (
	maxSessionNameLen = 32
	shortDockerIDLen  = 12
	containerMaxAge   = 30 * time.Second
	defaultEndpoint   = "unix:///var/run/docker.sock"
	envRoleVarName    = "IAM_ROLE"
)

var (
	// matches char that is not valid in a STS role session name
	reInvalid = regexp.MustCompile(`[^\w+=,.@-]`)

	ErrNoContainerForIP = errors.New("no container found for IP address")
)

type ContainerInfo struct {
	Container *docker.Container
	ARN       *RoleARN
	Updated   time.Time
}

func (ci *ContainerInfo) IsValid() bool {
	if ci.ARN == nil {
		return false
	}

	return time.Since(ci.Updated) > containerMaxAge
}

type DockerMgr struct {
	client         *docker.Client
	lock           sync.RWMutex
	containerIPMap map[string]*ContainerInfo
}

func NewDockerMgr() (*DockerMgr, error) {
	client, err := docker.NewClient(defaultEndpoint)
	if err != nil {
		return nil, err
	}
	_, err = client.Info()
	if err != nil {
		return nil, err
	}

	manager := &DockerMgr{
		client:         client,
		containerIPMap: make(map[string]*ContainerInfo),
	}
	return manager, nil
}

func (d *DockerMgr) Roles() []string {
	var roles []string
	for i := range d.containerIPMap {
		roles = append(roles, d.containerIPMap[i].ARN.String())
	}
	return roles
}

func (d *DockerMgr) Role(ipaddr string) (*RoleARN, error) {
	d.lock.RLock()
	c, ok := d.containerIPMap[ipaddr]
	d.lock.RUnlock()
	if !ok {
		return nil, ErrNoContainerForIP
	}

	return c.ARN, nil
}

func (d *DockerMgr) Synchronise() error {
	log.Println("Synchronising state with running docker containers")
	containers, err := d.client.ListContainers(docker.ListContainersOptions{
		All:    false, // only running containers
		Size:   false, // do not need size information
		Limit:  0,     // all running containers
		Since:  "",    // not applicable
		Before: "",    // not applicable
	})
	if err != nil {
		return err
	}

	d.lock.Lock()
	d.containerIPMap = make(map[string]*ContainerInfo)
	for _, container := range containers {
		shortID := container.ID[:shortDockerIDLen]
		c, err := d.client.InspectContainer(container.ID)
		if err != nil {
			log.Println("Error inspecting container: ", shortID, ": ", err)
			continue
		}

		roleARN := roleFromENV(c.Config.Env)
		log.Printf("Container: id=%s image=%s role=%s", shortID, c.Config.Image, roleARN)
		d.containerIPMap[c.NetworkSettings.IPAddress] = &ContainerInfo{
			Container: c,
			ARN:       roleARN,
		}
	}
	d.lock.Unlock()
	return nil
}

func roleFromENV(env []string) *RoleARN {
	var arn *RoleARN
	for i := range env {
		v := strings.SplitN(env[i], "=", 2)
		if len(v) < 2 || v[0] != envRoleVarName {
			continue
		}
		var err error
		arn, err = NewRoleARN(v[1])
		if err != nil {
			log.Println("Bad ARN, ", err)
		}
		break
	}

	return arn
}

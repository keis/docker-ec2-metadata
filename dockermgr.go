package main

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/fsouza/go-dockerclient"
)

const (
	defaultEndpoint  = "unix:///var/run/docker.sock"
	shortDockerIDLen = 12
	envRoleVarName   = "IAM_ROLE"
	containerMaxAge  = 20 * time.Second
	containerMinWait = 2 * time.Second
)

var ()

type ContainerInfo struct {
	Updated   time.Time
	IPAddress string
	Role      *RoleARN
}

func (ci *ContainerInfo) IsValid() bool {
	return time.Since(ci.Updated) < containerMaxAge
}

type DockerManager struct {
	client     *docker.Client
	lock       sync.RWMutex
	containers map[string]*ContainerInfo
	lastupdate time.Time
}

func NewDockerManager() (*DockerManager, error) {
	client, err := docker.NewClient(defaultEndpoint)
	if err != nil {
		return nil, err
	}
	_, err = client.Info()
	if err != nil {
		return nil, err
	}

	scanner := &DockerManager{
		client:     client,
		containers: make(map[string]*ContainerInfo),
	}
	return scanner, nil
}

func (cs *DockerManager) containerForIP(ip string) *ContainerInfo {
	cs.lock.RLock()
	defer cs.lock.RUnlock()
	for _, ci := range cs.containers {
		if !ci.IsValid() || ci.IPAddress != ip {
			continue
		}
		return ci
	}
	return nil
}

func (cs *DockerManager) IPRole(ip string) *RoleARN {
	ci := cs.containerForIP(ip)
	if ci == nil || time.Since(ci.Updated) > containerMaxAge {
		cs.update()
		cs.purge()
		ci = cs.containerForIP(ip)
	}
	if ci == nil {
		return nil
	}
	log.Printf("Role request: ip=%s role=%s\n", ip, ci.Role)
	return ci.Role
}

func (cs *DockerManager) update() error {
	now := time.Now()
	if now.Sub(cs.lastupdate) < containerMinWait {
		return nil
	}
	containers, err := cs.client.ListContainers(docker.ListContainersOptions{
		All:    false, // only running containers
		Size:   false, // do not need size information
		Limit:  0,     // all running containers
		Since:  "",    // not applicable
		Before: "",    // not applicable
	})
	if err != nil {
		return err
	}

	cs.lock.Lock()
	for _, container := range containers {
		shortID := container.ID[:shortDockerIDLen]
		ci, ok := cs.containers[shortID]
		if ok {
			ci.Updated = now
			continue
		}
		c, err := cs.client.InspectContainer(container.ID)
		if err != nil {
			log.Println("Error inspecting container: ", shortID, ": ", err)
			continue
		}
		ci = &ContainerInfo{
			Updated:   now,
			IPAddress: c.NetworkSettings.IPAddress,
			Role:      roleFromENV(c.Config.Env),
		}
		cs.containers[shortID] = ci
		log.Printf("New container: id=%s image=%s role=%s", shortID, c.Config.Image, ci.Role)
	}
	cs.lock.Unlock()
	cs.lastupdate = now
	return nil
}

func (cs *DockerManager) purge() {
	cs.lock.Lock()
	for key := range cs.containers {
		if !cs.containers[key].IsValid() {
			delete(cs.containers, key)
		}
	}
	cs.lock.Unlock()
}

func roleFromENV(env []string) *RoleARN {
	for i := range env {
		v := strings.SplitN(env[i], "=", 2)
		if len(v) < 2 || v[0] != envRoleVarName {
			continue
		}
		var err error
		arn, err := NewRoleARN(v[1])
		if err != nil {
			log.Println("Bad ARN, ", err)
		}
		return arn
	}
	return nil
}

/*
	roleARN := roleARNFromENV(c.Config.Env)
	if roleARN == nil {
		continue
	}
	ci.ARN = roleARN
*/

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	//"gopkg.in/natefinch/lumberjack.v2"
)

// TODO
// Get current zone from http://169.254.169.254/latest/meta-data/placement/availability-zone/

var (
// reInvalid matches char that is not valid in a STS role session name
//reInvalid = regexp.MustCompile(`[^\w+=,.@-]`)

)

type RoleMapper interface {
	IPRole(string) *RoleARN
}

type CredentialsMapper interface {
	RoleCredentials(*RoleARN) *RoleCredentials
}

type appContext struct {
	cMgr RoleMapper
	rMgr CredentialsMapper
}

type proxyHandler struct {
	context     appContext
	passThrough func(http.ResponseWriter, *http.Request) (int, error)
	intercept   func(*appContext, http.ResponseWriter, *http.Request, string) (int, error)
}

func (p proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var status int
	var err error

	r.URL.Scheme = "http"
	r.URL.Host = awsMetaHost
	match := reCredentials.FindStringSubmatch(r.URL.Path)
	if match != nil {
		status, err = p.intercept(&p.context, w, r, match[1])
	} else {
		status, err = p.passThrough(w, r)
	}
	if err != nil {
		log.Printf("HTTP %d: %q", status, err)
		switch status {
		case http.StatusNotFound:
			http.NotFound(w, r)
			// And if we wanted a friendlier error page, we can
			// now leverage our context instance - e.g.
			// err := ah.renderTemplate(w, "http_404.tmpl", nil)
		case http.StatusInternalServerError:
			http.Error(w, http.StatusText(status), status)
		default:
			http.Error(w, http.StatusText(status), status)
		}
	}
}

func main() {
	var err error
	var ctx = appContext{}

	fmt.Println("Metaproxy")
	//l := &lumberjack.Logger{Filename: "logfile.log"}
	//log.SetOutput(l)
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	/*
		go func() {
			for {
				<-c
				l.Rotate()
			}
		}()
	*/

	ctx.cMgr, err = NewDockerManager()
	if err != nil {
		log.Fatal(err)
	}

	ctx.rMgr, err = NewRoleManager()
	if err != nil {
		log.Fatal(err)
	}

	// Proxy non-credentials requests to primary metadata service
	http.Handle("/", proxyHandler{
		context:     ctx,
		passThrough: passThrough,
		intercept:   intercept,
	})
	log.Println(http.ListenAndServe("0.0.0.0:18000", nil))
}

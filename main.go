package main

//go:generate go-bindata templates/...

import (
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	weblog "github.com/samitpal/goProbe/log"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/samitpal/simple-sso/ldap"
	"github.com/samitpal/simple-sso/sso"
)

var lsso sso.SSOer
var templates = template.New("")

func init() {
	var err error
	lsso, err = ldap.NewLdapSSO()
	if err != nil {
		log.Fatalf("Error initializing ldap sso: %s", err)
	}

	for _, path := range AssetNames() {
		bytes, err := Asset(path)
		if err != nil {
			log.Fatalf("Unable to parse: path=%s, err=%s", path, err)
		}
		templates.New(path).Parse(string(bytes))
	}
}

type TmplData struct {
	QueryString string
	Error       bool
}

func renderTemplate(w http.ResponseWriter, tmpl string, p interface{}) {
	err := templates.ExecuteTemplate(w, tmpl, p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleSSOGetRequest presents the login form
func handleSSOGetRequest(w http.ResponseWriter, r *http.Request) {
	err := false
	if r.URL.Query().Get("auth_error") != "" {
		err = true
	}
	tmplData := TmplData{QueryString: r.URL.Query().Get("s_url"), Error: err}
	renderTemplate(w, "templates/login.html", &tmplData)
}

// handleSSOPostRequest sets the sso cookie.
func handleSSOPostRequest(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	p_uri := r.PostFormValue("query_string")

	u, g, err := lsso.Auth(r.PostFormValue("username"), r.PostFormValue("password"))
	if u != nil {
		vh := lsso.CTValidHours()
		exp := time.Now().Add(time.Hour * time.Duration(vh)).UTC()
		tok, _ := lsso.BuildJWTToken(*u, *g, exp)
		c := lsso.BuildCookie(tok, exp)
		http.SetCookie(w, &c)
		http.Redirect(w, r, p_uri, 301)
		return
	}
	if err != nil {
		if sso.Err401Map[err] {
			log.Println(err)
			http.Redirect(w, r, fmt.Sprintf("/sso?s_url=%s&auth_error=true", p_uri), 301)
			return
		}
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Not able to service this request. Please try again later.")
		return

	}
}

// handleAuthTokenRequest generates the raw jwt token and sends it across.
func handleAuthTokenRequest(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	u, g, err := lsso.Auth(r.PostFormValue("username"), r.PostFormValue("password"))
	if u != nil {
		tok, _ := lsso.BuildJWTToken(*u, *g, time.Now().Add(time.Hour*time.Duration(lsso.CTValidHours())).UTC())
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, tok)
		return
	}
	if err != nil {
		if sso.Err401Map[err] {
			log.Println(err)
			fmt.Fprintf(w, "Unauthorized.")
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Not able to service the request. Please try again later.")
		return

	}
}

// handleLogoutRequest function invalidates the sso cookie.
func handleLogoutRequest(w http.ResponseWriter, r *http.Request) {
	expT := time.Now().Add(time.Hour * time.Duration(-1))
	lc := lsso.Logout(expT)

	http.SetCookie(w, &lc)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "You have been logged out.")
	return
}

// handleTestRequest function is just for the purpose of testing.
func handleTestRequest(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "You have visited a test page.")
	return
}

func main() {
	log.Println("Starting login server.")
	r := mux.NewRouter()

	var fh *os.File
	var err error
	wld := ldap.BaseConf.WeblogDir
	if wld != "" {
		fh, err = weblog.SetupWebLog(wld, time.Now())
		if err != nil {
			log.Fatalf("Failed to set up logging: %v", err)
		}
	} else {
		fh = os.Stdout // logs web accesses to stdout. May not be thread safe.
	}

	r.Handle("/sso", handlers.CombinedLoggingHandler(fh, http.HandlerFunc(handleSSOPostRequest))).Methods("POST")
	r.Handle("/sso", handlers.CombinedLoggingHandler(fh, http.HandlerFunc(handleSSOGetRequest))).Methods("GET")
	r.Handle("/logout", handlers.CombinedLoggingHandler(fh, http.HandlerFunc(handleLogoutRequest))).Methods("GET")
	r.Handle("/auth_token", handlers.CombinedLoggingHandler(fh, http.HandlerFunc(handleAuthTokenRequest))).Methods("POST")
	r.Handle("/test", handlers.CombinedLoggingHandler(fh, http.HandlerFunc(handleTestRequest))).Methods("GET")

	http.Handle("/", r)

	err = http.ListenAndServeTLS(":8081", ldap.BaseConf.SSLCertPath, ldap.BaseConf.SSLKeyPath, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

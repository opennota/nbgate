// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
// Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program.  If not, see <http://www.gnu.org/licenses/>.

// Reverse proxy to notabenoid.org
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"

	"rsc.io/letsencrypt"
)

const (
	host        = "notabenoid.org"
	baseURL     = "http://notabenoid.org/"
	settingsURL = baseURL + "register/settings"
)

var (
	user = flag.String("u", "", "Username")
	pass = flag.String("p", "", "Password")
	addr = flag.String("http", "", "HTTP service address (will be redirected to HTTPS)")

	jar, _ = cookiejar.New(nil)
	c      = http.Client{Jar: jar}

	rSensitivePath = regexp.MustCompile(`(?i)^/register|^/users/\d+/(edit|delete)`)
)

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func logRequest(r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	log.Println(host, r.Method, r.URL, r.Referer(), r.UserAgent())
}

var removeHeaders = []string{
	"Cookie",
	"Set-Cookie",
	"Connection",
	"Keep-Alive",
}

func send(req *http.Request) (*http.Response, error) {
	for _, cookie := range jar.Cookies(req.URL) {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if rc := resp.Cookies(); len(rc) > 0 {
		jar.SetCookies(req.URL, rc)
	}
	return resp, err
}

func reverseProxy(w http.ResponseWriter, req *http.Request) {
	logRequest(req)

	if rSensitivePath.MatchString(req.URL.Path) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	outReq := new(http.Request)
	outReq.Method = req.Method
	outReq.URL = &url.URL{
		Scheme:   "http",
		Host:     host,
		Path:     req.URL.Path,
		RawQuery: req.URL.RawQuery,
	}
	outReq.Proto = "HTTP/1.1"
	outReq.ProtoMajor = 1
	outReq.ProtoMinor = 1
	outReq.Header = make(http.Header)
	outReq.Body = req.Body
	outReq.ContentLength = req.ContentLength
	outReq.Host = host

	for _, h := range removeHeaders {
		req.Header.Del(h)
	}
	copyHeader(outReq.Header, req.Header)
	outReq.Header.Set("Host", host)
	outReq.Header.Set("Referer", baseURL)
	outReq.Header.Set("Origin", baseURL)

	resp, err := send(outReq)
	if err != nil {
		log.Printf("proxy error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	for _, h := range removeHeaders {
		resp.Header.Del(h)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		if u, err := url.Parse(loc); err == nil && u.Host == host {
			u.Scheme = "https"
			u.Host = req.Host
			resp.Header.Set("Location", u.String())
		}
	}
	copyHeader(w.Header(), resp.Header)
	w.Header().Add("X-Frame-Options", "SAMEORIGIN")
	w.Header().Add("X-XSS-Protection", "1; mode=block")
	w.Header().Add("X-Content-Type-Options", "nosniff")
	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)
}

func robotsHandler(w http.ResponseWriter, req *http.Request) {
	logRequest(req)
	w.Write([]byte("User-agent: *\nDisallow: /\n"))
}

func login() error {
	loginForm := url.Values{
		"login[login]": {*user},
		"login[pass]":  {*pass},
	}
	resp, err := c.PostForm(baseURL, loginForm)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New(resp.Status)
	}

	resp, err = c.Get(settingsURL)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New(resp.Status)
	}

	return nil
}

func redirectHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil || r.Host == "" {
		http.Error(w, "not found", 404)
		return
	}

	u := r.URL
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	u.Host = host
	u.Scheme = "https"
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func main() {
	flag.Parse()

	if *user == "" || *pass == "" {
		fmt.Println("Usage: nbgate -u username -p password")
		os.Exit(1)
	}

	if err := login(); err != nil {
		log.Fatalf("failed to log in: %v; invalid username or password?", err)
	}

	http.HandleFunc("/", reverseProxy)
	http.HandleFunc("/robots.txt", robotsHandler)

	if *addr != "" {
		l, err := net.Listen("tcp", *addr)
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		go http.Serve(l, http.HandlerFunc(redirectHTTP))
	}

	var m letsencrypt.Manager
	if err := m.CacheFile("letsencrypt.cache"); err != nil {
		log.Fatal(err)
	}

	log.Println("listening...")
	log.Fatal(m.ServeHTTPS())
}

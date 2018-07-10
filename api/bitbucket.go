package api

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
)

type BitBucketGateway struct {
	proxy *httputil.ReverseProxy
}

func NewBitBucketGateway() *BitBucketGateway {
	return &BitBucketGateway{
		proxy: &httputil.ReverseProxy{
			Director:  bitbucketDirector,
			Transport: &BitBucketTransport{},
		},
	}
}

var bitbucketPathRegexp = regexp.MustCompile("^/bitbucket/?")
var bitbucketAllowedRegexp = regexp.MustCompile("^/bitbucket/(src)/?")

func bitbucketDirector(r *http.Request) {
	ctx := r.Context()
	target := getProxyTarget(ctx)
	accessToken := getAccessToken(ctx)

	targetQuery := target.RawQuery
	r.Host = target.Host
	r.URL.Scheme = target.Scheme
	r.URL.Host = target.Host
	r.URL.Path = singleJoiningSlash(target.Path, bitbucketPathRegexp.ReplaceAllString(r.URL.Path, "/"))
	if targetQuery == "" || r.URL.RawQuery == "" {
		r.URL.RawQuery = targetQuery + r.URL.RawQuery
	} else {
		r.URL.RawQuery = targetQuery + "&" + r.URL.RawQuery
	}
	if _, ok := r.Header["User-Agent"]; !ok {
		r.Header.Set("User-Agent", "")
	}

	if r.Method != http.MethodOptions {
		r.Header.Set("Authorization", "Bearer "+accessToken)
	}

	log := getLogEntry(r)
	log.Infof("Proxying to BitBucket: %v", r.URL.String())
}

func (bb *BitBucketGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	config := getConfig(ctx)
	if config == nil || config.BitBucket.AccessToken == "" {
		handleError(notFoundError("No BitBucket Settings Configured"), w, r)
		return
	}

	if err := bb.authenticate(w, r); err != nil {
		handleError(unauthorizedError(err.Error()), w, r)
		return
	}

	endpoint := config.BitBucket.Endpoint
	apiURL := singleJoiningSlash(endpoint, "/repositories/"+config.BitBucket.Repo)
	target, err := url.Parse(apiURL)
	if err != nil {
		handleError(internalServerError("Unable to process BitBucket endpoint"), w, r)
		return
	}
	ctx = withProxyTarget(ctx, target)
	ctx = withAccessToken(ctx, config.BitBucket.AccessToken)
	bb.proxy.ServeHTTP(w, r.WithContext(ctx))
}

func (bb *BitBucketGateway) authenticate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	claims := getClaims(ctx)
	config := getConfig(ctx)

	if claims == nil {
		return errors.New("Access to endpoint not allowed: no claims found in Bearer token")
	}

	if !allowedRegexp.MatchString(r.URL.Path) {
		return errors.New("Access to endpoint not allowed: this part of GitHub's API has been restricted")
	}

	if len(config.Roles) == 0 {
		return nil
	}

	roles, ok := claims.AppMetaData["roles"]
	if ok {
		roleStrings, _ := roles.([]interface{})
		for _, data := range roleStrings {
			role, _ := data.(string)
			for _, adminRole := range config.Roles {
				if role == adminRole {
					return nil
				}
			}
		}
	}

	return errors.New("Access to endpoint not allowed: your role doesn't allow access")
}

// NEED LINK REWRITE CODE HERE

type BitBucketTransport struct{}

func (t *BitBucketTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err == nil {
		// remove CORS headers from BitBucket and use our own
		resp.Header.Del("Access-Control-Allow-Origin")
	}
	return resp, err
}

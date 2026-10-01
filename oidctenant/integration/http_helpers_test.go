package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func urlValues() url.Values { return url.Values{} }

func queryParam(raw, key string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Query().Get(key)
}

func postForm(t *testing.T, client *http.Client, action string, fields map[string]string) *http.Response {
	t.Helper()
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	req, err := http.NewRequest(http.MethodPost, action, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new post form: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post form: %v", err)
	}
	return resp
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func absKeycloak(action string) string {
	if strings.HasPrefix(action, "http") {
		return action
	}
	if strings.HasPrefix(action, "/") {
		return kcBaseURL() + action
	}
	return kcBaseURL() + "/" + action
}

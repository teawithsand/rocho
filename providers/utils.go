package providers

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

func getHTTPClient(ctx context.Context) (client *http.Client) {
	rawCl := ctx.Value(oauth2.HTTPClient)
	if rawCl != nil {
		client = rawCl.(*http.Client)
		return
	}
	client = http.DefaultClient
	return
}

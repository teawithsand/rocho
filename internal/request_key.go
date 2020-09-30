package internal

// TODO(teawithsand): make use of it

type RequestKey string

// RequestContextKey is key for context.WithValue method for passing HTTP request to inner components.
var RequestContextKey RequestKey = ""

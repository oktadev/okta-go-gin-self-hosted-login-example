package main

import "okta-go-gin-sample/server"

func main() {
	// Init web app
	server := server.NewServer()
	server.Init()
}

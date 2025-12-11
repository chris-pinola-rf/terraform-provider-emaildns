package main

import (
	"context"
	"flag"
	"log"

	"terraform-provider-emaildns/internal/provider"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

var (
	// version is set during build via ldflags
	version string = "dev"
)

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/hashicorp/emaildns",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}

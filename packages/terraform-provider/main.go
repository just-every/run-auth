package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
	"github.com/just-every/run-auth/terraform-provider/internal/provider"
)

func main() { plugin.Serve(&plugin.ServeOpts{ProviderFunc: provider.New}) }

package vxpwngard

import "embed"

//go:embed rules/*.yaml
var RulesFS embed.FS

//go:embed demo/vulnerable/workflows/*.yml
var DemoFS embed.FS

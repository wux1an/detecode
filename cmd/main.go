package main

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/wux1an/detecode"
	"os"
	"path/filepath"
)

var Version = "v0.0.0"
var ShortCommit = "123456"

func main() {
	if len(os.Args) != 2 {
		fmt.Printf(color.CyanString("usage:")+"   %s <path-to-scan>\n", filepath.Base(os.Args[0]))
		fmt.Printf(color.CyanString("version:")+" %s(%s)\n", Version, ShortCommit)
		fmt.Printf(color.New(color.Italic, color.Underline, color.FgCyan, color.Bold).Sprintf("see: github.com/wux1an/detecode\n"))
		os.Exit(0)
	}

	detecode.StartScan(os.Args[1])
}

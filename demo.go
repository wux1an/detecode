package detecode

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func StartScan(root string) {
	var detector = NewDetector(root)
	count, _ := detector.FileCount()
	fmt.Printf("[+] total %d files\n", count)

	var wg sync.WaitGroup
	var timer = time.Now()

	var bar = progressbar.NewOptions(count,
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetWidth(15),
		progressbar.OptionSetDescription("[cyan] Detecting... [reset]"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}))

	wg.Add(1)
	go func() {
		defer wg.Done()

		detector.Start()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		pwd, _ := filepath.Abs(".")

		c := color.New()
		for record := range detector.Results() {
			bar.Add(1)
			bar.Describe("[cyan] Detecting " + less(detector.CurrentFile()) + " [reset]")
			for _, s := range record.Findings {
				bar.Clear()
				rel, err := filepath.Rel(pwd, record.FilePath)
				if err != nil {
					rel = record.FilePath
				}

				var width = 10
				var start = strings.Index(s.Line, s.Secret)
				var prefixIndex = int(math.Max(float64(start-1-width), 0))
				var suffixIndex = int(math.Min(float64(start+len(s.Secret)+width), float64(len(s.Line))))
				c.Println(color.CyanString("[+] %s:%-3d", less(rel), s.StartLine) +
					color.YellowString(" %s", s.Description) + "  " +
					color.GreenString(s.Line[prefixIndex:start]) + color.HiGreenString(s.Secret) + color.GreenString(s.Line[start+len(s.Secret):suffixIndex]))
			}
		}
	}()

	wg.Add(1)
	go func() {
		wg.Done()

		for err := range detector.ChError() {
			fmt.Println("[x]", err)
		}
	}()

	wg.Wait()

	bar.Clear()

	fmt.Printf("\n[+] finished, cost: %v\n", time.Duration(int(time.Now().Sub(timer).Seconds()))*time.Second)
}

func less(str string) string {
	maxPathWidth := 50

	if len(str) <= maxPathWidth {
		return str
	}

	return str[:maxPathWidth/2-2] + "...." + str[len(str)-(maxPathWidth/2-2):]
}

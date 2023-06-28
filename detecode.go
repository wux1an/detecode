package detecode

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
	"os"
	"path/filepath"
	"sync"
	"unicode/utf8"
)

var opts = &Option{ // todo only for test
	Thread:      30,
	RegexThread: 30,
}

func DefaultOption() *Option {
	return opts
}

type Option struct {
	Thread      int
	RegexThread int
}

type Record struct {
	FilePath string
	Findings []report.Finding
}

type Detector struct {
	chFilePath    chan string
	chRecord      chan *Record
	chError       chan error
	chErrorEnable bool
	root          string
	currentFile   map[string]bool
	locker        sync.Mutex
}

func NewDetector(root string) *Detector {
	return &Detector{
		root:        root,
		chFilePath:  make(chan string),
		chRecord:    make(chan *Record),
		chError:     make(chan error),
		currentFile: make(map[string]bool),
	}
}

func (d *Detector) CurrentFile() string {
	d.locker.Lock()
	defer d.locker.Unlock()

	for k := range d.currentFile {
		return k
	}
	return "..."
}

func (d *Detector) FileCount() (int, error) {
	var result = 0
	err := filepath.Walk(d.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			result++
		}
		return nil
	})

	return result, err
}

func (d *Detector) ChError() <-chan error {
	d.chErrorEnable = true
	return d.chError
}

func (d *Detector) Results() <-chan *Record {
	return d.chRecord
}

func (d *Detector) Start() {
	var wg = sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := d.startProvideFile(); err != nil {
			d.pushError(errors.New("failed to start scan, " + err.Error()))
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		d.startDetectFile()
	}()

	wg.Wait()

	if d.chErrorEnable {
		close(d.chError)
	}
}

func (d *Detector) startDetectFile() {
	var wg = sync.WaitGroup{}

	wg.Add(opts.Thread)
	for i := 0; i < opts.Thread; i++ {
		go func() {
			defer wg.Done()

			for p := range d.chFilePath {
				d.locker.Lock()
				d.currentFile[p] = true
				d.locker.Unlock()

				d.chRecord <- d.detect0(p)

				d.locker.Lock()
				delete(d.currentFile, p)
				d.locker.Unlock()
			}
		}()
	}

	wg.Wait()

	defer close(d.chRecord)
}

func (d *Detector) startProvideFile() error {
	defer close(d.chFilePath)

	err := filepath.Walk(d.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			d.chFilePath <- path
		}
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (d *Detector) isBinaryFile(p string) bool {
	readFile, err := os.Open(p)
	if err != nil {
		panic(err)
	}
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)

	fileScanner.Scan()

	return !utf8.ValidString(fileScanner.Text())
}

func (d *Detector) detect0(p string) *Record {
	var record = &Record{FilePath: p}

	if d.isBinaryFile(p) {
		return record
	}

	var (
		chRegex = make(chan *config.Rule)
		wg      = sync.WaitGroup{}
		locker  = sync.Mutex{}
	)

	// provider
	wg.Add(1)
	go func() {
		defer wg.Done()

		for _, r := range secretRules {
			chRegex <- r
		}
		close(chRegex)
	}()

	// consumer
	wg.Add(opts.RegexThread)
	for i := 0; i < opts.RegexThread; i++ {
		go func() {
			defer wg.Done()

			for r := range chRegex {
				detector := newSubDetector(r)
				results, err := detector.DetectFiles(p)
				if err != nil {
					d.pushError(errors.New(fmt.Sprintf("failed to detect file, " + err.Error())))
					continue
				}

				if len(results) != 0 {
					locker.Lock()
					record.Findings = append(record.Findings, results...)
					locker.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	return record
}

func (d *Detector) pushError(err error) {
	if d.chErrorEnable {
		d.chError <- err
	}
}

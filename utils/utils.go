package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"
	pb "gopkg.in/cheggaaa/pb.v1"
)

func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "vuln-list-update")
	return dir
}

func VulnListDir() string {
	return filepath.Join(CacheDir(), "vuln-list")
}

func SaveCVEPerYear(dirName string, cveID string, data interface{}) error {
	s := strings.Split(cveID, "-")
	if len(s) != 3 {
		return xerrors.Errorf("invalid CVE-ID format: %s\n", cveID)
	}

	yearDir := filepath.Join(VulnListDir(), dirName, s[1])
	if err := os.MkdirAll(yearDir, os.ModePerm); err != nil {
		return err
	}

	filePath := filepath.Join(yearDir, fmt.Sprintf("%s.json", cveID))
	if err := Write(filePath, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}

func Write(filePath string, data interface{}) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	_, err = f.Write(b)
	if err != nil {
		return err
	}
	return nil
}

// GenWorkers generate workders
func GenWorkers(num, wait int) chan<- func() {
	tasks := make(chan func())
	for i := 0; i < num; i++ {
		go func() {
			for f := range tasks {
				f()
				time.Sleep(time.Duration(wait) * time.Second)
			}
		}()
	}
	return tasks
}

// DeleteNil deletes nil in errs
func DeleteNil(errs []error) (new []error) {
	for _, err := range errs {
		if err != nil {
			new = append(new, err)
		}
	}
	return new
}

// TrimSpaceNewline deletes space character and newline character(CR/LF)
func TrimSpaceNewline(str string) string {
	str = strings.TrimSpace(str)
	return strings.Trim(str, "\r\n")
}

// FetchURL returns HTTP response body with retry
func FetchURL(url, apikey string, retry int) (res []byte, err error) {
	for i := 0; i <= retry; i++ {
		if i > 0 {
			wait := math.Pow(float64(i), 2) + float64(randInt()%10)
			log.Printf("retry after %f seconds\n", wait)
			time.Sleep(time.Duration(time.Duration(wait) * time.Second))
		}
		res, err = fetchURL(url, apikey)
		if err == nil {
			return res, nil
		}
	}
	return nil, xerrors.Errorf("failed to fetch URL: %w", err)
}

func randInt() int {
	seed, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	return int(seed.Int64())
}

func fetchURL(url, apikey string) ([]byte, error) {
	req := gorequest.New().Get(url)
	if apikey != "" {
		req.Header.Add("api-key", apikey)
	}
	resp, body, errs := req.Type("text").EndBytes()
	if len(errs) > 0 {
		return nil, xerrors.Errorf("HTTP error. url: %s, err: %w", url, errs[0])
	}
	if resp.StatusCode != 200 {
		return nil, xerrors.Errorf("HTTP error. status code: %d, url: %s", resp.StatusCode, url)
	}
	return body, nil
}

// FetchConcurrently fetches concurrently
func FetchConcurrently(urls []string, concurrency, wait, retry int) (responses [][]byte, err error) {
	reqChan := make(chan string, len(urls))
	resChan := make(chan []byte, len(urls))
	errChan := make(chan error, len(urls))
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, url := range urls {
			reqChan <- url
		}
	}()

	bar := pb.StartNew(len(urls))
	tasks := GenWorkers(concurrency, wait)
	for range urls {
		tasks <- func() {
			url := <-reqChan
			res, err := FetchURL(url, "", retry)
			if err != nil {
				errChan <- err
				return
			}
			resChan <- res
		}
		bar.Increment()
	}
	bar.Finish()

	var errs []error
	timeout := time.After(10 * 60 * time.Second)
	for range urls {
		select {
		case res := <-resChan:
			responses = append(responses, res)
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return nil, xerrors.New("Timeout Fetching URL")
		}
	}
	if 0 < len(errs) {
		return responses, fmt.Errorf("%s", errs)

	}
	return responses, nil
}

// Major returns major version
func Major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}

func IsCommandAvailable(name string) bool {
	cmd := exec.Command(name, "--help")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func Exec(command string, args []string) (string, error) {
	cmd := exec.Command(command, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		log.Println(stderrBuf.String())
		return "", xerrors.Errorf("failed to exec: %w", err)
	}
	return stdoutBuf.String(), nil
}

func LookupEnv(key, defaultValue string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultValue
}

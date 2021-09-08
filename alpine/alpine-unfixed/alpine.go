package alpineunfix

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/spf13/afero"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	alpineDir = "alpine-unfix"
	filePath  = "alpine/alpine-unfixed/all.tar.gz"
	secFixUrl = "https://aquasecurity.github.io/secfixes-tracker/all.tar.gz"
)

var (
	alpineActiveReleases = []string{
		"edge-main",
		"edge-community",
		"3.14-main",
		"3.14-community",
		"3.13-main",
		"3.12-main",
		"3.11-main",
		"3.10-main",
	}
)

type Updater struct {
	vulnListDir      string
	appFs            afero.Fs
	baseURL          string
	fileDownloadPath string
	retry            int
}

func NewUpdater() *Updater {
	updater := &Updater{
		vulnListDir:      utils.VulnListDir(),
		appFs:            afero.NewOsFs(),
		baseURL:          secFixUrl,
		fileDownloadPath: filePath,
	}
	return updater
}
func (u Updater) Update() (err error) {
	dir := filepath.Join(u.vulnListDir, alpineDir)
	log.Printf("Remove Alpine directory %s", dir)
	if err := u.appFs.RemoveAll(dir); err != nil {
		return xerrors.Errorf("failed to remove Alpine directory: %w", err)
	}
	if err := u.appFs.MkdirAll(dir, 0755); err != nil {
		return err
	}

	log.Println("Fetching Alpine unfix data...")
	err = utils.DownloadFile(u.fileDownloadPath, u.baseURL)
	if err != nil {
		return err
	}
	defer os.RemoveAll(u.fileDownloadPath)

	err = u.ExtractTarGz(dir)
	if err != nil {
		return err
	}
	return
}

func (u Updater) ExtractTarGz(saveDir string) error {
	gzFile, err := os.Open(u.fileDownloadPath)
	if err != nil {
		return xerrors.Errorf("failed to open gz file: %w", err)
	}

	if err := u.appFs.MkdirAll(saveDir, os.ModePerm); err != nil {
		return xerrors.Errorf("unable to create a directory: %w", err)
	}

	uncompressedStream, err := gzip.NewReader(gzFile)
	if err != nil {
		return xerrors.Errorf("failed creating reader for gz file: %w", err)
	}
	tarReader := tar.NewReader(uncompressedStream)
	for true {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return xerrors.Errorf("failed in getting next(): %w", err)
		}
		switch header.Typeflag {
		case tar.TypeDir:
		case tar.TypeReg:
			var alpineUnfix AlpineUnfix

			byteValue, _ := ioutil.ReadAll(tarReader)
			err = json.Unmarshal(byteValue, &alpineUnfix)
			if err != nil {
				return xerrors.Errorf("failed unmarshall security fix json %s : %w", header.Name, err)
			}

			_, fileName := filepath.Split(header.Name)
			saveFileName := filepath.Join(saveDir, fileName)
			if err = u.save(saveFileName, alpineUnfix); err != nil {
				return xerrors.Errorf("failed saving json file %s : %w", saveFileName, err)
			}
		default:
			return xerrors.Errorf("ExtractTarGz: unknown type: %s in %s", header.Typeflag, header.Name)
		}
	}
	return nil
}

func (u Updater) save(fileName string, alpineUnfix interface{}) error {
	f, err := u.appFs.Create(fileName)
	defer f.Close()

	b, err := utils.JSONMarshal(alpineUnfix)
	if err != nil {
		return xerrors.Errorf("failed to marshal JSON: %w", err)
	}

	if _, err = f.Write(b); err != nil {
		return xerrors.Errorf("failed to save a file: %w", err)
	}
	return nil
}

package tfinstall

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hashicorp/go-getter"
	"golang.org/x/crypto/openpgp"
)

const releaseHost = "https://releases.hashicorp.com/terraform"

const hashicorpPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFMORM0BCADBRyKO1MhCirazOSVwcfTr1xUxjPvfxD3hjUwHtjsOy/bT6p9f
W2mRPfwnq2JB5As+paL3UGDsSRDnK9KAxQb0NNF4+eVhr/EJ18s3wwXXDMjpIifq
fIm2WyH3G+aRLTLPIpscUNKDyxFOUbsmgXAmJ46Re1fn8uKxKRHbfa39aeuEYWFA
3drdL1WoUngvED7f+RnKBK2G6ZEpO+LDovQk19xGjiMTtPJrjMjZJ3QXqPvx5wca
KSZLr4lMTuoTI/ZXyZy5bD4tShiZz6KcyX27cD70q2iRcEZ0poLKHyEIDAi3TM5k
SwbbWBFd5RNPOR0qzrb/0p9ksKK48IIfH2FvABEBAAG0K0hhc2hpQ29ycCBTZWN1
cml0eSA8c2VjdXJpdHlAaGFzaGljb3JwLmNvbT6JAU4EEwEKADgWIQSRpuf4XQXG
VjC+8YlRhS2HNI/8TAUCXn0BIQIbAwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAK
CRBRhS2HNI/8TJITCACT2Zu2l8Jo/YLQMs+iYsC3gn5qJE/qf60VWpOnP0LG24rj
k3j4ET5P2ow/o9lQNCM/fJrEB2CwhnlvbrLbNBbt2e35QVWvvxwFZwVcoBQXTXdT
+G2cKS2Snc0bhNF7jcPX1zau8gxLurxQBaRdoL38XQ41aKfdOjEico4ZxQYSrOoC
RbF6FODXj+ZL8CzJFa2Sd0rHAROHoF7WhKOvTrg1u8JvHrSgvLYGBHQZUV23cmXH
yvzITl5jFzORf9TUdSv8tnuAnNsOV4vOA6lj61Z3/0Vgor+ZByfiznonPHQtKYtY
kac1M/Dq2xZYiSf0tDFywgUDIF/IyS348wKmnDGjuQENBFMORM0BCADWj1GNOP4O
wJmJDjI2gmeok6fYQeUbI/+Hnv5Z/cAK80Tvft3noy1oedxaDdazvrLu7YlyQOWA
M1curbqJa6ozPAwc7T8XSwWxIuFfo9rStHQE3QUARxIdziQKTtlAbXI2mQU99c6x
vSueQ/gq3ICFRBwCmPAm+JCwZG+cDLJJ/g6wEilNATSFdakbMX4lHUB2X0qradNO
J66pdZWxTCxRLomPBWa5JEPanbosaJk0+n9+P6ImPiWpt8wiu0Qzfzo7loXiDxo/
0G8fSbjYsIF+skY+zhNbY1MenfIPctB9X5iyW291mWW7rhhZyuqqxN2xnmPPgFmi
QGd+8KVodadHABEBAAGJATwEGAECACYCGwwWIQSRpuf4XQXGVjC+8YlRhS2HNI/8
TAUCXn0BRAUJEvOKdwAKCRBRhS2HNI/8TEzUB/9pEHVwtTxL8+VRq559Q0tPOIOb
h3b+GroZRQGq/tcQDVbYOO6cyRMR9IohVJk0b9wnnUHoZpoA4H79UUfIB4sZngma
enL/9magP1uAHxPxEa5i/yYqR0MYfz4+PGdvqyj91NrkZm3WIpwzqW/KZp8YnD77
VzGVodT8xqAoHW+bHiza9Jmm9Rkf5/0i0JY7GXoJgk4QBG/Fcp0OR5NUWxN3PEM0
dpeiU4GI5wOz5RAIOvSv7u1h0ZxMnJG4B4MKniIAr4yD7WYYZh/VxEPeiS/E1CVx
qHV5VVCoEIoYVHIuFIyFu1lIcei53VD6V690rmn0bp4A5hs+kErhThvkok3c
=+mCN
-----END PGP PUBLIC KEY BLOCK-----`

type installer struct {
	osName        string
	archName      string
	version       string
	client        getter.Client
	sumsTmpDir    string
	sumsPath      string
	sumsSigPath   string
	terraformPath string
}

// InstallTerraform downloads a suitable Terraform binary to a temporary
// folder, verifies the hash and signature file, and returns the path to
// the binary.
func InstallTerraform(version string, installDir string) (string, error) {
	var tfDir string
	var err error

	if installDir == "" {
		tfDir, err = ioutil.TempDir("", "tfexec")
		if err != nil {
			return "", fmt.Errorf("failed to create temp dir: %s", err)
		}
	} else {
		if _, err := os.Stat(installDir); err != nil {
			return "", fmt.Errorf("could not access directory %s for installing Terraform: %s", installDir, err)
		}
		tfDir = installDir

	}

	if version == "" {
		version, err = tfVersion()
		if err != nil {
			return "", err
		}
	}

	ti, err := newInstaller(version)
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(ti.sumsTmpDir)

	url := ti.tfUrl()

	// verify signature SHA255SUMS.sig
	err = ti.verifySumsSignature()
	if err != nil {
		return "", fmt.Errorf("SHA256SUMS.sig signature is invalid: %s\nDid not download terraform from %s", err, url)
	}

	// download terraform
	err = ti.getDir(url, tfDir)
	if err != nil {
		return "", fmt.Errorf("failed to download terraform from %s: %s", url, err)
	}
	terraformPath := filepath.Join(tfDir, "terraform")
	ti.terraformPath = terraformPath

	return terraformPath, nil
}

func (ti *installer) get(src, dst string) error {
	ti.client.Mode = getter.ClientModeAny
	ti.client.Src = src
	ti.client.Dst = dst

	return ti.client.Get()
}

func (ti *installer) getDir(src, dst string) error {
	ti.client.Mode = getter.ClientModeDir
	ti.client.Src = src
	ti.client.Dst = dst

	return ti.client.Get()
}

func (ti *installer) tfUrl() string {
	sumsFilename := "terraform_" + ti.version + "_SHA256SUMS"
	sumsUrl := fmt.Sprintf("%s/%s/%s",
		releaseHost, ti.version, sumsFilename)
	return fmt.Sprintf(
		"%s/%s/terraform_%s_%s_%s.zip?checksum=file:%s",
		releaseHost, ti.version, ti.version, ti.osName, ti.archName, sumsUrl,
	)
}

func tfVersion() (string, error) {
	// TODO KEM: use Checkpoint to find latest version
	return "0.12.26", nil
}

func newInstaller(version string) (*installer, error) {
	httpHeader := make(http.Header)
	httpHeader.Set("User-Agent", "HashiCorp-tfinstaller/"+Version)
	httpGetter := &getter.HttpGetter{
		Netrc: true,
	}

	client := getter.Client{
		Getters: map[string]getter.Getter{
			"https": httpGetter,
		},
	}

	sumsTmpDir, err := ioutil.TempDir("", "tfinstall")
	if err != nil {
		return nil, err
	}

	ti := installer{
		osName:     runtime.GOOS,
		archName:   runtime.GOARCH,
		version:    version,
		sumsTmpDir: sumsTmpDir,
		client:     client,
	}

	sumsFilename := "terraform_" + ti.version + "_SHA256SUMS"
	sumsSigFilename := sumsFilename + ".sig"

	sumsUrl := fmt.Sprintf("%s/%s/%s",
		releaseHost, ti.version, sumsFilename)
	sumsSigUrl := fmt.Sprintf("%s/%s/%s",
		releaseHost, ti.version, sumsSigFilename)

	err = ti.get(sumsUrl, ti.sumsTmpDir)
	if err != nil {
		return nil, fmt.Errorf("error fetching checksums: %s", err)
	}
	err = ti.get(sumsSigUrl, ti.sumsTmpDir)
	if err != nil {
		return nil, fmt.Errorf("error fetching checksums signature: %s", err)
	}

	ti.sumsPath = filepath.Join(sumsTmpDir, sumsFilename)
	ti.sumsSigPath = filepath.Join(sumsTmpDir, sumsSigFilename)

	return &ti, nil
}

// verifySumsSignature downloads SHA256SUMS and SHA256SUMS.sig and verifies
// the signature using the HashiCorp public key.
func (ti *installer) verifySumsSignature() error {
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(hashicorpPublicKey))
	if err != nil {
		return err
	}
	data, err := os.Open(ti.sumsPath)
	if err != nil {
		return err
	}
	sig, err := os.Open(ti.sumsSigPath)
	if err != nil {
		return err
	}
	_, err = openpgp.CheckDetachedSignature(el, data, sig)

	return err
}

// verifySums verifies the hash of the downloaded file against the appropriate line
// in SHA256SUMS
func (ti *installer) verifySums() error {
	t, err := os.Open(ti.terraformPath)
	if err != nil {
		return err
	}
	defer t.Close()

	h := sha256.New()
	if _, err := io.Copy(h, t); err != nil {
		return err
	}

	f, err := os.Open(ti.sumsPath)
	if err != nil {
		return err
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
		parts := strings.Fields(line)
		fmt.Println(parts)
		if parts[0] == "terraform" {
			fmt.Println("J")
			checksum, err := hex.DecodeString(parts[1])
			if err != nil {
				return err
			}
			if bytes.Equal(h.Sum(nil), checksum) {
				return nil
			} else {
				return fmt.Errorf("incorrect checksum for terraform binary")
			}
		}
	}

	return fmt.Errorf("checksum for terraform binary not found in SHA256SUMS")
}

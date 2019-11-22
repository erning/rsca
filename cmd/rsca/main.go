package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"

	"github.com/erning/rsca/pkg/rsca"

	"github.com/erning/rsca/internal/pkg/rest"

	"github.com/spf13/cobra"
)

var cacertFile string
var cakeyFile string

var rootCmd = &cobra.Command{
	Use:   "rsca",
	Short: "RSCA Command Line Tools",
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Usage()
	},
}

var restCmd = &cobra.Command{
	Use: "rest [host:port]",
	RunE: func(cmd *cobra.Command, args []string) error {
		cacert, cakey, err := loadCA()
		if err != nil {
			return err
		}
		handler := rest.NewHandler(cacert, cakey)
		http.HandleFunc("/issue", handler.HandleIssueClientCertificate)

		var addr string
		if len(args) >= 1 {
			addr = args[0]
		} else {
			addr = ":3000"
		}

		log.Println()
		log.Println("HTTP Serve on", addr)
		log.Println("GOMAXPROCS: ", runtime.GOMAXPROCS(0))
		return http.ListenAndServe(addr, nil)
	},
}

var issueCmd = &cobra.Command{
	Use: "issue <pubkey file>",
	RunE: func(cmd *cobra.Command, args []string) error {
		cacert, cakey, err := loadCA()
		if err != nil {
			return err
		}

		if len(args) <= 0 {
			return errors.New("missing pubkey file")
		}
		pubPEM, err := ioutil.ReadFile(args[0])
		if err != nil {
			return err
		}
		pub, err := rsca.ParsePublicKey(pubPEM)
		if err != nil {
			return err
		}
		cert, err := rsca.IssueClientCertificate(cacert, cakey, pub)
		if err != nil {
			return err
		}

		data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		fmt.Printf("%s\n", string(data))
		return nil
	},
}

func loadCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	cacertPEM, err := ioutil.ReadFile(cacertFile)
	if err != nil {
		return nil, nil, err
	}
	cakeyPEM, err := ioutil.ReadFile(cakeyFile)
	if err != nil {
		return nil, nil, err
	}
	cacert, err := rsca.ParseCertificate(cacertPEM)
	if err != nil {
		return nil, nil, err
	}
	cakey, err := rsca.ParsePrivateKey(cakeyPEM)
	if err != nil {
		return nil, nil, err
	}
	return cacert, cakey, nil
}

func init() {
	// cobra.OnInitialize(initConfig)
	{
		flags := rootCmd.PersistentFlags()
		flags.StringVar(&cacertFile, "cacert", "", "ca cert")
		flags.StringVar(&cakeyFile, "cakey", "", "ca prikey")

		_ = rootCmd.MarkPersistentFlagRequired("cacert")
		_ = rootCmd.MarkPersistentFlagRequired("cakey")
	}

	rootCmd.AddCommand(restCmd)
	rootCmd.AddCommand(issueCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

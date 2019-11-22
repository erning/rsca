package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"

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
	Use: "rest",
	RunE: func(cmd *cobra.Command, args []string) error {
		cacertPEM, err := ioutil.ReadFile(cacertFile)
		if err != nil {
			return err
		}
		cakeyPEM, err := ioutil.ReadFile(cakeyFile)
		if err != nil {
			return err
		}

		handler, err := rest.NewHandlerFromPEM(cacertPEM, cakeyPEM)
		if err != nil {
			return err
		}
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

func init() {
	// cobra.OnInitialize(initConfig)
	{
		flags := rootCmd.PersistentFlags()
		flags.StringVar(&cacertFile, "cacert", "", "certificate of ca")
		flags.StringVar(&cakeyFile, "cakey", "", "private key of ca")

		_ = rootCmd.MarkPersistentFlagRequired("cacert")
		_ = rootCmd.MarkPersistentFlagRequired("cakey")
	}

	rootCmd.AddCommand(restCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

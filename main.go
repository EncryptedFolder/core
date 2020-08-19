package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"sync"
	"syscall"

	"ef_core/lib"

	"golang.org/x/crypto/ssh/terminal"
)

import "C"

/*
	C API
*/
//export Encrypt
func Encrypt(path string, password string) {
	lib.Run(true, path, password)
}

//export Decrypt
func Decrypt(path string, password string) {
	lib.Run(false, path, password)
}

/*
	CLI
*/
func main() {
	dirPath := ""
	mode := ""
	cfgPath := ""

	flag.StringVar(&dirPath, "d", "", "directory: path for directory")
	flag.StringVar(&mode, "m", "", "mode: encrypt or decrypt")
	flag.StringVar(&cfgPath, "c", "", `config path: path for JSON file with dirs and passwords (example: { "targets": [{ "dir_path": "/path", "password": "123" }] })`)
	flag.Parse()

	cfg := lib.Config{}

	// cfg or params
	if cfgPath != "" {
		fileBytes, err := ioutil.ReadFile(cfgPath)

		if err != nil {
			fmt.Println("cfg path is invalid")
			return
		}
		if err := json.Unmarshal(fileBytes, &cfg); err != nil {
			fmt.Println("config file is invalid:", err)
			return
		}
		if err := cfg.Validate(); err != nil {
			fmt.Println("validate config file error:", err)
			return
		}
	} else {
		if dirPath == "" {
			fmt.Println("directory path are required")
			return
		}
	}
	if mode == "" {
		fmt.Println("mode are required")
		return
	}
	if mode != "encrypt" && mode != "decrypt" {
		fmt.Printf("mode %s is wrong. Use 'encrypt' or 'decrypt' values", mode)
		return
	}
	// run
	if cfgPath != "" {
		// with config
		var wg sync.WaitGroup

		for _, item := range cfg.Items {
			wg.Add(1)
			if mode == "encrypt" {
				go func(wg *sync.WaitGroup, it lib.CongigItem) {
					fmt.Println("\nencrypting", it.DirPath)
					Encrypt(it.DirPath, it.Password)
					wg.Done()
				}(&wg, item)
			} else {
				go func(wg *sync.WaitGroup, it lib.CongigItem) {
					fmt.Println("\ndecrypting", it.DirPath)
					Decrypt(it.DirPath, it.Password)
					wg.Done()
				}(&wg, item)
			}
		}

		wg.Wait()
	} else {
		// without config
		fmt.Print("Enter Password: ")
		bytePassword, err := terminal.ReadPassword(syscall.Stdin)

		if err != nil || len(bytePassword) == 0 {
			fmt.Println("password is required")
			return
		}
		if mode == "encrypt" {
			fmt.Println("\nencrypting", dirPath)
			Encrypt(dirPath, string(bytePassword))
		} else {
			fmt.Println("\ndecrypting", dirPath)
			Decrypt(dirPath, string(bytePassword))
		}
	}

	fmt.Println("done")
}

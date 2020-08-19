package lib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	IsEncrypted = 0
	IsDecryped  = 1
	workerCount = 40
)

var systemNames = map[string]bool{
	".":         true,
	"..":        true,
	".DS_Store": true,
}

type FileData struct {
	Name string
	Path string
}

type Config struct {
	Items []CongigItem `json:"targets"`
}

type CongigItem struct {
	DirPath  string `json:"dir_path"`
	Password string `json:"password"`
}

func (cfg *Config) Validate() error {
	for _, item := range cfg.Items {
		if item.DirPath == "" {
			return errors.New(`all "dir_path" is require`)
		}
		if item.Password == "" {
			return errors.New(`all "password" is require`)
		}
	}

	return nil
}

var InterfaceReportChan chan string
var CryptChan chan int

////export Encrypt
//func Encrypt(path string, password string) {
//	Run(true, path, password)
//}
//
////export Decrypt
//func Decrypt(path string, password string) {
//	Run(false, path, password)
//}

func Run(isCrypt bool, path string, password string) {
	if path == "" || password == "" {
		log.Println("folder path or password is empty")
		return
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Printf("directory %s is not exist", path)
		return
	}

	pswd := sha256.Sum256([]byte(password))
	pathChan := make(chan string, 100)

	for i := 0; i < workerCount; i++ {
		if isCrypt {
			go cryptWorker(pathChan, pswd[:])
			continue
		}
		go decryptWorker(pathChan, pswd[:])
	}

	var wg sync.WaitGroup

	readDir(path, pathChan, &wg)
	wg.Wait()

	// wait for close
	tick := time.NewTicker(500 & time.Millisecond)

	for range tick.C {
		if len(pathChan) == 0 {
			close(pathChan)
			tick.Stop()

			if CryptChan != nil {
				if isCrypt {
					CryptChan <- IsEncrypted
				} else {
					CryptChan <- IsDecryped
				}
			}

			return
		}
	}
}

func cryptWorker(pathChan <-chan string, password []byte) {
	for path := range pathChan {
		fmt.Println(path)

		if InterfaceReportChan != nil {
			InterfaceReportChan <- path
		}

		// чтение файла
		fileData, err := getImageData(path)

		if err != nil {
			log.Println("get file data error:", err)
			continue
		}

		body, err := ioutil.ReadFile(path)

		if err != nil {
			log.Printf("open file %s error: %s", path, err)
			continue
		}

		// шифрование содержимого файла
		cipherText, err := encrypt(body, password)

		if err != nil {
			log.Printf("encrypt file %s error: %s", path, err)
			continue
		}

		// шифрование имени  файла

		// запись нового содержимого по новому пути
		if err := ioutil.WriteFile(fileData.Path+"/"+fileData.Name, cipherText, 0777); err != nil {
			log.Printf("write encrypted file %s error %s", path, err)
			continue
		}
	}
}

func decryptWorker(pathChan <-chan string, password []byte) {
	for path := range pathChan {
		fmt.Println(path)

		if InterfaceReportChan != nil {
			InterfaceReportChan <- path
		}

		// чтение файла
		fileData, err := getImageData(path)

		if err != nil {
			log.Println("get file data error:", err)
			continue
		}

		body, err := ioutil.ReadFile(path)

		if err != nil {
			log.Printf("open file %s error: %s", path, err)
			continue
		}

		// расшифровка содержимого файла
		decryptedText, err := decrypt(body, password)

		if err != nil {
			log.Printf("encrypt file %s error: %s", path, err)
			continue
		}

		// расшифровка имени  файла

		// запись нового содержимого по новому пути
		if err := ioutil.WriteFile(fileData.Path+"/"+fileData.Name, decryptedText, 0777); err != nil {
			log.Printf("write decrypted file %s error %s", path, err)
			continue
		}
	}
}

func readDir(path string, pathChan chan string, wg *sync.WaitGroup) {
	wg.Add(1)
	if !strings.HasSuffix(path, "/") && !strings.HasSuffix(path, `\`) {
		path += "/"
	}

	files, err := ioutil.ReadDir(path)

	if err != nil {
		log.Println("read dir err:", err)
		return
	}
	for _, file := range files {
		fileName := file.Name()

		if _, ok := systemNames[fileName]; ok {
			continue
		}
		if !file.IsDir() {
			pathChan <- path + fileName
			continue
		}

		go readDir(path+fileName, pathChan, wg)
	}

	time.Sleep(100 * time.Millisecond) // time for run goroutine and make wg.Add
	wg.Done()
}

func getImageData(path string) (FileData, error) {
	fileData := FileData{}
	pathChunks := strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '\\'
	})

	if len(pathChunks) < 2 {
		return fileData, fmt.Errorf("invalid file path: %s", path)
	}

	fileName := pathChunks[len(pathChunks)-1]
	fileData.Name = fileName
	fileData.Path = strings.ReplaceAll(path, fileName, "")

	return fileData, nil
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)

	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(cipherText []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)

	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	if len(cipherText) < nonceSize {
		return nil, errors.New("cipherText too short")
	}

	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	return gcm.Open(nil, nonce, cipherText, nil)
}

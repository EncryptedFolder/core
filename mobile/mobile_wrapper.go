package mobile

import "ef_core/lib"

type CryptView interface {
	IsEncryped()
	IsDecryped()
	ShowPath(path string)
}
type CryptPresenter struct {
	doneChan chan bool
	view     CryptView
}

func NewCryptPresenter(view CryptView) *CryptPresenter {
	c := new(CryptPresenter)
	c.doneChan = make(chan bool, 1)
	c.view = view

	lib.InterfaceReportChan = make(chan string, 100)
	lib.CryptChan = make(chan int, 1)

	go c.listener()

	return c
}

func (c *CryptPresenter) Encrypt(path string, password string) {
	go lib.Run(true, path, password)
}

func (c *CryptPresenter) Decrypt(path string, password string) {
	go lib.Run(false, path, password)
}

func (c *CryptPresenter) Dispose() {
	c.doneChan <- true
}

func (c *CryptPresenter) listener() {
	for {
		select {
		case status := <-lib.CryptChan:
			if status == lib.IsEncrypted {
				c.view.IsEncryped()
			}
			if status == lib.IsDecryped {
				c.view.IsDecryped()
			}
		case <-c.doneChan:
			close(lib.CryptChan)
			close(c.doneChan)
			return
		case path := <-lib.InterfaceReportChan:
			go c.view.ShowPath(path)
		}
	}
}

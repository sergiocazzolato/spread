package spread

import (
	"time"
	"golang.org/x/crypto/ssh"
	"net/http"
)

func MockClient() *Client {
	config := &ssh.ClientConfig{
		User:    "mock",
		Timeout: 10 * time.Second,
	}
	return &Client{
		config: config,
		job:    "mock-job",
	}
}

func DialOnReboot(cli *Client, prevUptime time.Time) error {
	return cli.dialOnReboot(prevUptime)
}

func SetKillTimeout(cli *Client, killTimeout time.Duration) {
	cli.killTimeout = killTimeout
}

func SetWarnTimeout(cli *Client, warnTimeout time.Duration) {
	cli.warnTimeout = warnTimeout
}

func MockSshDial(f func(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error)) (restore func()) {
	oldSshDial := sshDial
	sshDial = f
	return func() {
		sshDial = oldSshDial
	}
}

func NewGoogleProviderForTesting(mockApiURL string, p *Project, b *Backend, o *Options) *googleProvider {
	provider := Google(p, b, o)
	ggl := provider.(*googleProvider)
	ggl.apiURL = mockApiURL
	ggl.keyChecked = true
	ggl.client = &http.Client{}
	return ggl
}

func (p *googleProvider) ProjectImages(project string) ([]googleImage, error) {
	return p.projectImages(project)
}

var QemuCmd = qemuCmd

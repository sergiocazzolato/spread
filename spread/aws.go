package spread

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/aws"
	"golang.org/x/oauth2/jwt"

	"github.com/niemeyer/pretty"
	"regexp"
	"strconv"
	"unicode"
)

func aws(p *Project, b *Backend, o *Options) Provider {
	return &awsProvider{
		project: p,
		backend: b,
		options: o,

		imagesCache: make(map[string]*awsImagesCache),
	}
}

type awsProvider struct {
	project *Project
	backend *Backend
	options *Options

	awsProject string
	awsZone    string

	svc ec2iface.EC2API

	mu sync.Mutex

	keyChecked bool
	keyErr     error

	imagesCache map[string]*awsImagesCache
}

type awsServer struct {
	p *awsProvider
	d awsServerData

	system  *System
	address string
}

type awsServerData struct {
	Name    string
	Plan    string    `json:"machineType"`
	Status  string    `yaml:"-"`
	Created time.Time `json:"creationTimestamp"`

	Labels map[string]string `yaml:"-"`
}

func (d *awsServerData) cleanup() {
	if i := strings.LastIndex(d.Plan, "/"); i >= 0 {
		d.Plan = d.Plan[i+1:]
	}
}

func (s *awsServer) String() string {
	if s.system == nil {
		return s.d.Name
	}
	return fmt.Sprintf("%s (%s)", s.system, s.d.Name)
}

func (s *awsServer) Label() string {
	return s.d.Name
}

func (s *awsServer) Provider() Provider {
	return s.p
}

func (s *awsServer) Address() string {
	return s.address
}

func (s *awsServer) System() *System {
	return s.system
}

func (s *awsServer) ReuseData() interface{} {
	return &s.d
}

const (
	awsStaging      = "STAGING"
	awsProvisioning = "PROVISIONING"
	awsRunning      = "RUNNING"
	awsStopping     = "STOPPING"
	awsStopped      = "STOPPED"
	awsSuspending   = "SUSPENDING"
	awsTerminating  = "TERMINATED"

	awsPending = "PENDING"
	awsDone    = "DONE"
)

func (p *awsProvider) Backend() *Backend {
	return p.backend
}

func (p *awsProvider) Reuse(ctx context.Context, rsystem *ReuseSystem, system *System) (Server, error) {
	s := &awsServer{
		p:       p,
		address: rsystem.Address,
		system:  system,
	}
	err := rsystem.UnmarshalData(&s.d)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal aws reuse data: %v", err)
	}
	return s, nil
}

func (p *awsProvider) Allocate(ctx context.Context, system *System) (Server, error) {
	if err := p.checkKey(); err != nil {
		return nil, err
	}

	s, err := p.createMachine(ctx, system)
	if err != nil {
		return nil, err
	}

	printf("Allocated %s.", s)
	return s, nil
}

func (s *awsServer) Discard(ctx context.Context) error {
	return s.p.removeMachine(ctx, s)
}

const googleStartupScript = `
#cloud-config
runcmd:
 - echo root:%s | chpasswd
 - sed -i 's/^\s*#\?\s*\(PermitRootLogin\|PasswordAuthentication\)\>.*/\1 yes/' /etc/ssh/sshd_config
 - pkill -o -HUP sshd || true
 - echo '` + awsReadyMarker + `' > /dev/ttyS2
`
const awsReadyMarker = "MACHINE-IS-READY"
const awsNameLayout = "Jan021504.000000"
const awsDefaultPlan = "t4g.micro"

func awsName() string {
	return strings.ToLower(strings.Replace(time.Now().UTC().Format(awsNameLayout), ".", "-", 1))
}

func awsParseName(name string) (time.Time, error) {
	t, err := time.Parse(awsNameLayout, strings.Replace(name, "-", ".", 1))
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid aws machine name for spread: %s", name)
	}
	return t, nil
}

var awsLabelExp = regexp.MustCompile("^[a-z0-9_-]+$")

func (p *awsProvider) validLabel(label string) bool {
	return len(label) < 64 && awsLabelExp.MatchString(label)
}


func (p *awsProvider) address(s *awsServer) (string, error) {
    allocRes, err := p.svc.AllocateAddress(&ec2.AllocateAddressInput{
        Domain: aws.String("vpc"),
    })
    if err != nil {
        return nil, nil, err
    }

    assocRes, err := p.svc.AssociateAddress(&ec2.AssociateAddressInput{
        AllocationId: allocRes.AllocationId,
        InstanceId:   instanceID,
    })
    if err != nil {
        return nil, err
    }

    return allocRes.PublicIp, nil
}

type awsImage struct {
	Project string
	Name    string
	Family  string
	Terms   []string
}

var termExp = regexp.MustCompile("[a-z]+|[0-9](?:[0-9.]*[0-9])?")

func toTerms(s string) []string {
	return termExp.FindAllString(strings.ToLower(s), -1)
}

func containsTerms(superset, subset []string) bool {
	j := 0
Outer:
	for _, term := range subset {
		for ; j < len(superset); j++ {
			if term == superset[j] {
				continue Outer
			}
		}
		return false
	}
	return true
}


type awsImagesCache struct {
	mu     sync.Mutex
	ready  bool
	images []awsImage
	err    error
}

func (p *googleProvider) azone() string {
	if i := strings.Index(p.backend.Location, "/"); i > 0 && i+1 < len(p.backend.Location) {
		return p.backend.Location[i+1:]
	}
	return googleMissingZone
}

func (p *awsProvider) createMachine(ctx context.Context, system *System) (*awsServer, error) {
	debugf("Creating new aws server for %s...", system.Name)

	name := awsName()
	plan := awsDefaultPlan
	if system.Plan != "" {
		plan = system.Plan
	}

	image, err := p.image(system)
	if err != nil {
		return nil, err
	}

	sess, err := session.NewSession(&aws.Config{
        Region: aws.String(p.azone()},
    )

    // Create EC2 service client
    p.svc := ec2.New(sess)

    cloudconfig := fmt.Sprintf(googleStartupScript, p.options.Password)
    userdata := base64.StdEncoding.EncodeToString([]byte(cloudconfig))

	runResult, err := p.svc.RunInstances(&ec2.RunInstancesInput{
        // An Amazon Linux AMI ID for t2.micro instances in the us-west-2 region
        ImageId:      aws.String(image),
        InstanceType: aws.String(plan),
        MinCount:     aws.Int64(1),
        MaxCount:     aws.Int64(1),
        UserData:     aws.String(userdata),
    })

    if err != nil {
        fmt.Println("Could not create instance", err)
        return
    }

    fmt.Println("Created instance", *runResult.Instances[0].InstanceId)

    // Add tags to the created instance
    _, errtag := p.svc.CreateTags(&ec2.CreateTagsInput{
        Resources: []*string{runResult.Instances[0].InstanceId},
        Tags: []*ec2.Tag{
            {
                Key:   aws.String("spread"),
                Value: aws.String("true"),
            },
            {
            	Key:   aws.String("owner"),
                Value: aws.String(strings.ToLower(username())),
            },
            {
                Key:   aws.String("reuse"),
                Value: aws.String(strconv.FormatBool(p.options.Reuse)),
            },
        },

    })
    if errtag != nil {
        log.Println("Could not create tags for instance", runResult.Instances[0].InstanceId, errtag)
        return
    }
    fmt.Println("Successfully tagged instance")

    s := &awsServer{
		p: p,
		d: awsServerData{
			Name:    name,
			Plan:    plan,
			Status:  awsProvisioning,
			Created: time.Now(),
		},

		system: system,
	}

	s.address, err = p.address(s)
	if err == nil {
		err = p.waitServerBoot(ctx, s)
	}
	if err == nil {
		err = p.dropStartupScript(s)
	}
	if err != nil {
		if p.removeMachine(ctx, s) != nil {
			return nil, &FatalError{fmt.Errorf("cannot allocate or deallocate (!) new aws server %s: %v", s, err)}
		}
		return nil, &FatalError{fmt.Errorf("cannot allocate new aws server %s: %v", s, err)}
	}

	return s, nil
}

func (p *awsProvider) waitServerBoot(ctx context.Context, s *awsServer) error {
	printf("Waiting for %s to boot at %s...", s, s.address)

	timeout := time.After(3 * time.Minute)
	relog := time.NewTicker(60 * time.Second)
	defer relog.Stop()
	retry := time.NewTicker(5 * time.Second)
	defer retry.Stop()

	var err error
	var marker = []byte(awsReadyMarker)
	var trail []byte
	var result struct {
		Contents string
		Next     string
	}
	result.Next = "0"
	for {

		err = p.doz("GET", fmt.Sprintf("/instances/%s/serialPort?port=3&start=%s", s.d.Name, result.Next), nil, &result)
		if err != nil {
			printf("Cannot get console output for %s: %v", s, err)
			return fmt.Errorf("cannot get console output for %s: %v", s, err)
		}

		trail = append(trail, result.Contents...)
		debugf("Current console buffer for %s:\n-----\n%s\n-----", s, trail)
		if bytes.Contains(trail, marker) {
			return nil
		}
		if i := len(trail) - len(marker); i > 0 {
			trail = append(trail[:0], trail[i:]...)
		}

		select {
		case <-retry.C:
			debugf("Server %s is taking a while to boot...", s)
		case <-relog.C:
			printf("Server %s is taking a while to boot...", s)
		case <-ctx.Done():
			return fmt.Errorf("cannot wait for %s to boot: interrupted", s)
		}
	}
	panic("unreachable")
}

func (p *awsProvider) checkLabel(s *awsServer) error {
	_, err := awsParseName(s.d.Name)
	return err
}

type awsInstanceMetadata struct {
	Metadata struct {
		Fingerprint string `json:"fingerprint"`
		Items       []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"items"`
	} `json:"metadata"`
}

func (p *awsProvider) dropStartupScript(s *awsServer) error {
	instance, err := p.metadata(s)
	if err != nil {
		return err
	}
	for i, item := range instance.Metadata.Items {
		if item.Key == "startup-script" {
			instance.Metadata.Items = append(instance.Metadata.Items[:i], instance.Metadata.Items[i+1:]...)
			return p.setMetadata(s, instance)
		}
	}
	return nil
}

func (p *awsProvider) metadata(s *awsServer) (*awsInstanceMetadata, error) {
	var result awsInstanceMetadata
	err := p.doz("GET", "/instances/"+s.d.Name, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("cannot get instance metadata: %v", err)
	}
	return &result, nil
}

func (p *awsProvider) setMetadata(s *awsServer, meta *awsInstanceMetadata) error {
	err := p.doz("POST", "/instances/"+s.d.Name+"/setMetadata", meta.Metadata, nil)
	if err != nil {
		return fmt.Errorf("cannot change instance metadata: %v", err)
	}
	return nil
}

type awsListResult struct {
	Items []awsServerData
}

var awsLabelWarning = true

func (p *awsProvider) removeMachine(ctx context.Context, s *awsServer) error {
	_, err := p.svc.ReleaseAddress(&ec2.ReleaseAddressInput{
		AllocationId: allocationID,
	})
	if err != nil {
		return fmt.Errorf("cannot relelase the instance address: %v", err)
	}

}

func (p *awsProvider) GarbageCollect() error {
	servers, err := p.list()
	if err != nil {
		return err
	}

	now := time.Now()
	haltTimeout := p.backend.HaltTimeout.Duration

	// Iterate over all the running instances
	for _, s := range servers {
		serverTimeout := haltTimeout
		if value, ok := s.d.Labels["halt-timeout"]; ok {
			d, err := time.ParseDuration(strings.TrimSpace(value))
			if err != nil {
				printf("WARNING: Ignoring bad aws server %s halt-timeout label: %q", s, value)
			} else {
				serverTimeout = d
			}
		}

		if serverTimeout == 0 {
			continue
		}

		printf("Checking %s...", s)

		runningTime := now.Sub(s.d.Created)
		if runningTime > serverTimeout {
			printf("Server %s exceeds halt-timeout. Shutting it down...", s)
			err := p.removeMachine(context.Background(), s)
			if err != nil {
				printf("WARNING: Cannot garbage collect %s: %v", s, err)
			}
		}
	}
	return nil
}

type awsOperation struct {
	Name          string
	Zone          string
	OperationType string
	TargetLink    string
	TargetID      string
	Status        string // PENDING, RUNNING or DONE
	StatusMessage string
	User          string // "system" or user email
	Progress      int
	InsertTime    time.Time
	StartTime     time.Time
	EndTime       time.Time
	SelfLink      string

	Error struct {
		Errors []awsOperationError
	}
}

type awsOperationError struct {
	Code     string
	Location string
	Message  string
}

func (op *awsOperation) err() error {
	for _, e := range op.Error.Errors {
		return fmt.Errorf("%s", strings.ToLower(string(e.Message[0]))+e.Message[1:])
	}
	return nil
}

func (p *awsProvider) operation(name string) (*awsOperation, error) {
	var result awsOperation
	err := p.doz("GET", "/operations/"+name, nil, &result)
	if err != nil && result.Name == "" {
		return nil, fmt.Errorf("cannot get operation details: %v", err)
	}
	return &result, nil
}

func (p *awsProvider) waitOperation(ctx context.Context, s *awsServer, verb, opname string) (*awsOperation, error) {
	debugf("Waiting for %s to %s...", s, verb)

	timeout := time.After(3 * time.Minute)
	retry := time.NewTicker(5 * time.Second)
	defer retry.Stop()

	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for %s to %s", s, verb)

		case <-retry.C:
			op, err := p.operation(opname)
			if err != nil {
				return nil, fmt.Errorf("cannot %s %s: %s", verb, s, err)
			}
			if op.Status == awsDone {
				err := op.err()
				if err != nil {
					err = fmt.Errorf("cannot %s %s: %s", verb, s, err)
				}
				return op, err
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("cannot %s %s: interrupted", verb, s)
		}
	}
	panic("unreachable")
}

func (p *awsProvider) checkKey() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.keyChecked {
		return p.keyErr
	}

	var err error

	if p.gproject() == awsMissingProject || p.gzone() == awsMissingZone {
		err = fmt.Errorf("location for %q backend must use the <aws project>/<compute zone> format", p.backend.Name)
	}

	if err == nil && p.client == nil {
		ctx := context.Background()
		if strings.HasPrefix(p.backend.Key, "{") {
			var cfg *jwt.Config
			cfg, err = aws.JWTConfigFromJSON([]byte(p.backend.Key), awsScope)
			if err == nil {
				p.client = oauth2.NewClient(ctx, cfg.TokenSource(ctx))
			}
		} else {
			os.Setenv("aws_APPLICATION_CREDENTIALS", p.backend.Key)
			p.client, err = aws.DefaultClient(context.Background(), awsScope)
		}
	}
	if err == nil {
		err = p.dofl("GET", "/zones", nil, nil, noCheckKey)
	}
	if err != nil {
		err = &FatalError{err}
	}

	p.keyChecked = true
	p.keyErr = err
	return err
}

const (
	awsMissingProject = "MISSING-PROJECT"
	awsMissingZone    = "MISSING-ZONE"
)

func (p *awsProvider) aproject() string {
	if i := strings.Index(p.backend.Location, "/"); i > 0 {
		return p.backend.Location[:i]
	}
	return awsMissingProject
}

func (p *awsProvider) azone() string {
	if i := strings.Index(p.backend.Location, "/"); i > 0 && i+1 < len(p.backend.Location) {
		return p.backend.Location[i+1:]
	}
	return awsMissingZone
}

type awsResult struct {
	Kind  string
	Error struct {
		Code    int
		Message string
		Status  string
		Errors  []awsError
	}
}

type awsError struct {
	Domain  string
	Reason  string
	Message string
}


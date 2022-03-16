package spread

import (
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/ec2"
    "github.com/aws/aws-sdk-go/service/ec2/ec2iface"

	"golang.org/x/net/context"

	"strconv"
)

func Amazon(p *Project, b *Backend, o *Options) Provider {
	return &amazonProvider{
		project: p,
		backend: b,
		options: o,

		imagesCache: make(map[string]*amazonImagesCache),
	}
}

type amazonProvider struct {
	project *Project
	backend *Backend
	options *Options

	amazonProject string
	amazonZone    string

	svc ec2iface.EC2API

	mu sync.Mutex

	keyChecked bool
	keyErr     error

	imagesCache map[string]*amazonImagesCache
}

type amazonServer struct {
	p *amazonProvider
	d amazonServerData

	system  *System
	address string
}

type amazonServerData struct {
	Name    string
	Plan    string    `json:"machineType"`
	Status  string    `yaml:"-"`
	Created time.Time `json:"creationTimestamp"`

	Labels map[string]string `yaml:"-"`
}

func (d *amazonServerData) cleanup() {
	if i := strings.LastIndex(d.Plan, "/"); i >= 0 {
		d.Plan = d.Plan[i+1:]
	}
}

func (s *amazonServer) String() string {
	if s.system == nil {
		return s.d.Name
	}
	return fmt.Sprintf("%s (%s)", s.system, s.d.Name)
}

func (s *amazonServer) Label() string {
	return s.d.Name
}

func (s *amazonServer) Provider() Provider {
	return s.p
}

func (s *amazonServer) Address() string {
	return s.address
}

func (s *amazonServer) System() *System {
	return s.system
}

func (s *amazonServer) ReuseData() interface{} {
	return &s.d
}

const (
	amazonStaging      = "STAGING"
	amazonProvisioning = "PROVISIONING"
	amazonRunning      = "RUNNING"
	amazonStopping     = "STOPPING"
	amazonStopped      = "STOPPED"
	amazonSuspending   = "SUSPENDING"
	amazonTerminating  = "TERMINATED"

	amazonPending = "PENDING"
	amazonDone    = "DONE"
)

func (p *amazonProvider) Backend() *Backend {
	return p.backend
}

func (p *amazonProvider) Reuse(ctx context.Context, rsystem *ReuseSystem, system *System) (Server, error) {
	s := &amazonServer{
		p:       p,
		address: rsystem.Address,
		system:  system,
	}
	err := rsystem.UnmarshalData(&s.d)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal amazon reuse data: %v", err)
	}
	return s, nil
}

func (p *amazonProvider) Allocate(ctx context.Context, system *System) (Server, error) {
	s, err := p.createMachine(ctx, system)
	if err != nil {
		return nil, err
	}

	printf("Allocated %s.", s)
	return s, nil
}

func (s *amazonServer) Discard(ctx context.Context) error {
	return s.p.removeMachine(ctx, s)
}

const amazonStartupScript = `
#cloud-config

runcmd:
 - echo root:%s | chpasswd
 - sed -i 's/^\s*#\?\s*\(PermitRootLogin\|PasswordAuthentication\)\>.*/\1 yes/' /etc/ssh/sshd_config
 - pkill -o -HUP sshd || true
`
const amazonReadyMarker = "MACHINE-IS-READY"
const amazonNameLayout = "Jan021504.000000"
const amazonDefaultPlan = "t4g.micro"

type amazonImage struct {
	Project string
	Name    string
	Family  string
	Terms   []string
}

type amazonImagesCache struct {
	mu     sync.Mutex
	ready  bool
	images []amazonImage
	err    error
}

func (p *amazonProvider) createMachine(ctx context.Context, system *System) (*amazonServer, error) {
	debugf("Creating new amazon server for %s...", system.Name)

    plan := amazonDefaultPlan
	if system.Plan != "" {
		plan = system.Plan
	}

	image := system.Image

	sess, err := session.NewSession(&aws.Config{
        Region: aws.String(p.azone())},
    )

    // Create EC2 service client
    p.svc = ec2.New(sess)

    cloudconfig := fmt.Sprintf(amazonStartupScript, p.options.Password)
    userdata := base64.StdEncoding.EncodeToString([]byte(cloudconfig))

	runResult, err := p.svc.RunInstances(&ec2.RunInstancesInput{
        // An Amazon Linux AMI ID for t2.micro instances in the us-west-2 region
        ImageId:        aws.String(image),
        InstanceType:   aws.String(plan),
        SecurityGroups: []*string{aws.String("spread"),},        
        MinCount:       aws.Int64(1),
        MaxCount:       aws.Int64(1),
        UserData:       aws.String(userdata),
    })

    if err != nil {
        return nil, &FatalError{fmt.Errorf("Could not create instance", err)}
    }

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
            {
                Key:   aws.String("password"),
                Value: aws.String(p.options.Password),
            },
        },

    })
    if errtag != nil {
    	return nil, &FatalError{fmt.Errorf("cannot allocate new amazon server %s: %v", runResult.Instances[0].InstanceId, errtag)}
    }

    s := &amazonServer{
		p: p,
		d: amazonServerData{
			Name:    *runResult.Instances[0].InstanceId,
			Plan:    plan,
			Status:  amazonProvisioning,
			Created: time.Now(),
		},

		system: system,
	}

	input := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(s.d.Name),
		},
	}
	if err == nil {
		err = p.svc.WaitUntilInstanceRunning(input)
	}
	if err != nil {
		if p.removeMachine(ctx, s) != nil {
			return nil, &FatalError{fmt.Errorf("cannot allocate or deallocate (!) new amazon server %s: %v", s, err)}
		}
		return nil, &FatalError{fmt.Errorf("cannot allocate new amazon server %s: %v", s, err)}
	}

	describeResult, err := p.svc.DescribeInstances(input)
	s.address = *describeResult.Reservations[0].Instances[0].PublicIpAddress
	printf("Waiting for %s to boot at %s...", s, s.address)
	if err == nil {
		err = p.svc.WaitUntilInstanceStatusOk(&ec2.DescribeInstanceStatusInput{
		InstanceIds: []*string{
			aws.String(s.d.Name),
		},
	})
	}

	if err != nil {
		if p.removeMachine(ctx, s) != nil {
			return nil, &FatalError{fmt.Errorf("cannot allocate or deallocate (!) new amazon server %s: %v", s, err)}
		}
		return nil, &FatalError{fmt.Errorf("cannot retrieve if for the new amazon server %s: %v", s, err)}
	}

	return s, nil
}

func (p *amazonProvider) list() ([]*amazonServer, error) {
	debug("Listing available amazon instances...")
	sess, err := session.NewSession(&aws.Config{
        Region: aws.String(p.azone())},
    )

    // Create EC2 service client
    p.svc = ec2.New(sess)


	input := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:spread"),
				Values: []*string{
					aws.String("true"),
				},
			},
		},
	}

	describeResult, err := p.svc.DescribeInstances(input)
	if err != nil {
		return nil, &FatalError{fmt.Errorf("cannot list amazon instances: %v", err)}
	}
	reservations := describeResult.Reservations

	// We know each reservation is done for just 1 instance
	instances := make([]*amazonServer, 0, len(reservations))
	for _, reservation := range reservations {
		d := amazonServerData{
			Name: *reservation.Instances[0].InstanceId,
			Created: *reservation.Instances[0].LaunchTime,
		}
		instances = append(instances, &amazonServer{p: p, d: d})
	}

	return instances, nil
}

func (p *amazonProvider) removeMachine(ctx context.Context, s *amazonServer) error {
	_, err := p.svc.TerminateInstances(&ec2.TerminateInstancesInput{
		InstanceIds: []*string{
			aws.String(s.d.Name),
		},
	})
	if err != nil {
		return fmt.Errorf("cannot terminate the instance: %v", s.d.Name)
	}
	return nil
}

func (p *amazonProvider) GarbageCollect() error {
	instances, err := p.list()
	if err != nil {
		return err
	}

	now := time.Now()
	haltTimeout := p.backend.HaltTimeout.Duration

	// Iterate over all the running instances
	for _, s := range instances {
		serverTimeout := haltTimeout
		if value, ok := s.d.Labels["halt-timeout"]; ok {
			d, err := time.ParseDuration(strings.TrimSpace(value))
			if err != nil {
				printf("WARNING: Ignoring bad Amazon instances %s halt-timeout label: %q", s, value)
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

type amazonOperation struct {
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
		Errors []amazonOperationError
	}
}

type amazonOperationError struct {
	Code     string
	Location string
	Message  string
}

func (op *amazonOperation) err() error {
	for _, e := range op.Error.Errors {
		return fmt.Errorf("%s", strings.ToLower(string(e.Message[0]))+e.Message[1:])
	}
	return nil
}

const (
	amazonMissingProject = "MISSING-PROJECT"
	amazonMissingZone    = "MISSING-ZONE"
)

func (p *amazonProvider) aproject() string {
	if i := strings.Index(p.backend.Location, "/"); i > 0 {
		return p.backend.Location[:i]
	}
	return amazonMissingProject
}

func (p *amazonProvider) azone() string {
	if i := strings.Index(p.backend.Location, "/"); i > 0 && i+1 < len(p.backend.Location) {
		return p.backend.Location[i+1:]
	}
	return amazonMissingZone
}

type amazonResult struct {
	Kind  string
	Error struct {
		Code    int
		Message string
		Status  string
		Errors  []amazonError
	}
}

type amazonError struct {
	Domain  string
	Reason  string
	Message string
}


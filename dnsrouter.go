package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fsouza/go-dockerclient"
	"github.com/miekg/dns"
)

const (
	Prefix = "dnsrouter_"
	port   = 12345
)

var dockerClient *docker.Client

func getDocker() *docker.Client {
	if dockerClient == nil {
		var err error
		dockerClient, err = docker.NewClient("unix:///var/run/docker.sock")
		if err != nil {
			log.Fatal(err)
		}
	}
	return dockerClient
}

type Config struct {
	Name        string
	Hostnames   []string
	Dockername  string
	MaxIdleTime time.Duration
}

func (c *Config) String() string {
	return fmt.Sprintf("{%s for %s (idle %.0fs)}", c.Name, c.Dockername, c.MaxIdleTime.Seconds())
}

func (c *Config) GenerateServeDNS(hostname string) func(dns.ResponseWriter, *dns.Msg) {
	if len(hostname) > 0 {
		if hostname[len(hostname)-1] != '.' {
			hostname += "."
		}
	}

	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		ip, err := c.GetOrLaunchInstance()
		if err != nil {
			// TODO: error handling
			log.Println("Error in GetOrLaunchInstance:", err)
			w.Close()
			return
		}

		rr := new(dns.A)
		rr.Hdr = dns.RR_Header{Name: hostname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(c.MaxIdleTime.Seconds())}
		rr.A = ip

		m.Answer = []dns.RR{rr}
		w.WriteMsg(m)
	}
}

func (c *Config) GetOrLaunchInstance() (net.IP, error) {
	d := getDocker()

	hostConfig := &docker.HostConfig{
		RestartPolicy: docker.AlwaysRestart(),
	}

	container, err := d.InspectContainer(Prefix + c.Name)
	if err != nil {
		if _, ok := err.(*docker.NoSuchContainer); ok {
			container, err = createContainer(d, c)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	if !container.State.Running {
		err = d.StartContainer(container.ID, hostConfig)
		if err != nil {
			return nil, err
		}

		container, err = d.InspectContainer(container.ID)
		if err != nil {
			return nil, err
		}
	}

	if container.NetworkSettings == nil {
		return nil, fmt.Errorf("I don't know what the network settings are ...")
	}

	ip := net.ParseIP(container.NetworkSettings.IPAddress)

	return ip, nil
}

func readConfig(filename string) (conf []*Config, err error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	s := string(b)
	lines := strings.Split(s, "\n")

	var currentEntry *Config
	for lineIndex, line := range lines {
		line = strings.Trim(line, "\r")

		if len(line) == 0 || len(clean(line)) == 0 {
			continue
		}

		if line[0:2] != "  " {
			currentEntry = new(Config)
			conf = append(conf, currentEntry)

			cleanline := clean(line)
			currentEntry.Name = cleanline
			currentEntry.Hostnames = []string{cleanline}
			continue
		}

		if currentEntry == nil {
			return nil, fmt.Errorf("Namespace required at line %d", lineIndex+1)
		}

		lineSplit := strings.SplitN(line, ":", 2)
		if len(lineSplit) <= 1 || len(clean(lineSplit[1])) == 0 {
			return nil, fmt.Errorf("Value missing at line %d", lineIndex+1)
		}

		switch clean(lineSplit[0]) {
		case "docker":
			currentEntry.Dockername = clean(lineSplit[1])
		case "alias":
			currentEntry.Hostnames = append(currentEntry.Hostnames, clean(lineSplit[1]))
		case "idle":
			currentEntry.MaxIdleTime, err = time.ParseDuration(clean(lineSplit[1]))
			if err != nil {
				return nil, fmt.Errorf("Error parsing idle (%v) at line %d", err, lineIndex+1)
			}
		default:
			return nil, fmt.Errorf("Unknown key: %v at line %d", clean(lineSplit[0]), lineIndex+1)
		}
	}

	return
}

func clean(str string) string {
	return strings.Trim(str, " ")
}

var config []*Config

var hostConfig = &docker.HostConfig{
	RestartPolicy: docker.AlwaysRestart(),
}

func createContainer(client *docker.Client, conf *Config) (*docker.Container, error) {
	// Ensure the image is available
	_, err := client.InspectImage(conf.Dockername)
	if err != nil {
		if err == docker.ErrNoSuchImage {
			// We can try to pull it?
			splitTag := strings.SplitN(conf.Dockername, ":", 2)
			if len(splitTag) == 1 {
				splitTag = append(splitTag, "latest")
			}
			pullOpts := docker.PullImageOptions{
				Tag:        splitTag[1],
				Repository: splitTag[0],
			}
			authConfig := docker.AuthConfiguration{}

			err = client.PullImage(pullOpts, authConfig)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	// Now create it
	config := &docker.Config{
		Image: conf.Dockername,
	}
	opts := docker.CreateContainerOptions{
		Name:       Prefix + conf.Name,
		Config:     config,
		HostConfig: hostConfig,
	}

	return client.CreateContainer(opts)
}

func main() {
	var err error

	config, err = readConfig("config.dns")
	if err != nil {
		log.Fatal(err)
	}

	// Cleanup all running containers
	client := getDocker()
	list, err := client.ListContainers(docker.ListContainersOptions{All: true})
	if err != nil {
		log.Fatal(err)
	}

ConfigLoop:
	for _, conf := range config {
		created := false

		// See if it already exists
		for _, c := range list {
			for _, name := range c.Names {
				if strings.Index(name, "/"+Prefix+conf.Name) == 0 {
					// Inspect to get info about it
					container, err := client.InspectContainer(c.ID)
					if err != nil {
						// Didn't exist, so let's create it and we're done
						if _, ok := err.(*docker.NoSuchContainer); ok {
							container, err = createContainer(client, conf)
							if err != nil {
								log.Println("Error creating container at startup:", err)
								continue ConfigLoop
							}
							created = true
							continue
						} else {
							log.Println("Error inspecting container at startup:", err)
							continue ConfigLoop
						}
					}

					// Stop it if it's running
					if container.State.Running {
						err = client.StopContainer(c.ID, 1)
						if err != nil {
							log.Println("Error stopping container at startup:", err)
							continue ConfigLoop
						}
					}

					// Get information about the image the container is based on - if it's the same one
					outdated := false

					image, err := client.InspectImage(conf.Dockername)
					if err != nil {
						outdated = true
					} else {
						outdated = container.Created.Before(image.Created)
					}

					// Recreate it if it's outdated
					if outdated {
						log.Println(conf.Dockername, container.Image)
						// So delete
						removeOpts := docker.RemoveContainerOptions{ID: c.ID}
						err = client.RemoveContainer(removeOpts)
						if err != nil {
							log.Println("Error removing container at startup:", err)
							continue ConfigLoop
						}

						// And create
						_, err = createContainer(client, conf)
						if err != nil {
							log.Println("Error creating container at startup:", err)
							continue ConfigLoop
						}
					}
					created = true
				}
			}
		}

		if !created {
			_, err = createContainer(client, conf)
			if err != nil {
				log.Println("Error creating container at startup:", err)
				continue ConfigLoop
			}
		}
	}
	log.Println("Initialized")

	for _, c := range config {
		for _, hostname := range c.Hostnames {
			dns.HandleFunc(hostname, c.GenerateServeDNS(hostname))
		}
	}

	go dns.ListenAndServe("localhost:"+strconv.Itoa(port), "tcp", nil)
	go dns.ListenAndServe("localhost:"+strconv.Itoa(port), "udp", nil)

	log.Printf("Server listening on port %d on TCP and UDP\n", port)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
forever:
	for {
		select {
		case s := <-sig:
			log.Printf("Signal (%d) received, stopping\n", s)
			break forever
		}
	}
}

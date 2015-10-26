# dnsrouter

Upon receiving a DNS lookup request, it starts the according docker container and returns the docker IP as a result. 

Docker containers will be closed automatically after a user-set period of time. (Yet to implement this)

This will create the same effect as AWS Lambda or Google AppEngine. 

Keep in mind that this is an MIT license. You can (and should) use this to change it to your desires. For instance:

* Connect to a remote docker instance;
* Connect to multiple docker instances, and start containers where needed (load balancing). 

## Usage
Enter your preferences in `config.dns`, then run `dnsrouter.go`. 

It is thought of to work behind a Nginx Reverse Proxy. Set its DNS to this `dnsserver` (port `12345`), and docker
containers will be started on-the-fly. 

Keep in mind:

* If containers do not exist, they will be created from the image. 
* If containers do exist, but the image was updated since the last start of `dnsrouter`, the container is destroyed and recreated. 
* If containers do not exist, and the image does not exist, the image will be `docker pull`ed. 
* If containers do not exist, and the image does not exist, and `docker pull` doesn't work, it logs an error. 

## Status
It's mostly a proof-of-concept, so no guarantees. 

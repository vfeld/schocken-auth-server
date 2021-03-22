# Architecture Overview

This project uses the hexagonal architecture as outlined here:
https://alistair.cockburn.us/hexagonal-architecture/

The terminology in nutshell is as follows:
- Domain: the business model
- Ports:  the interfaces used to interact with the domain from the outside
- Adapter: adapt the ports to the outside world e.g. towards a http server or a data base
- Hexagon: an aggregation of adapter, ports and domains belong together.

Finally there exists the application which wires hexagon together using dependency injection. 

A characteristic of this archicture is to have well defined bounderies and responsibilities by knowing what is in- or outside of the hexagon. Dependencies are explicitly managed through the use of adapters, ports and the fact that one is only allowed to interact with the domain through ports.

For the schocken-auth-server the domain provides an authentication and user management API. The domain offers its service through the authentication service port. The http rest adapter uses this port to offer an http rest api with help of the actix_web crate. The authentication service domain uses the postgress data base adapter through the authentication store port. The postgres adapter is realized with the help of the sqlx crate. All ports are modeled as rust traits using the async_trait crate.

The adapters and domain are unit tested independently using "crate test". To test the components independently the dependencies are mocked with help of the mock-it crate. 

Concurrency is achieved using rust async/await. Parallelism can be achieved by setting the number of worker threads the actix_web server spawns. The domain is stateless and relies for maintenance of state data and state synchronization on the database backend. 


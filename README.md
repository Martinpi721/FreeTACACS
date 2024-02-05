# FreeTACACS

This is a Python project implementing a TACACS+ (Terminal Access Controller
Access-Control System Plus) server using the Twisted framework. TACACS+ is
a network protocol that provides centralized authentication, authorization,
and accounting (AAA) services.

## Overview

The TACACS+ server is built using the Twisted framework, a powerful and
event-driven networking engine. The server supports authentication and
authorization of network devices and services that use the TACACS+ protocol.

## Features

* TACACS+ Protocol Support: Implements the TACACS+ protocol for secure and
  reliable communication with network devices.
* Authentication: Provides authentication services for network users using TACACS+.
* Authorization: Implements authorization checks to control access to network
  resources based on user roles and permissions.
* Twisted Framework: Leverages the Twisted framework for efficient and scalable
  event-driven networking.

## Getting Started

### Prerequisites

* Python 3.x
* Twisted Framework

### Installation

1. Clone the repository:

```bash
git clone https://github.com/Martinpi721/FreeTACACS.git
cd FreeTACACS
```

2. Install dependencies:

```bash
pip install -r requirement.txt
```

3. Install

```bash
pip install .
```

### Usage

1. Run the TACACS+ server:

```bash
# Run the service in the foreground
sudo twistd --pidfile=/var/run/freetacacs.pid \
            --nodaemon freetacacs-start \
            --config /etc/freetacacs/config.yaml

# Run the service as a daemon
sudo twistd --syslog
            --pidfile=/var/run/freetacacs.pid \
            freetacacs-start \
            --config /etc/freetacacs/config.yaml
```

2. Configure network equipment to use server instance

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please
open an issue. Pull requests are also appreciated.

## License

This project is licensed under the GPLv2 License - see the LICENSE file for details.

## Acknowledgments

* Thanks to the Twisted team for providing a robust framework for building networked
  applications.

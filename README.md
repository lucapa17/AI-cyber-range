# Master-Thesis
This repository contains Dockerfiles and Docker Compose configuration for creating and running containers to simulate various attack scenarios on remote classifiers. Follow the instructions below to build and run these containers.

## Prerequisites

Make sure you have Docker installed on your system. If not, you can download and install Docker from [Docker's official website](https://www.docker.com/get-started).

## Build and Run Instructions

### Building the Images

- #### Option 1: Building the Images
  To build the Docker images for the containers locally, navigate to the root directory of this repository and run the following commands:
  ```bash
  docker build -t image-server DockerServer
  docker build -t image-client DockerClient
  ```

- #### Option 2: Pulling Images from Docker Hub
  Alternatively, you can pull them directly from Docker Hub using the following commands:
  ```bash
  docker pull lucapa17/image-server
  docker pull lucapa17/image-client
  ```
  If you choose option 2, remember to update the image names in the Docker Compose files from `image-server` and `image-client` to `lucapa17/image-server` and `lucapa17/image-client` respectively.
### Running the Containers

After building the images or pulling them from Docker Hub, you can run the containers using Docker Compose files to simulate different attack scenarios on remote classifiers. Remember to place the goodware and malware samples in the `data/goodware_samples` and `data/malware_samples` folders, respectively. If you wish to modify the attacks and use different strategies and parameters, you can modify the contents of the `query` folder.


- #### Scenario 1: Evasion Attack against Malconv hosted on a Server
  ```bash
  docker compose -f docker-compose-malconv.yml up
  ```
- #### Scenario 2: Evasion Attack against EMBER GBDT hosted on a Server
  ```bash
  docker compose -f docker-compose-malconv.yml up
  ```
- #### Scenario 3: Evasion Attack against VirusTotal
  ```bash
  docker compose -f docker-compose-virustotal.yml up
  ```
  For Scenario 3, make sure to modify the queries in the `query/evasion-virustotal` folder, specifying your own API key for VirusTotal.
- #### Scenario 4: Evasion Attack against MetaDefender
  ```bash
  docker compose -f docker-compose-metadefender.yml up
  ```
  For Scenario 4, make sure to modify the queries in the `query/evasion-metadefender` folder, specifying your own API key for MetaDefender.

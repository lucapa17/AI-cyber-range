# Master-Thesis
This repository contains Dockerfiles and Docker Compose configuration for creating and running containers to simulate various attack scenarios on remote classifiers. Follow the instructions below to build and run these containers.

## Prerequisites

Make sure you have Docker installed on your system. If not, you can download and install Docker from [Docker's official website](https://www.docker.com/get-started).

You also need to download the Ember dataset and extract its features as indicated in the [Ember GitHub repository](https://github.com/elastic/ember). You can automate these operations by running the following command:
```bash
python download_extract_ember_dataset.py
```
This script will download the dataset and extract its features into the `data` folder automatically.
## Build and Run Instructions

### Building the Images

- #### Option 1: Building the Images
  To build the Docker images for the containers locally, navigate to the root directory of this repository and run the following commands:
  ```bash
  docker build -t image-server DockerServer
  docker build -t image-client-evasion DockerClientEvasion
  docker build -t image-client-poisoning DockerClientPoisoning
  ```

- #### Option 2: Pulling Images from Docker Hub
  Alternatively, you can pull them directly from Docker Hub using the following commands:
  ```bash
  docker pull lucapa17/image-server
  docker pull lucapa17/image-client-evasion
  docker pull lucapa17/image-client-poisoning
  ```
  If you choose option 2, remember to update the image names in the Docker Compose files from `image-server`, `image-client-evasion`  and `image-client-poisoning` to `lucapa17/image-server` , `lucapa17/image-client-evasion`  and `lucapa17/image-client-poisoning` respectively.
### Running the Containers

After building the images or pulling them from Docker Hub, you can run the containers using Docker Compose files to simulate different attack scenarios on remote classifiers. Remember to place the goodware and malware samples in the `data/goodware_samples` and `data/malware_samples` folders, respectively.

- ### Evasion attacks
  Evasion attacks within the following scenarios are based on the black-box attack framework named GAMMA (Genetic Adversarial Machine Learning Malware Attack), as described in the article [Functionality-preserving Black-box Optimization of Adversarial Windows Malware](https://arxiv.org/abs/2003.13526), specifically using the section injection manipulation.
  If you wish to modify the attacks and use different strategies and parameters, you can modify the contents of the `query` folder.
  - #### Scenario 1: Evasion Attack against Malconv hosted on a Server
    ```bash
    docker compose -f docker-compose-malconv-evasion.yml up
    ```
  - #### Scenario 2: Evasion Attack against EMBER GBDT hosted on a Server
    ```bash
    docker compose -f docker-compose-emberGBDT-evasion.yml up
    ```
  - #### Scenario 3: Evasion Attack against VirusTotal
    ```bash
    docker compose -f docker-compose-virustotal-evasion.yml up
    ```
    For Scenario 3, make sure to modify the queries in the `query/evasion-virustotal` folder, specifying your own API key for VirusTotal.
  - #### Scenario 4: Evasion Attack against MetaDefender
    ```bash
    docker compose -f docker-compose-metadefender-evasion.yml up
    ```
    For Scenario 4, make sure to modify the queries in the `query/evasion-metadefender` folder, specifying your own API key for MetaDefender.
- ### Poisoning attacks
  The following scenarios represent poisoning attacks initiated by a client against the server. In these scenarios, the client modifies either goodware or malware samples before sending them to the server . The server sends the newly collected samples to an external antivirus service for proper labeling and then fine-tunes its anti-malware detection model. Subsequently, the client sends new samples without any modifications. The client's objective is to increase the number of false positives or false negatives after the poisoning. To adjust the parameters for the scenarios, please modify the environment variables in the Docker Compose files.
  - #### Scenario 1: Poisoning Attack against against EMBER GBDT hosted on a Server to increase false negative rates
    ```bash
    docker compose -f docker-compose-emberGBDT-poisoning-false-negatives.yml up
    ```
    In Scenario 1, the antivirus labeling service is provided by another server hosting a Malconv Classifier.
  - #### Scenario 2: Poisoning Attack against against EMBER GBDT hosted on a Server to increase false positive rates
    ```bash
    docker compose -f docker-compose-emberGBDT-poisoning-false-positives.yml up
    ```
    In Scenario 2, the antivirus labeling service used is Metadefender. Ensure to update the Docker Compose Files with your Metadefender API key(s).

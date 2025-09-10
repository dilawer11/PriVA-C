# PriVA-C: Artifact README

This repository contains the artifact for the paper:

**PriVA-C: Defending Voice Assistants from Fingerprinting Attacks**  
Authors: Dilawer Ahmed, Aafaq Sabir, Ahsan Zafar, Anupam Das 
Conference/Journal: PETS, 2026

## Setup

### Hardware Requirements
The setup has been tested using the following setup

1) OS: Ubuntu 22.04
2) RAM: 64GB
3) CPU: 32cores
4) GPU: 2x4090
5) Software: Docker

### Docker Image Build

In the base directory (the directory containing the Dockerfile) run the following command to build the docker image

```bash
docker build . -t privac
```

### Run the Docker Image

```bash
docker run -e IOTBASE=/PriVA-C -e PYTHONPATH=/PriVA-C/src -v /path/to/PriVA-C:/PriVA-C -it privac bash

```

## Datasets

The datasets can be accessed at the following link: https://privacy-datahub.csc.ncsu.edu/publication/ahmed-pets-2026/

### Alexa SDK Dataset
This dataset was collected using the Alexa SDK. It is the primary dataset used for Alexa evaluations

### Siri Dataset (Apple Homepod)
This dataset was used to measure the performance for Siri across the paper

### Google Dataset (Google Nest)
This dataset was used to measure the performance for Google Assistant across the paper

### Alexa Dataset (Amazon Echo)
This dataset was used to measure the performance for Alexa device

## Dataset Setup

After downloading each dataset place the zip file in the data subdirectory and unzip it using the following command from inside the data directory

```bash
unzip dataset_name.zip
```

For each dataset first it needs to be converted from PCAP to CSV and then divided into windows where each window contains only traffic for a certain activity.

To convert the raw PCAP files to CSV run the following command inside the docker container

```bash
python3 src/scripts/PCAP2CSV.py -i data/dataset_name/
```

After the PCAP files have been converted run the following command to create windows

```bash
python3 src/scripts/CSV2Windows.py -i data/dataset_name/
```

## Testing Baseline Performance: Spying Attack (Optional)

To test the baseline performance of a defense first features need to extracted from the CSV windows. Since each dataset can have multiple different windows, we need to provide the unique window identifier to the script. The time will be in the format DD-MMM-YYY_HHMM e.g 08-Sep-2025_0702 (by default it will run on the last windows extracted). We can use the following command to do this

```bash
python3 src/scripts/SpyingFeatures.py -i data/dataset_name/ -s DD-MMM-YYYY_HHMM
```

This will create a feature file and we can then train the classifier and evaluate it's performance using the following command

```bash
python3 src/scripts/SpyingTrain.py -i data/dataset_name/ -s DD-MMM-YYYY_HHMM
```


## Contact
For questions or issues, please email authors or open an issue on GitHub.

## License
This artifact is released under the MIT license. See `LICENSE` for details.
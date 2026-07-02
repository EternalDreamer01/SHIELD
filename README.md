# SHIELD: Assessing Security-by-Design in Federated Data Spaces using Attack Graphs

## Abstract

Federated data spaces relate to collaborative environments, where smart communities exchange messages for providing services, efficiency, and decision-making processes. The huge number of nowadays discovered vulnerabilities makes federated data spaces highly exposed to cyber attacks. Existing solutions to secure them focus on messaging protocol protection (e.g., using cryptographic means), but this is not enough. Attackers may exploit application and platform vulnerabilities to perpetrate detrimental circumstances (e.g., availability disruption of community services). To this aim, we propose SHIELD, a security-by-design solution for federated data spaces, which leverages attack graphs and trust computation to mitigate the risks posed by attacks exploiting vulnerabilities of devices in smart communities. Mitigation is accomplished by proactively assessing system weaknesses, and enabling security messaging measures before reaching detrimental attacks.
A prototype implementation of SHIELD using publish/subscribe as a messaging mechanism is experimentally evaluated over a real architecture in a V2X (Vehicle-to-Everything) scenario.

## Requirements

* Install  the required packages: `pip3 install -r requirements.txt`

* **Docker** is required which you can find [here](https://docs.docker.com/engine/install/ubuntu/).

* **Mosquitto**: to install Mosquitto, run `sudo apt update -y && sudo apt install -y mosquitto mosquitto-clients`

We highly suggest using **Ubuntu** to facilitate reproducibility.

## Installation Instruction

### 1. Docker Network instantiation

1. Disable host mosquito service: `sudo systemctl disable --now mosquitto`
1. Make sure port 1883 is free: `sudo lsof -i :1883`, otherwise killing processes is required.
1. Instantiate the Mosquitto broker:
```sh
docker run --rm -it -d --name broker -p 1883:1883 --network bridge -v ./src/srcEx/config/broker.conf:/mosquitto/config/mosquitto.conf eclipse-mosquitto
```

4. (Optional) Check if everything worked smoothly: `docker logs broker`, then you should find something like this:

```
mosquitto version 2.0.18 starting
Config loaded from /mosquitto/config/mosquitto.conf.
Opening ipv4 listen socket on port 1883.
mosquitto version 2.0.18 running
```

### 2. Run experiments

1. Launch the following commands in a first terminal (for subscribers):

```sh
cd src/srcEx
python3 buildNet.py
# The terminal stays idle waiting for the other terminal to send messages (Subscriber service)
```

2. In a second terminal launch `python3 src/main.py` and wait for the experiment to finish. Expect 15mn, you can customize the duration with the `td` variable, expressed in seconds.
	* The message `GRAPHS PRINTED, SUCCESS` indicates the successful completion of the experiment.

2. You can find the assessment results in `experiments/plot` folder.

## Repository structure

In this repository you will find the following folders:

- **src**: contains all the source files to run the code.
- **data**: contains the inputs to reproduce the experiment. You can add your custom networks according to the JSON format present in this folder.
- **experiments**: contains the assessment output, including data and plots.

### Experiment

| File | Description | Expect |
|-|-|-|
| `agtime` | Trend of the computation time with the increasing number of patched vulnerabilities | Decreasing |
| `community_matrix` | Messaging accuracy based on the number of messages retrieved by the devices in the different communities ; defining trust | High TP (>50%),<br/>Low FP/FN (<50%),<br/>No TN (0%) |
| `length` | ??? Average attack path length from source to target | SHIELD to be lower /better |
| `paths` | Number of attack paths | SHIELD to be lower /better |
| `response_time` | Average end-to-end response time | SHIELD to be lower /better |
| `risk` | Average risk | SHIELD to be lower /better |

## Functioning

1. Publish MQTT/TCP messages (?????)
1. Retrieve network and generate attack graph
1. Generate paths, analyze them, calculate trust and mitigations, and save the attack surface and unsubscriptions for each device
1. Save the unsubscriptions
1. Run the experiment by pusbling the messages again


## Cite this work

If using this code for research purposes, please cite:

```bibtex
@inproceedings{10.1145/3672608.3707797,
	author = {Palma, Alessandro and Papadakis, Nikolaos and Bouloukakis, Georgios and Garcia-Alfaro, Joaquin and Sospetti, Mattia and Magoutis, Kostas},
	title = {SHIELD: Assessing Security-by-Design in Federated Data Spaces Using Attack Graphs},
	year = {2025},
	isbn = {9798400706295},
	publisher = {Association for Computing Machinery},
	address = {New York, NY, USA},
	url = {https://doi.org/10.1145/3672608.3707797},
	doi = {10.1145/3672608.3707797},
	abstract = {Federated data spaces allow organizations to share and control their own data across various domains, but their exposure to cyber attacks has increased due to a surge in newly discovered vulnerabilities. Existing solutions to secure them focus on messaging protocol protection (e.g., using cryptographic means), but this is not sufficient. Attackers may exploit additional vulnerabilities to cause significant issues (e.g., disrupting the availability of services). To this end, we propose SHIELD, a security-by-design approach for federated data spaces, which leverages attack graphs and trust computation to mitigate the risks of cyber attacks. Mitigation is accomplished by proactively assessing the data spaces' weaknesses and implementing security messaging measures to prevent detrimental attacks. A prototype implementation of SHIELD using publish/subscribe as a messaging mechanism is experimentally evaluated over a real architecture in a V2X (Vehicle-to-Everything) scenario.},
	booktitle = {Proceedings of the 40th ACM/SIGAPP Symposium on Applied Computing},
	pages = {480–489},
	numpages = {10},
	keywords = {federated data spaces, security by design, attack graph, trust management},
	location = {Catania International Airport, Catania, Italy},
	series = {SAC '25}
}
```

## Acknowledgements
This work is supported by the Horizon Europe project DI-Hydro under grant agreement number 101122311 and by the Avvio alla Ricerca Sapienza grant AR2241902B426269. We acknowledge as well support from the European Union’s Horizon 2020 research and innovation program under the Marie Skłodowska-Curie grant agreement No. 10100782.

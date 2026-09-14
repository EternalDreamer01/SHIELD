import os
import nvdlib, time, json, uuid, random
import pandas as pd
import argparse
from rich.progress import track

MITIGATION_FILE = "data/NIST/cwe_mitigation.csv"

import gzip
import json
import re
from pathlib import Path
from functools import lru_cache
from rich.progress import track

NVD_DIR = Path("~/.cache/cve-bin-tool/").expanduser()

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def extract_cve_id(record):
    """Extract the CVE ID from either NVD 1.1 or 2.0 format."""
    # NVD 2.0
    try:
        return record["cve"]["id"]
    except KeyError:
        pass

    # NVD 1.1
    try:
        return record["cve"]["CVE_data_meta"]["ID"]
    except KeyError:
        return None


def extract_records(data):
    """Return CVE records from either NVD JSON schema."""
    # NVD 2.0
    if "vulnerabilities" in data:
        return data["vulnerabilities"]

    # NVD 1.1
    if "CVE_Items" in data:
        return data["CVE_Items"]

    return []


@lru_cache(maxsize=None)
def load_year(year):
    """
    Load all matching feeds for one year.

    NVD 2.0 is preferred when the same CVE exists in both formats.
    """
    records_by_id = {}

    feed_paths = [
        NVD_DIR / f"nvdcve-2.0-{year}.json.gz",
        NVD_DIR / f"nvdcve-1.1-{year}.json.gz",
    ]

    for feed_path in feed_paths:
        if not feed_path.exists():
            continue

        print(f"Loading {feed_path.name}...")

        with gzip.open(feed_path, "rt", encoding="utf-8") as f:
            data = json.load(f)

        for record in extract_records(data):
            cve_id = extract_cve_id(record)

            if cve_id:
                # setdefault keeps the 2.0 record if it was loaded first
                records_by_id.setdefault(cve_id.upper(), record)

    return records_by_id


def read_cve_ids(input_files: list[str]):
    """Yield normalized CVE IDs from text files."""
    for input_file in input_files:
        with open(input_file, encoding="utf-8") as f:
            for line in f:
                # Remove comments
                line = line.split("#", 1)[0]

                # Find CVE IDs even if the line contains extra text
                match = CVE_RE.search(line)

                if match:
                    yield match.group(0).upper()


def find_cve(cve_id):
    """Find one CVE in the appropriate NVD feed."""
    year = int(cve_id.split("-", 2)[1])
    records = load_year(year)
    return records.get(cve_id.upper())

def get_cwes(cve_record) -> list[str]:
    """
    Extract CWE values from either an NVD 2.0 or NVD 1.1 CVE record.
    """

    # NVD 2.0 records usually look like:
    # {"cve": {"id": "...", "weaknesses": [...]}}
    cve_data = cve_record.get("cve", cve_record)

    cwes = []

    # NVD 2.0:
    # cve.weaknesses[].description[].value
    for weakness in cve_data.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value")

            if value:
                cwes.append(value.strip())

    # NVD 1.1:
    # cve.problemtype.problemtype_data[].description[].value
    problemtype = cve_data.get("problemtype", {})

    for problemtype_data in problemtype.get("problemtype_data", []):
        for description in problemtype_data.get("description", []):
            value = description.get("value")

            if value:
                cwes.append(value.strip())

    # Remove duplicates while preserving order
    return list(dict.fromkeys(cwes))

def normalize_cwe(value) -> str:
    value = str(value).strip().upper()

    if value.startswith("CWE-"):
        value = value[4:]

    return value

def getCweMitigation(cve_record) -> list[dict[str, str]]:
	cve_data = cve_record.get("cve", cve_record)
	cveid = cve_data.get("id", "")

	cwes = get_cwes(cve_record)

	if not cwes:
		print(f"No CWEs found for {cveid}")
		return []

	df = pd.read_csv(MITIGATION_FILE, sep=",")
	df.columns = df.columns.str.strip()

	# NVD: "CWE-22" -> "22"
	normalized_cwes = {
		normalize_cwe(cwe)
		for cwe in cwes
	}

	# CSV: 22 -> "22"
	df["_normalized_cwe"] = df["CWE-ID"].map(normalize_cwe)

	# print(f"CWEs for {cveid}: {cwes}")
	# print(f"Normalized CWEs: {normalized_cwes}")
	# print(f"CSV CWE IDs: {df['_normalized_cwe'].unique()}")

	mitigations = df[
		df["_normalized_cwe"].isin(normalized_cwes)
	][
		["CWE-ID", "phase", "strategy"]
	]

	records = mitigations.to_dict("records")
	
	for record in records:
		record["cve"] = cveid
		if not isinstance(record["phase"], str):
			record["phase"] = "Unknown"
		if not isinstance(record["strategy"], str):
			record["strategy"] = "Unknown"

	# print(f"Mitigations for {cveid}:", records)

	return records


def generate_vuln_files(cve_files: list[str]|None):
	### Electric Vehicle
	vuln_vehicle=[]
	vulnid_vehicle=[]
	cve_vehicle = []

	os.makedirs("data/NIST/", exist_ok=True)
	
	if cve_files:
		for cve_id in read_cve_ids(cve_files):
			record = find_cve(cve_id)

			if record is None:
				print(f"  Not found in local NVD feeds: {cve_id}")
				continue
			print(f"+ {cve_id}")
			record["id"] = cve_id
			cve_vehicle.append(record)
		# for cve_file in track(cve_files, description="Loading CVEs..."):
		# 	with open(cve_file) as f:
		# 		for cve_id in track(f.readlines(), description=f"Processing CVE file: {cve_file}"):
		# 			cve_id = cve_id.split('#', 1)[0].strip()
		# 			print(f"+ {cve_id}")
		# 			print(nvdlib.searchCVE(cveId=cve_id))
		# 			return
	else:
		cve_vehicle = nvdlib.searchCVE(keywordSearch='Vehicle Service Management System')
	for cve in cve_vehicle:
		vulnid_vehicle.append(
			cve["id"] if isinstance(cve, dict) else cve.id
		)
		vuln_vehicle.append(cve)

	
	with open("data/NIST/vehicle.json", "w") as outfile:
		json_data = json.dumps({"vulnerabilities":vuln_vehicle
					},default=lambda o: o.__dict__, indent=2)
		outfile.write(json_data)

	### Charging stations
	vuln_charging=[] #vuln_vehicle
	vulnid_charging=[] #vulnid_vehicle
	cve_charging = nvdlib.searchCVE(keywordSearch='evlink v3.4.0.1')
	for cve in cve_charging: 
		vulnid_charging.append(cve.id)
		vuln_charging.append(cve)
	
	with open("data/NIST/charging.json", "w") as outfile:
		json_data = json.dumps({"vulnerabilities":vuln_charging
					},default=lambda o: o.__dict__, indent=2)
		outfile.write(json_data)

	# time.sleep(6)
	### MQTT
	vuln_mqtt=[] #vuln_vehicle
	vulnid_mqtt=[] #vulnid_vehicle
	cve_mqtt = nvdlib.searchCVE(keywordSearch='mqtt')
	for cve in cve_mqtt: 
		vulnid_mqtt.append(cve.id)
		vuln_mqtt.append(cve)

	with open("data/NIST/broker.json", "w") as outfile:
		json_data = json.dumps({"vulnerabilities":vuln_mqtt
					},default=lambda o: o.__dict__, indent=2)
		outfile.write(json_data)

	# time.sleep(6)
	### Redis
	vuln_redis=[] #vuln_vehicle
	vulnid_redis=[] #vulnid_vehicle
	cve_redis = nvdlib.searchCVE(keywordSearch='redis 6.2.6')
	for cve in cve_redis: 
		vulnid_redis.append(cve.id)
		vuln_redis.append(cve)

	# time.sleep(6)
	### Django
	vuln_django=[]
	vulnid_django=[]
	cve_django = nvdlib.searchCVE(keywordSearch='django 3.2')
	for cve in cve_django: 
		vulnid_django.append(cve.id)
		vuln_django.append(cve)

	with open("data/NIST/management.json", "w") as outfile:
		json_data = json.dumps({"vulnerabilities":vuln_redis+vuln_django
					},default=lambda o: o.__dict__, indent=2)
		outfile.write(json_data)

	# time.sleep(6)
	### Postgres
	vuln_postgres=[] #vuln_vehicle
	vulnid_postgres=[] # vulnid_vehicle
	cve_postgres = nvdlib.searchCVE(keywordSearch='postgresql 15.5')
	for cve in cve_postgres: 
		vulnid_postgres.append(cve.id)
		vuln_postgres.append(cve)
	
	# time.sleep(6)
	### Elasticsearch
	vuln_elastic=[]
	vulnid_elastic=[]
	cve_elastic = [] # nvdlib.searchCVE(keywordSearch='elasticsearch 7.17')
	for cve in cve_elastic: 
		vulnid_elastic.append(cve.id)
		vuln_elastic.append(cve)
	
	# time.sleep(6)
	### filebrowser
	vuln_file=[]
	vulnid_file=[]
	cve_file = [] # nvdlib.searchCVE(keywordSearch='filebrowser 2.22')
	for cve in cve_file: 
		vulnid_file.append(cve.id)
		vuln_file.append(cve)

	with open("data/NIST/storage.json", "w") as outfile:
		json_data = json.dumps({"vulnerabilities":vuln_elastic+vuln_file+vuln_postgres
					},default=lambda o: o.__dict__, indent=2)
		outfile.write(json_data)

	return

def build_v2x_net(num_charging=1,num_management=1,num_storage=1,num_vehicle=1):
	vulnid_mqtt=[]
	mitig_mqtt=[]
	with open("data/NIST/broker.json") as f: vuln_broker = json.load(f)["vulnerabilities"]
	vuln_broker_filter = [] # random.sample(vuln_broker,10)
	for v in vuln_broker_filter:
		vulnid_mqtt.append(v["id"])
		mitig_mqtt+=getCweMitigation(v)
	
	# broker_hosts=[]
	# for i in range(0,num_broker):
	#	 broker_hosts.append({
	#		 'id': str(uuid.uuid4()),
	#		 'hostname':"Broker",
	#		 'community': "broker",
	#		 'network_interfaces':[{
	#			 'ipaddress':"192.168.0.1",
	#			 'macaddress':"ad:49:52:ba:19:76",
	#			 'ports':[{
	#				 "number": 1883,
	#				 "state": "open",
	#				 "protocol": "MQTT",
	#				 "services": [{
	#					 "name": "pubsub",
	#					 "cve_list": vulnid_mqtt
	#				 }]
	#			 }]
	#		 }]
	#	 })

	
	vulnid_charging=[]
	mitig_charging=[]
	with open("data/NIST/charging.json") as f: vuln_charging = json.load(f)["vulnerabilities"]
	for v in vuln_charging: 
		vulnid_charging.append(v["id"])
		mitig_charging+=getCweMitigation(v)

	### Charging stations
	charging_hosts=[]
	charging_hostsSOA=[]
	for i in range(0,num_charging):
		iddev=str(uuid.uuid4())
		
		charging_hosts.append({
			'id': iddev,
			'hostname':"Charging Station",
			'community': "charging",
			'network_interfaces':[{
				'ipaddress':"192.168.0.1",
				'macaddress':"ad:49:52:ba:19:76",
				'ports':[{
					"number": 1883,
					"state": "open",
					"protocol": "MQTT",
					"services": [{
						"name": "pubsub",
						"cve_list": vulnid_charging+vulnid_mqtt
					}]
				}]
			}]
		})

		charging_hostsSOA.append({
			'id': iddev,
			'hostname':"Charging Station",
			'community': "charging",
			'network_interfaces':[{
				'ipaddress':"192.168.0.1",
				'macaddress':"ad:49:52:ba:19:76",
				'ports':[{
					"number": 1883,
					"state": "open",
					"protocol": "MQTT",
					"services": [{
						"name": "pubsub",
						"cve_list": vulnid_charging
					}]
				}]
			}]
		})
   

	vulnid_mng=[]
	mitig_mng=[]
	with open("data/NIST/management.json") as f: vuln_mng = json.load(f)["vulnerabilities"]
	for v in vuln_mng: 
		vulnid_mng.append(v["id"])
		mitig_mng+=getCweMitigation(v)

	management_hosts=[]
	management_hostsSOA=[]
	for i in range(0,num_management):
		iddev=str(uuid.uuid4())
		management_hosts.append({
			'id': iddev,
			'hostname':"Management Platform",
			'community': "management",
			'network_interfaces':[{
				'ipaddress':"192.168.0.1",
				'macaddress':"ad:49:52:ba:19:76",
				'ports':[{
					"number": 8080,
					"state": "open",
					"protocol": "TCP",
					"services": [{
						"name": "tcp",
						"cve_list": vulnid_mng+vulnid_mqtt
					}]
				}]
			}]
		})
		management_hostsSOA.append({
			'id': iddev,
			'hostname':"Management Platform",
			'community': "management",
			'network_interfaces':[{
				'ipaddress':"192.168.0.1",
				'macaddress':"ad:49:52:ba:19:76",
				'ports':[{
					"number": 8080,
					"state": "open",
					"protocol": "TCP",
					"services": [{
						"name": "tcp",
						"cve_list": vulnid_mng
					}]
				}]
			}]
		})

	vulnid_store=[]
	mitig_store=[]
	with open("data/NIST/storage.json") as f: vuln_store = json.load(f)["vulnerabilities"]
	for v in vuln_store: 
		vulnid_store.append(v["id"])
		mitig_store+=getCweMitigation(v)
	
	storage_hosts=[]
	storage_hostsSOA=[]
	for i in range(0,num_storage):
		iddev=str(uuid.uuid4())
		storage_hosts.append({
			'id': iddev,
			'hostname':"Storage Device",
			'community': "vehicle",
			'network_interfaces':[{
				'ipaddress':"192.168.0.1",
				'macaddress':"ad:49:52:ba:19:76",
				'ports':[{
					"number": 8080,
					"state": "open",
					"protocol": "TCP",
					"services": [{
						"name": "tcp",
						"cve_list": vulnid_store+vulnid_mqtt
					}]
				}]
			}]
		})
		storage_hostsSOA.append({
			'id': iddev,
			'hostname':"Storage Device",
			'community': "vehicle",
			'network_interfaces':[{
				'ipaddress':"192.168.0.1",
				'macaddress':"ad:49:52:ba:19:76",
				'ports':[{
					"number": 8080,
					"state": "open",
					"protocol": "TCP",
					"services": [{
						"name": "tcp",
						"cve_list": vulnid_store
					}]
				}]
			}]
		})

	vulnid_vehicle=[]
	mitig_vehicle=[]
	with open("data/NIST/vehicle.json") as f: vuln_vehicle = json.load(f)["vulnerabilities"]
	for v in vuln_vehicle: 
		vulnid_vehicle.append(v["id"])
		mitig_vehicle+=getCweMitigation(v)

	### Vehicles
	vehicle_hosts=[]
	vehicle_hostsSOA=[]
	for i in range(0,num_vehicle):
		iddev=str(uuid.uuid4())
		
		vehicle_hosts.append({
			'id': iddev,
			'hostname':"Electric Vehicle",
			'community': "vehicle",
			'network_interfaces':[{
				'ipaddress':"192.168.0.1",
				'macaddress':"ad:49:52:ba:19:76",
				'ports':[{
					"number": 1883,
					"state": "open",
					"protocol": "MQTT",
					"services": [{
						"name": "pubsub",
						"cve_list": vulnid_vehicle+vulnid_mqtt
					}]
				}]
			}]
		})

		vehicle_hostsSOA.append({
			'id': iddev,
			'hostname':"Electric Vehicle",
			'community': "vehicle",
			'network_interfaces':[{
				'ipaddress':"192.168.0.1",
				'macaddress':"ad:49:52:ba:19:76",
				'ports':[{
					"number": 1883,
					"state": "open",
					"protocol": "MQTT",
					"services": [{
						"name": "pubsub",
						"cve_list": vulnid_vehicle
					}]
				}]
			}]
		})

	edges=[]
	for h1 in management_hosts:
		h1id=h1["id"]
		for h2 in management_hosts:
			h2id=h2["id"]
			if h1id!=h2id:
				edges.append([h1id,h2id])
				edges.append([h2id,h1id])

	for h1 in storage_hosts:
		h1id=h1["id"]
		for h2 in storage_hosts:
			h2id=h2["id"]
			if h1id!=h2id:
				edges.append([h1id,h2id])
				edges.append([h2id,h1id])

	for hcharg in charging_hosts:
		hcid=hcharg["id"]
		# for hstore in storage_hosts:
		#	 hstid=hstore["id"]
		#	 edges.append([hcid,hstid])
		for hmng in management_hosts:
			hmngid=hmng["id"]
			edges.append([hcid,hmngid])
			edges.append([hmngid,hcid])

	for hveh in vehicle_hosts:
		hcid=hveh["id"]
		# for hstore in storage_hosts:
		#	 hstid=hstore["id"]
		#	 edges.append([hcid,hstid])
		for hmng in management_hosts:
			hmngid=hmng["id"]
			edges.append([hcid,hmngid])
			edges.append([hmngid,hcid])
	
	for hstore in storage_hosts:
		hstid=hstore["id"]
		for hmng in management_hosts:
			hmngid=hmng["id"]
			edges.append([hstid,hmngid])
			# edges.append([hmngid,hstid])

	with open("data/v2x_network.json", "w") as outfile:
		json_data = json.dumps({
			"devices": charging_hosts+management_hosts+storage_hosts,
			"vulnerabilities":vuln_charging+vuln_broker_filter+vuln_mng+vuln_store,
			"edges":edges,
			"mitigations":mitig_charging+mitig_mqtt+mitig_mng+mitig_store
		},default=lambda o: o.__dict__, indent=2)
		outfile.write(json_data)

	with open("data/v2x_networkSOA.json", "w") as outfile:
		json_data = json.dumps({
			"devices": charging_hostsSOA+management_hostsSOA+storage_hostsSOA,
			"vulnerabilities":vuln_charging+vuln_mng+vuln_store,
			"edges":edges,
			"mitigations":mitig_charging+mitig_mng+mitig_store
		},default=lambda o: o.__dict__, indent=2)
		outfile.write(json_data)

if __name__ == "__main__":
	argparse = argparse.ArgumentParser()
	argparse.add_argument("--generate-vuln-files", nargs='*', help="Generate vulnerability files for each device type. Optional files of CVEs can be provided")
	args = argparse.parse_args()
	

	try:
		if args.generate_vuln_files is not None:
			generate_vuln_files(args.generate_vuln_files)

		else:
			build_v2x_net(10,7,7,5)
	except KeyboardInterrupt:
		print("Process interrupted by user. Exiting...")

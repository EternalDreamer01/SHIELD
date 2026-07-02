import json, csv, os
from attack_graph import generate_ag_model, generate_paths, analyze_paths
from mitigation import calculate_trust, mitigations_by_dev, mitigation_to_pubsub
from srcEx.publish import runPublish
from srcEx.pub import Pub
from srcEx.sub import Sub
import threading
import time
from analysis_experiments import runGraphs
from rich.progress import track


if __name__ == "__main__":
    numberExp=2 # number of experiments
    td=1 # experiment duration

    pubs=runPublish()

    print('STARTING THE EXPERIMENT BEFORE THE SECURITY MODULE')

	##################################################
	# 1. Publish messages
	##################################################
    for _ in range(numberExp):
        threads=[]
        for pub,client in pubs:
            threads.append(threading.Thread(target=pub.publish, args=(td,client,)))
        
        for thread in threads:
            thread.start()

        time.sleep(td+2)
        
        #pub=Pub("end", topic='endtopic', broker='127.0.0.1', port=1883)
        #pub.publishEnd()
    
	##################################################
	# 2. Retrieve network and generate attack graph
	##################################################
    file_network="data/v2x_network.json"

    os.makedirs("experiments/data", exist_ok=True)
    os.makedirs("experiments/plot", exist_ok=True)

    with open(file_network) as nf:
        devices = json.load(nf)["devices"]
    devs=[]
    for d in devices: devs.append(d["id"])

    AG = generate_ag_model(file_network)

	######################################################################
	# 3. Generate paths, analyze them, calculate trust and mitigations,
	#    and save the attack surface and unsubscriptions for each device
	######################################################################
    tot_surface=[]
    tot_unsubscribe=[]
    for id in track(devs):
        src_dev=[id]
        paths = generate_paths(file_network, AG, src_dev)
        risk_vals = analyze_paths(paths,file_network)
        trust_matrix = calculate_trust(risk_vals)
        
        mitigations_dev = mitigations_by_dev(file_network,src_dev[0])
        attack_surface, unsubscriptions = mitigation_to_pubsub(trust_matrix,risk_vals,mitigations_dev, pubs)

        tot_surface.append(attack_surface)
        tot_unsubscribe.append(unsubscriptions)

    data_unsub=[]

	######################################################################
	# 4. Save the unsubscriptions
	######################################################################
    for elem in track(tot_unsubscribe):
        for keypath in elem.keys():
            src=keypath.split("#")[0]
            dst=keypath.split("#")[1]
            val=elem[keypath]
            data_unsub.append({
                "src":src,
                "dst":dst,
                "unsubscription":val
            })

    keys = data_unsub[0].keys()
    with open('experiments/data/unsubscriptions.csv', 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(data_unsub)
    
    time.sleep(td+2)
    pubendsec=Pub("endsec", topic='endtopic', broker='127.0.0.1', port=1883)
    pubendsec.publishEnd()

    print('STARTING THE EXPERIMENT')

	######################################################################
	# 5. Run the experiment by pusbling the messages again
	######################################################################
    for _ in track(range(numberExp)):
        threads=[]
        for pub,client in pubs:
            threads.append(threading.Thread(target=pub.publishSecExp, args=(td,client,)))
        
        for thread in threads:
            thread.start()
        for thread in track(threads):
            thread.join()
        time.sleep(td+2)  # flush the messages queue
               
    print('EXPERIMENT FINISHED, PRINTING GRAPHS')
    runGraphs()
    print('GRAPHS PRINTED, SUCCESS')

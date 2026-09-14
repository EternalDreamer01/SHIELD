import json
import networkx as nx
def get_risk_by_vuln(vuln):
    """
    Supports both:

    NVD 2.0:
        vuln["cve"]["metrics"]

    NVD 1.1:
        vuln["impact"]
    """

    likelihood = 1
    impact = 1

    # NVD 2.0 stores the CVE data inside "cve".
    # NVD 1.1 stores it directly in the item.
    cve = vuln.get("cve", vuln)

    # ---------------------------------------------------------
    # NVD 2.0
    # ---------------------------------------------------------
    metrics = cve.get("metrics", {})

    # Keep CVSS v2 as the default
    if "cvssMetricV2" in metrics:
        metric_v2 = metrics["cvssMetricV2"][0]

        likelihood = metric_v2.get(
            "exploitabilityScore",
            likelihood,
        )
        impact = metric_v2.get(
            "impactScore",
            impact,
        )

    # Prefer CVSS v3.1 over v3.0 and v2
    if "cvssMetricV30" in metrics:
        metric_v3 = metrics["cvssMetricV30"][0]

        likelihood = metric_v3.get(
            "exploitabilityScore",
            likelihood,
        )
        impact = metric_v3.get(
            "impactScore",
            impact,
        )

    if "cvssMetricV31" in metrics:
        metric_v3 = metrics["cvssMetricV31"][0]

        likelihood = metric_v3.get(
            "exploitabilityScore",
            likelihood,
        )
        impact = metric_v3.get(
            "impactScore",
            impact,
        )

    # ---------------------------------------------------------
    # NVD 1.1
    # ---------------------------------------------------------
    legacy_impact = vuln.get("impact", {})

    # CVSS v2
    if "baseMetricV2" in legacy_impact:
        metric_v2 = legacy_impact["baseMetricV2"]

        likelihood = metric_v2.get(
            "exploitabilityScore",
            likelihood,
        )
        impact = metric_v2.get(
            "impactScore",
            impact,
        )

    # CVSS v3
    # This intentionally comes after v2 so v3 takes priority.
    if "baseMetricV3" in legacy_impact:
        metric_v3 = legacy_impact["baseMetricV3"]

        likelihood = metric_v3.get(
            "exploitabilityScore",
            likelihood,
        )
        impact = metric_v3.get(
            "impactScore",
            impact,
        )

    return likelihood, impact


def get_vulns_by_hostid(devid,devices):
    cve_list=[]
    for host in devices:
        if host["id"] == devid:
            for iface in host["network_interfaces"]:
                if "ports" in iface.keys():
                    for port in iface["ports"]:
                        for service in port["services"]:
                            cve_list.append(service["cve_list"])
                if "applications" in iface.keys():
                    for app in iface["applications"]:
                        cve_list.append(app["cve_list"])
            return list(set([item for sublist in cve_list for item in sublist]))
    return []

"""
These functions checks the pre-post condition chaining
"""
def get_req_privilege(str_priv):
    if str_priv == "NONE" or str_priv == "LOW":
        return "NONE"
    elif str_priv == "SINGLE" or str_priv == "MEDIUM":
        return "USER"
    else:
        return "ROOT"
def get_gain_privilege(isroot, isuser, req_privilege):
    if isroot == "UNCHANGED" and isuser == "UNCHANGED":
        return get_req_privilege(req_privilege)
    elif isroot == True:
        return "ROOT"
    elif isuser == True:
        return "USER"
    else:
        return "ROOT"
def retrieve_privileges(vulnID, vulnerabilities):
    """
    Supports:

    NVD 2.0:
        vulnerabilities[].cve

    NVD 1.1:
        CVE_Items[]
    """

    for vuln in vulnerabilities:
        # NVD 2.0 uses vuln["cve"]
        # NVD 1.1 stores the CVE directly in the item
        cve = vuln.get("cve", vuln)

        # Get the CVE ID from either format
        current_id = (
            cve.get("id")
            or cve.get("CVE_data_meta", {}).get("ID")
        )

        if current_id != vulnID:
            continue

        # ---------------------------------------------------------
        # NVD 2.0 metrics
        # ---------------------------------------------------------
        metrics = cve.get("metrics", {})

        # NVD 2.0 CVSS v2
        if "cvssMetricV2" in metrics:
            metric_v2 = metrics["cvssMetricV2"][0]
            cvss_v2 = metric_v2.get("cvssData", {})

            authentication = cvss_v2.get("authentication", "NONE")

            priv_required = get_req_privilege(authentication)

            priv_gained = get_gain_privilege(
                metric_v2.get("obtainAllPrivilege", False),
                metric_v2.get("obtainUserPrivilege", False),
                authentication,
            )

            return vuln, priv_required, priv_gained

        # NVD 2.0 CVSS v3.0 or v3.1
        metric_v3 = None

        if "cvssMetricV31" in metrics:
            metric_v3 = metrics["cvssMetricV31"][0]
        elif "cvssMetricV30" in metrics:
            metric_v3 = metrics["cvssMetricV30"][0]

        if metric_v3:
            cvss_v3 = metric_v3.get("cvssData", {})

            privileges_required = cvss_v3.get(
                "privilegesRequired",
                "NONE",
            )
            scope = cvss_v3.get("scope", "UNCHANGED")

            priv_required = get_req_privilege(privileges_required)

            priv_gained = get_gain_privilege(
                scope,
                scope,
                privileges_required,
            )

            return vuln, priv_required, priv_gained

        # ---------------------------------------------------------
        # NVD 1.1 metrics
        # ---------------------------------------------------------
        impact = vuln.get("impact", {})

        # NVD 1.1 CVSS v2:
        # vuln["impact"]["baseMetricV2"]
        if "baseMetricV2" in impact:
            metric_v2 = impact["baseMetricV2"]
            cvss_v2 = metric_v2.get("cvssV2", {})

            authentication = cvss_v2.get("authentication", "NONE")

            priv_required = get_req_privilege(authentication)

            priv_gained = get_gain_privilege(
                metric_v2.get("obtainAllPrivilege", False),
                metric_v2.get("obtainUserPrivilege", False),
                authentication,
            )

            return vuln, priv_required, priv_gained

        # NVD 1.1 CVSS v3:
        # vuln["impact"]["baseMetricV3"]
        if "baseMetricV3" in impact:
            metric_v3 = impact["baseMetricV3"]
            cvss_v3 = metric_v3.get("cvssV3", {})

            privileges_required = cvss_v3.get(
                "privilegesRequired",
                "NONE",
            )
            scope = cvss_v3.get("scope", "UNCHANGED")

            priv_required = get_req_privilege(privileges_required)

            priv_gained = get_gain_privilege(
                scope,
                scope,
                privileges_required,
            )

            return vuln, priv_required, priv_gained

        # The CVE exists but has no supported CVSS metrics
        return vuln, "NONE", "NONE"

    # The CVE ID was not found
    return vulnID, "NONE", "NONE"


def generate_ag_model(network_file, writeonfile=False):
    with open(network_file) as nf:
        content_network = json.load(nf)
    reachability_edges = content_network["edges"]
    vulnerabilities = content_network["vulnerabilities"]
    devices = content_network["devices"]
        
    G = nx.DiGraph()
    for r_edge in reachability_edges:
        src=r_edge[0]
        dst=r_edge[1]
        dev_vulns=get_vulns_by_hostid(dst,devices)
        for v in dev_vulns:
            vuln,precondition,postcondition = retrieve_privileges(v,vulnerabilities)

            req_node = precondition+"@"+str(src)
            gain_node = postcondition+"@"+str(dst)
            vuln_id = v+'@'+str(dst)
            
            if req_node not in G.nodes(): G.add_node(req_node, type="privilege", color="green")
            if gain_node not in G.nodes(): G.add_node(gain_node, type="privilege", color="green")
            if vuln_id not in G.nodes(): G.add_node(vuln_id, type="vulnerability", color="blue")
            if (req_node, vuln_id) not in G.edges() and (vuln_id, req_node) not in G.edges(): G.add_edge(req_node, vuln_id)
            if (vuln_id, gain_node) not in G.edges() and (gain_node, vuln_id) not in G.edges(): G.add_edge(vuln_id, gain_node)

    for node_1 in G.nodes():
        if "@" not in node_1: continue
        priv1,hostid1 = node_1.split("@")
        for node_2 in G.nodes():
            if node_1 == node_2 or "@" not in node_2: continue
            priv2,hostid2 = node_2.split("@")
            if hostid1 != hostid2: continue
            
            if priv1 == "ROOT" and priv2 == "USER": G.add_edge(node_1, node_2)
            if priv1 == "USER" and priv2 == "NONE": G.add_edge(node_1, node_2)
            if priv1 == "ROOT" and priv2 == "NONE": G.add_edge(node_1, node_2)

    if writeonfile: nx.write_graphml_lxml(G, "data/agtest.graphml")
    return G

def compute_risk_analysis(vuln_ids, vulns_list):
    impact_scores=[]
    exploit_scores=[]
    for v_curr in vuln_ids:
        for v_gt in vulns_list:
            if v_gt["id"] in v_curr:
                likelihood,impact=get_risk_by_vuln(v_gt)
                exploit_scores.append(likelihood )
                impact_scores.append(impact)
    
    lambda_exploit_scores = []
    for expl_s in exploit_scores:
        lambda_exploit_scores.append(1/expl_s)
    
    lik_risk = sum(lambda_exploit_scores) if len(lambda_exploit_scores)>0 else 0
    imp_risk = (impact_scores[len(impact_scores)-1])/max(impact_scores) if len(impact_scores)>0 and max(impact_scores)>0 else 0

    if lik_risk>1: lik_risk=1
    if imp_risk>1: imp_risk=1

    return {
        "impact": imp_risk,
        "likelihood": lik_risk,
        "risk":(imp_risk)*(lik_risk),
    }

def generate_paths(network_file, G, src_ids=None, target_ids=None):
    if not target_ids: target_ids=[]
    node_types = nx.get_node_attributes(G,"type")

    with open(network_file) as nf:
        network = json.load(nf)
    vulnerabilities=network["vulnerabilities"]
    edges=network["edges"]

    for e in edges:
        if e[0] in src_ids:
            target_ids.append(e[1])
    
    sources,goals=[],[]
    for n in G.nodes:
        if "@" in n and node_types[n] != "vulnerability": 
            privilege,hostid=n.split("@")
            if hostid in src_ids: sources.append(n)
            elif hostid in target_ids: goals.append(n)
            # if not src_ids and not hostid in target_ids: sources.append(n)
            # if src_ids and hostid in src_ids: sources.append(n)
    
    list_risk_values=[]
    for s in sources:
        for t in goals:
            try: current_paths = list(nx.all_shortest_paths(G, source=s, target=t))
            except nx.NetworkXNoPath: current_paths=[]
            for single_path in current_paths:
                vulns_path=[]
                path_trace=''
                for node_p in single_path:
                    path_trace=path_trace+'#'+node_p
                    if node_types[node_p] == "vulnerability":
                        vulns_path.append(node_p)
                if len(vulns_path)<=0: continue
                risk_val = compute_risk_analysis(vulns_path, vulnerabilities)
                risk_val['path']=path_trace
                list_risk_values.append(risk_val)
            if len(list_risk_values)<=0: continue
            
    return list_risk_values

def check_communities(source,target,network_file):
    with open(network_file) as nf:
        devices = json.load(nf)["devices"]

    comSrc,comDst="",""
    for dev in devices:
        if dev["id"]==source: comSrc=dev["community"]
        if dev["id"]==target: comDst=dev["community"]
    return comSrc==comDst

def calculate_communities(path, network_file):
    with open(network_file) as nf:
        devices = json.load(nf)["devices"]
    
    all_communities=[]
    for node in path:
        if "@" not in node or "CVE" in node: continue
        dev_id=node.split("@")[1]
        for dev in devices:
            if dev["id"]==dev_id: all_communities.append(dev["community"])
    return len(set(all_communities))

def analyze_paths(attack_paths, networkfile):
    clients={}
    for path in attack_paths:
        trace_components=path["path"].split("#")
        source=trace_components[1].split("@")[1]
        target=trace_components[len(trace_components)-1].split("@")[1]
        key_path=source+"#"+target
        
        communities=calculate_communities(trace_components, networkfile)
        isSameCommunity=check_communities(source,target, networkfile)
        if key_path not in clients.keys():
            clients[key_path]={
                "count":1,
                "lengths":[len(trace_components)],
                "risks":[path["risk"]],
                "communities":[communities],
                "sameCommunity":isSameCommunity
            }
        else:
            clients[key_path]["count"]+=1
            clients[key_path]["lengths"].append(len(trace_components))
            clients[key_path]["risks"].append(path["risk"])
            clients[key_path]["communities"].append(communities)

    return clients
import requests, json, subprocess, time, os

def get_all_files():
    all_files = []
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    return all_files

def load_and_read_json():
    get_files = get_all_files()
    # get the exe file
    for i in get_files :
        if "data_file" in i:
            return i
    print("ERROR !!!")

def load_and_read_json2():
    get_files = get_all_files()
    # get the exe file
    for i in get_files :
        if "final_report.json" in i:
            return i
    print("ERROR !!!")

def load_and_read_exe():
    get_files = get_all_files()
    # get the exe file
    for i in get_files :
        if ".exe" in i:
            return i
    for i in get_files:
        if not ".json" in i:
            if not ".txt" in i:
                return i
    print("ERROR !!!")
    print("ERROR !!!")

def scan_using_virustotal(hash_id):
    url = f"https://www.virustotal.com/api/v3/files/{hash_id}"

    headers = {
        "accept": "application/json",
        "x-apikey": "f18862dd85b0ec074530c0931faab8b9471df84513c521c282b1b3004ba0095d"
    }
    response = requests.get(url, headers=headers)
    json_object = json.dumps(response.json(), indent=4)

    # saving to final_report.json
    with open("final_report.json", "w") as outfile:
        outfile.write(json_object)

def open_json_file_and_print(hash_file):
    scan_using_virustotal(hash_file)
    file_path = load_and_read_json2()
    with open(file_path) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)
    #print(dictionary["data"]["attributes"]["last_analysis_results"])
    print("[VirusTotal] ~ ")
    try:
        data = []
        desc = []
        for i in dictionary["data"]["attributes"]["last_analysis_results"]:
            data.append(i)
            if dictionary["data"]["attributes"]["last_analysis_results"][i]["category"].lower() in "malicious":
                desc.append(False)
            else:
                desc.append(True)
        return data,desc
    except KeyError:
        return True
    
# Testing the connection :
def connection_testing(auth):
    url = 'https://api.scanii.com/v2.1/ping'
    command = ['curl', '--insecure', '-u', auth, url]
    output = subprocess.check_output(command)


# submitting the file
def Analyse_by_Scanii(auth,file_path):
    url = 'https://api.scanii.com/v2.1/files'
    command = ['curl', '--insecure', '-u', auth, '-F', f'file=@{file_path}', url]
    output = subprocess.check_output(command)
    if "\"findings\" : [ ]" in output.decode('utf-8'):
        return True
    else:
        return False

def analyze_by_intezer(hash_id):
    
    base_url = 'https://analyze.intezer.com/api/v2-0'
    response = requests.post(base_url + '/get-access-token', json={'api_key': '770cf0ce-0e9d-44a5-8162-d141aa2bf795'})
    response.raise_for_status()
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer 770cf0ce-0e9d-44a5-8162-d141aa2bf795"
    }
    headers["Authorization"] = 'Bearer %s' % response.json()['result']
    url = f"https://analyze.intezer.com/api/v2-0/files/{hash_id}"
    response = requests.request("GET", url, headers=headers)
    try:
        if response.json()['result']['verdict'].lower() in "malicious":
            return False
        else:
            return True
    except KeyError:
        return True
    
def solution_deja_existante():
    exe_file = load_and_read_exe()
    with open(load_and_read_json()) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)
    return analyze_by_intezer(dictionary[exe_file]["md5Hash"]), Analyse_by_Scanii('7fc0373b5c9291f2df14f0789274ad17:2ecb7c4f7',exe_file), open_json_file_and_print(dictionary[exe_file]["md5Hash"])

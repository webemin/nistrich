import pandas as pd
from termcolor import colored
import time
from os import system, name
import json

def clear():
 
    if name == 'nt':
        _ = system('cls')
 
    else:
        _ = system('clear')

def read_json_o():
    with open('output.json', 'r') as f:
        data = json.load(f)
    f.close

    f = open("cve_ip_list.txt", "a")

    for i in range(len(data)-1):
        for j in range(len(data[i]['vulns'])):
            if data[i] != "":
                f.write("{}:{}\n".format(data[i]['ip'], data[i]['vulns'][j]))

def file_to_str(file_path):
    file_f = open(file_path, "r", encoding="utf8")
    file_l = file_f.readlines()
    file_str =""

    for file in file_l:
        file_str += file
    
    file_f.close()
    return file_str

def seperate_df(df_sep):
    for item in df_sep.index:
        df_sep.at[item, 'CVSS Severity V3.1'] = str(df_sep.at[item, 'CVSS Severity']).split(' V')[0].split(':')[1]
        df_sep.at[item, 'CVSS Severity V2.0'] = str(df_sep.at[item, 'CVSS Severity']).split(' V')[1].split(':')[1]
        try:
            df_sep.at[item, 'Alert V3.1'] = str(df_sep.at[item, 'CVSS Severity V3.1']).split(' ')[2]
        except:
            df_sep.at[item, 'Alert V3.1'] = 0

        try:
            df_sep.at[item, 'Alert V2.0'] = str(df_sep.at[item, 'CVSS Severity V2.0']).split(' ')[2]
        except:
            df_sep.at[item, 'Alert V2.0'] = 0

    df_sep = df_sep.drop(['CVSS Severity'], axis=1)
    return df_sep

def color_df(df_color):

    for item in df_color.index:

        if df_color.at[item, 'Alert V3.1'] == 'CRITICAL' or df_color.at[item, 'Alert V2.0'] == 'CRITICAL':
            for col in df_color.columns:
                df_color.at[item, col] = colored(df_color.at[item, col], 'magenta')

        elif df_color.at[item, 'Alert V3.1'] == 'HIGH' or df_color.at[item, 'Alert V2.0'] == 'HIGH':
            for col in df_color.columns:
                df_color.at[item, col] = colored(df_color.at[item, col], 'red')

        elif df_color.at[item, 'Alert V3.1'] == 'MEDIUM' or df_color.at[item, 'Alert V2.0'] == 'MEDIUM':
            for col in df_color.columns:
                df_color.at[item, col] = colored(df_color.at[item, col], 'yellow')
        
        elif df_color.at[item, 'Alert V3.1'] == 'LOW' or df_color.at[item, 'Alert V2.0'] == 'LOW':
            for col in df_color.columns:
                df_color.at[item, col] = colored(df_color.at[item, col], 'cyan')

    df_color.columns = [[colored('IP |', 'white'), colored('Vuln ID |', 'white'), colored('CVSS Severity V3.1 |', 'white'), colored('CVSS Severity V2.0 |', 'white'), 
    colored('Alert V3.1 |', 'white'), colored('Alert V2.0 |', 'white')]]

    return df_color[[colored('IP |', 'white'), colored('Vuln ID |', 'white'), colored('CVSS Severity V3.1 |', 'white'), colored('CVSS Severity V2.0 |', 'white')]]


def nist_search(cve_list):

    df_searched = pd.DataFrame(columns=['IP', 'Vuln ID', 'Summary', 'CVSS Severity V3.1', 'CVSS Severity V2.0', 'Alert V3.1', 'Alert V2.0'])
    last = 0
    if len(cve_list[0]) == 0:
        name_of_output = "{}_results.csv".format(time.strftime("%m%d%y_%H%M",time.localtime()))
        f = open(name_of_output, "a")
        f.write("No Vulns Found.")
        f.close()
        exit("No Vulns Found.")

    
    failed_cve = []
    fail_falg = False

    for ip_cve in cve_list:
        if 'CVE' not in ip_cve:
            break
        ip = ip_cve.split(':')[0]
        cve = ip_cve.split(':')[1]
        fail_falg2 = False
        try:
            data_nist = pd.read_html('https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={}&queryType=phrase&search_type=all&isCpeNameSearch=false'.format(str(cve)))
        except:
            fail_falg = True
            fail_falg2 = True
            failed_cve.append(cve)

        if len(data_nist[0]["Vuln ID"]) == 0:
            continue
        df_website = pd.DataFrame(data = data_nist[0])
        df_searched = pd.concat([df_searched, df_website[df_website['Vuln ID'] == cve]])
        df_searched.reset_index(drop=True, inplace=True)
      
        df_searched.at[last, 'IP'] = ip
        last += 1
        clear()
        print("CVEs for each IP address generated via nrich. Searching for CVSS Scores from nvd.nist.org\n\n")
        print(color_df(seperate_df(df_searched[['IP', 'Vuln ID', 'CVSS Severity', 'CVSS Severity V3.1', 'CVSS Severity V2.0', 'Alert V3.1', 'Alert V2.0']])))
        if fail_falg:
            print("\nFailed to fetch CVSS for CVE/CVEs Below:\n")
            for cve in failed_cve:
                print(cve)
        if fail_falg2:
            print("\n\nWaiting for connection")
            time.sleep(3)

    return seperate_df(df_searched[['IP', 'Vuln ID', 'CVSS Severity', 'CVSS Severity V3.1', 'CVSS Severity V2.0', 'Alert V3.1', 'Alert V2.0']])

def main():

    print("nrich is working..")

    read_json_o()

    print("Data fetched properly.")

    try:
        cve_list = file_to_str("./cve_ip_list.txt").split('\n')
    except:
        exit("cve_ip_list.txt file couldn't found.")

    results = nist_search(cve_list)
    results = results.drop(['Alert V3.1', 'Alert V2.0'], axis=1)
    name_of_output = "{}_results.csv".format(time.strftime("%m%d%y_%H%M",time.localtime()))
    results.to_csv(name_of_output, index=False)
    print("\n{} output file has been created.".format(name_of_output))

if __name__ == '__main__':
    main()

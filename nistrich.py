import pandas as pd
from termcolor import colored
import time

def nist_search(cve_list):
    
    df_searched = pd.DataFrame(columns=['Vuln ID', 'Summary', 'CVSS Severity V3.1', 'CVSS Severity V2.0', 'Alert V3.1', 'Alert V2.0'])
    for cve in cve_list:
        data_nist = pd.read_html('https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={}&queryType=phrase&search_type=all&isCpeNameSearch=false'.format(str(cve)))
        #data_nist = pd.read_csv('./data.csv')
        df_website = pd.DataFrame(data = data_nist[0])
        df_searched = pd.concat([df_searched, df_website[df_website['Vuln ID'] == cve]])
        
        time.sleep(5)

    df_searched.reset_index(drop=True, inplace=True)
    return df_searched[['Vuln ID', 'CVSS Severity', 'CVSS Severity V3.1', 'CVSS Severity V2.0', 'Alert V3.1', 'Alert V2.0']]

def seperate_df(df_sep):

    for item in df_sep.index:
        df_sep.at[item, 'CVSS Severity V3.1'] = str(df_sep.at[item, 'CVSS Severity']).split('  ')[0].split(': ')[1]
        df_sep.at[item, 'CVSS Severity V2.0'] = str(df_sep.at[item, 'CVSS Severity']).split('  ')[1].split(': ')[1]
        try:
            df_sep.at[item, 'Alert V3.1'] = str(df_sep.at[item, 'CVSS Severity V3.1']).split(' ')[1]
        except:
            df_sep.at[item, 'Alert V3.1'] = 0

        try:
            df_sep.at[item, 'Alert V2.0'] = str(df_sep.at[item, 'CVSS Severity V2.0']).split(' ')[1]
        except:
            df_sep.at[item, 'Alert V2.0'] = 0

        if df_sep.at[item, 'Alert V3.1'] == 'CRITICAL' or df_sep.at[item, 'Alert V2.0'] == 'CRITICAL':
            for col in df_sep.columns:
                df_sep.at[item, col] = colored(df_sep.at[item, col], 'grey')

        elif df_sep.at[item, 'Alert V3.1'] == 'HIGH' or df_sep.at[item, 'Alert V2.0'] == 'HIGH':
            for col in df_sep.columns:
                df_sep.at[item, col] = colored(df_sep.at[item, col], 'red')

        elif df_sep.at[item, 'Alert V3.1'] == 'MEDIUM' or df_sep.at[item, 'Alert V2.0'] == 'MEDIUM':
            for col in df_sep.columns:
                df_sep.at[item, col] = colored(df_sep.at[item, col], 'yellow')
        
        elif df_sep.at[item, 'Alert V3.1'] == 'LOW' or df_sep.at[item, 'Alert V2.0'] == 'LOW':
            for col in df_sep.columns:
                df_sep.at[item, col] = colored(df_sep.at[item, col], 'cyan')

    df_sep = df_sep.drop(['CVSS Severity'], axis=1)
    df_sep.columns = [[colored('Vuln ID |', 'white'), colored('CVSS Severity V3.1 |', 'white'), colored('CVSS Severity V2.0 |', 'white'), 
    colored('Alert V3.1 |', 'white'), colored('Alert V2.0 |', 'white')]]

    return df_sep[[colored('Vuln ID |', 'white'), colored('CVSS Severity V3.1 |', 'white'), colored('CVSS Severity V2.0 |', 'white')]]

def file_to_str(file_path):
    file_f = open(file_path, "r", encoding="utf8")
    file_l = file_f.readlines()
    file_str =""

    for file in file_l:
        file_str += file
    
    file_f.close()
    return file_str

def main():
    cve_list = file_to_str("a.txt").split('\n')
    result = seperate_df(nist_search(cve_list))
    print(result)

if __name__ == '__main__':
    main()
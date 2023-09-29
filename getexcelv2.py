import os
import requests
import pandas as pd
from pprint import pprint
import re
from datetime import datetime

pd.set_option('display.max_colwidth', None)

xls_file = 'PCST_RQL_listv2_1.xlsx'

token = os.getenv("prisma_token")
headers = {
  'Content-Type': 'application/json; charset=UTF-8',
  'Accept': 'application/json; charset=UTF-8',
  'x-redlock-auth': token
}

# --- Returns search/config results for individual rqls, custom standards

def response_custom(payload):
  url = "https://api0.prismacloud.io/search/config"
  response_json = requests.request("POST", url, headers=headers, data=payload).json()['data']['items']
  return pd.json_normalize([item for item in response_json] )

# --- Returns scan_info results for native standards

def response_native(cloud, section):
  url = f"https://api0.prismacloud.io/resource/scan_info?timeType=to_now&cloud.type={cloud}&policy.complianceStandard=CIS%20v1.3.0%20({cloud})&policy.complianceSection={section}&scan.status=all"
  payload = {}
  response_json = requests.request("GET", url, headers=headers, data=payload).json()['resources']
  return pd.json_normalize([item for item in response_json] )

# --- Creates query to be passed as payload to search/config

def wrap_text(rql):
  rql_str = re.sub(r"(where cloud.type)", r"where cloud.accountgroup = '%s' AND cloud.type", rql)
  return  '{\r\n  \"query\":\"' + rql_str + '\",\r\n  \"timeRange\":{\"type\":\"to_now\",\"value\":\"epoch\"},\r\n  \"heuristicSearch\":true\r\n}'

def result(accgr, **params):

# --- Columns list from csv output xls file

  dfcolumns = ['Description', 'Account ID', 'Policy name', 'Asset ID', 'Asset Type', \
             'Compliant or non compliant', 'Account group name', 'Is the policy in the mandatory standard ?', \
             'Account name', 'Date of the extraction', 'Last update of the asset', 'Cloud region', 'Section ID']
    
# --- Two fundtions below are to append the output the 'df_xls' table that will be pushed to csv
# --- First function to append the non-empty dataframes, second is to append empty dataframes

  def df_to_xls(df, passed, cloud, section):
    to_xls = pd.DataFrame(columns=dfcolumns)
    to_xls['Account ID'] = df['accountId'] # --- The data from parameter df (non-empty rql result) is extracted
    to_xls['Asset ID'] = df['rrn']
    to_xls['Asset Type'] = df['resourceType']
    to_xls['Account name'] = df['accountName']
    to_xls['Cloud region'] = df['regionName']
    to_xls['Description'] = params[cloud][section]['description'] # --- "Static" data from xls file
    to_xls['Policy name'] = params[cloud][section]['policy']
    to_xls['Compliant or non compliant'] = passed
    to_xls['Account group name'] = accgr
    to_xls['Is the policy in the mandatory standard ?'] = params[cloud][section]['mandatory']
    to_xls['Date of the extraction'] = datetime.now()
    to_xls['Last update of the asset'] = datetime.now()
    to_xls['Section ID'] = section
    
    return to_xls

  def df_to_xls_empty(passed, cloud, section):
    to_xls = pd.DataFrame(columns=dfcolumns)
    to_xls['Account ID'] = ["N/A"] # --- No results from RQL, [] is needed to create row in empty pandas df
    to_xls['Asset ID'] = "N/A"
    to_xls['Asset Type'] = "N/A"
    to_xls['Account name'] = "N/A"
    to_xls['Cloud region'] = "N/A"
    to_xls['Description'] = params[cloud][section]['description']
    to_xls['Policy name'] = params[cloud][section]['policy']
    to_xls['Compliant or non compliant'] = passed
    to_xls['Account group name'] = accgr
    to_xls['Is the policy in the mandatory standard ?'] = params[cloud][section]['mandatory']
    to_xls['Date of the extraction'] = datetime.now()
    to_xls['Last update of the asset'] = datetime.now()
    to_xls['Section ID'] = section

    return to_xls

# --- The loop is run twice per account groups ('accgr' in current func parameters) per cloud (Azure, AWS)

  for cloud in params:
    df_xls = pd.DataFrame(columns=dfcolumns) # --- Need to create empty "master" for each cloud to accomodate the results
    for section in params[cloud]:
        if params[cloud][section]['API'] == 'Custom': # --- Handling custom standards
          rql1 = wrap_text(params[cloud][section]['rql1']) % accgr
          df1 = response_custom(rql1)

          if params[cloud][section]['rql2'] != "nan": # --- Hadnling empty lines for rql2, that are 'nan' in input dataframe from xls
            rql2 = wrap_text(params[cloud][section]['rql2']) % accgr
            df2 = response_custom(rql2) # --- Get scan_info only if rql2 is not empty

          # --- Handling differnet scenarions with rql2 and rql1 being not empty, rql2 is the scope of check for custom policies
          # --- Emtpty and non-empty results are appended to the "master" dataframe - df_xls, that is pushed to csv

          if df2.empty:
            df_xls = pd.concat([df_xls, df_to_xls_empty("No assets", cloud, section)])
            
          if df1.empty and not df2.empty:
            df_xls = pd.concat([df_xls, df_to_xls(df2, "True", cloud, section)])

          if not df1.empty and not df2.empty:
            df_xls = pd.concat([df_xls, df_to_xls(df1, "False", cloud, section)])
            passed = pd.concat([df2,df1]).astype(str).drop_duplicates(keep=False)
            df_xls = pd.concat([df_xls, df_to_xls(passed, "True", cloud, section)])
        else:
          df_native = response_native(cloud, section) # --- Hadling native standards, getting scan_info for a secton of CIS 1.3.0 (Azure/AWS)
          if df_native.empty:
            df_xls = pd.concat([df_xls, df_to_xls_empty("No assets", cloud, section)])
          else:
            df_native.rename(columns = {'assetType':'resourceType'}, inplace = True)
            df_xls = pd.concat([df_xls, df_to_xls(df_native, df_native['overallPassed'], cloud, section)])

    # --- Create csv file from the df containing all results for cloud per account

    df_xls.to_csv(f"{accgr.replace(' ', '_')}_{cloud}_{datetime.now()}.csv", index=False)

# --- The dictionary that contains all the data from input xls file, put into 2 dicts by cloud

standards = {"Azure":{}, "AWS":{}}

# --- Getting data from xls to standard dict by cloud

for cloud in standards:
    fromxls = pd.read_excel(xls_file, sheet_name=cloud)
    for i in range(len(fromxls)):
      standards[cloud].update({fromxls.iloc[i]["MTSBv2 ID"]:{ # --- Standard section ID
                              "policy": fromxls.iloc[i]["Policy name"], 
                              "API": fromxls.iloc[i]["API"],
                              "mandatory": fromxls.iloc[i]["Mandatory"],
                              "description": fromxls.iloc[i]["Description"],
                              "rql1": fromxls.iloc[i]["Scope defining RQL"],
                              "rql2": fromxls.iloc[i]["Full RQL"],
                              "builtin": fromxls.iloc[i]["Built-in control"]}}) 

# --- Reports are created by account group, account groups are extracted into list

with open('accgroups.txt') as f:
    accgroups = f.readlines()

# --- Adding query results to report is done in 'result' function, it will be calld as many times as there are accounts
# --- Dictionary containing xls input is passed to 'result' to process the rql and get policy data

for accgr in accgroups:
   result(accgr.strip(), **standards)
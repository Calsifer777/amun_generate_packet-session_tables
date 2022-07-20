#!/usr/bin/env python
# coding: utf-8

# In[1]:


from collections import defaultdict
import geoip2.database
from tqdm import tqdm
import argparse
import time
import os

parser = argparse.ArgumentParser(prog='amun_generate_tables.py', description='This script is for generate packet/session table.')
parser.add_argument("geoip_country", type=str, help='Geoip country db path')
parser.add_argument("geoip_domain", type=str, help='Geoip country db path')
parser.add_argument("geoip_ISP", type=str, help='Geoip country db path')
parser.add_argument("isp", type=str, help='ISP for input file')
parser.add_argument("input_file", type=str, help='Input amun log file')
# parser.add_argument("core", type=int, help='Core number for multi-processing (be aware of device limitations)')
parser.add_argument("output_directory", type=str, help='Directory to save output files packet/session table (00, 06, 12, 18)')

args = parser.parse_args()
start = time.time() # 執行時間

# geoip_country_path = '/home/steven/code/share/steven/SSH/GeoIP2-Country_20200526/GeoIP2-Country.mmdb'
# geoip_domain_path = '/home/steven/code/share/steven/SSH/GeoIP2-Domain_20200526/GeoIP2-Domain.mmdb'
# gepip_ISP_path = '/home/steven/code/share/steven/SSH/GeoIP2-ISP_20200526/GeoIP2-ISP.mmdb'
geoip_country_path = args.geoip_country
geoip_domain_path = args.geoip_domain
gepip_ISP_path = args.geoip_ISP

isp = args.isp
file_path = args.input_file
Protocol = "telnet"
date = os.path.basename(file_path).split('.')[-1]
print("Reading log file ...")
f = open(file_path, 'r')
data = f.read()
data = data. split('\n')


# In[2]:


# data[0:20]


# In[3]:


tmp = []
for i in data:
    if 'Mess' in i:
        tmp.append(i)


# In[4]:


format_data =[]
for i in tmp:
    format_data.append(i.split(' '))


# In[5]:


# format_data[261]


# In[6]:


def clean_timestamp(x):
    x[1] = x[1].replace(',', '.')
    return x

format_data = list(map(clean_timestamp, format_data))


# In[7]:


# format_data[262]


# In[8]:

print("Cleaning log info ...")
ppc = []
for row in format_data:
    tmpp = ""
    for x in range(len(row)):
        if row[x][0:2] == "['"  or  row[x][0:2] == "[\"" and x != len(row) - 1:
            while True :
                if row[x][-2:] == "']" or row[x][-2:] == "\"]":
                    tmpp = tmpp + row[x]
                    break
                else:
                    tmpp = tmpp + row[x]
                    x = x + 1
            ppc.append(tmpp)
            break


# In[9]:


ppc = list(map(lambda x: x[2:-2], ppc))


# In[10]:


timestamp = []
src_port =[]
src_ip = [] 


# In[11]:


import numpy as np

for i in format_data:
    timestamp.append(i[0] + " " + i[1])
    src_ip.append(i[7])
    src_port.append(i[9].replace(',',''))
        


# In[12]:


import pytz
from datetime import datetime
def convert2timestamp(x):
    return pytz.utc.localize(datetime.strptime(x,"%Y-%m-%d %H:%M:%S.%f")).timestamp()
timestamp_process = list(map(convert2timestamp, timestamp))


# In[13]:


# for i in range(len(timestamp)):
#     timestamp_process.append(pytz.utc.localize(datetime.strptime(timestamp[i],"%Y-%m-%d %H:%M:%S.%f")).timestamp())


# In[14]:


import pandas as pd


# In[15]:


result = {
    'Timestamp_process' : timestamp_process,
    'Datetime' :  timestamp,
    'Src_ISP' : [isp] * len(timestamp_process),
    'Protocol' : [Protocol] * len(timestamp_process),
    'tcp_srcport' : src_port,
    'ip_src' : src_ip,
    'Payload' : ppc
}

result_df = pd.DataFrame(result)


# In[16]:


result_df


# In[17]:


result_df = result_df.sort_values(["Timestamp_process"], ascending=True)


# In[18]:


# result_df.shape[0]


# In[19]:


def get_ip_info(ip, client_country, client_isp, client_domain):
    ip_info = {'country':None, 'isp':None, 'domain':None}
    try:
        response_country = client_country.country(str(ip))
        ip_info['country'] = response_country.country.name
    except:
        pass
    try:
        response_isp = client_isp.isp(str(ip))
        ip_info['isp'] = response_isp.isp
    except:
        pass
    try:
        response_domain = client_domain.domain(str(ip))
        ip_info['domain'] = response_domain.domain
    except:
        pass
    return ip_info


# In[20]:

print("Making packet table ...")
client_country = geoip2.database.Reader(geoip_country_path)
client_isp = geoip2.database.Reader(gepip_ISP_path)
client_domain = geoip2.database.Reader(geoip_domain_path)

output_form_template = defaultdict(list)
key_index = 0
# compare =[]
for i in tqdm(range(result_df.shape[0])):
    key = result_df.Timestamp_process[key_index] + 120
    time_i = result_df.Timestamp_process[i]
    if(time_i < key) and (result_df.tcp_srcport[key_index] == result_df.tcp_srcport[i]) and (result_df.ip_src[key_index] == result_df.ip_src[i]):
        pass
    else:
        key_index = i
    
    output_form_template['Session_ID'].append(f'{date}_{isp}_'+ str(Protocol) + '_' + str(result_df.Timestamp_process[key_index])) # session_id
    output_form_template['session_time'].append(result_df.Timestamp_process[key_index])
    output_form_template['Packet_ID'].append(f'{date}_{isp}_'+ str(Protocol) + '_' + str(result_df.Timestamp_process[i])) # packet_id
    output_form_template['timestamp'].append(result_df.Timestamp_process[i])
    ip_info = get_ip_info(result_df.ip_src[i], client_country, client_isp, client_domain)
    output_form_template['country'] = ip_info['country']
    output_form_template['isp'] = ip_info['isp']
    output_form_template['domain'] = ip_info['domain']

output_form_template['Src_ISP'] = result_df['Src_ISP']
output_form_template['Protocol'] = result_df['Protocol']
output_form_template['tcp_srcport'] = result_df['tcp_srcport']
output_form_template['ip_src'] = result_df['ip_src']
output_form_template['Datetime'] = result_df['Datetime']
output_form_template['tcp_payload'] = result_df['Payload']


# In[21]:


total_table = pd.DataFrame(output_form_template)
total_table


# In[22]:


packet_table = total_table[['Packet_ID', 'timestamp', 'country', 'isp', 'domain', 'Protocol', 'tcp_srcport', 'ip_src', 'tcp_payload']]
packet_table


# In[23]:

print("Saving packet table ...")
packet_df_4 = np.array_split(packet_table, 4)
time_list = ['00', '06', '12', '18']
output_directory = args.output_directory
if not os.path.exists(output_directory):
    os.makedirs(output_directory)
for i in range(4):
    packet_df_4[i].to_pickle(f'{output_directory}/packet_table_{"".join(date.split("-"))}_{time_list[i]}_{isp}_telnet_pcap.pickle')


# # Session table

# In[24]:


grouped = total_table.groupby(['Session_ID'])


# In[25]:


# grouped.get_group('2022-01-01_test_telnet_1640995232.94')['Datetime'].iloc[0]


# In[26]:

print("Making session table ...")
session_template = defaultdict(list)
for name, group in tqdm(grouped):
    session_template['Session_ID'].append(name)
    session_template['Datetime'].append(group.Datetime.iloc[0])
    session_template['country'].append(group.country.iloc[0])
    session_template['isp'].append(group.isp.iloc[0])
    session_template['domain'].append(group.domain.iloc[0])
    session_template['session_time'].append(group.session_time.iloc[0])
    session_template['Packet_ID'].append(list(group.Packet_ID))
    session_template['ip_src'].append(group.ip_src.iloc[0])
    session_template['tcp_srcport'].append(group.tcp_srcport.iloc[0])
    session_template['session_time_list'].append(list(group.timestamp))
    session_template['session_duration'].append(group.timestamp.max() - group.timestamp.min())
    session_template['session_i_payload_tt_packet'].append(group.shape[0])
    session_template['session_i_tt_frame_length'].append(len(''.join(group.tcp_payload)))
    session_template['tcp_i_tt_payload_length'].append(len(''.join(group.tcp_payload)))
    session_template['tcp_i_payload_list'].append(list(group.tcp_payload))
    session_template['Src_ISP'].append(group.Src_ISP.iloc[0])
    
session_table = pd.DataFrame(session_template)


# In[27]:


# session_table


# In[28]:

print("Saving session table ...")
session_df_4 = np.array_split(session_table, 4)
for i in range(4):
    session_df_4[i].to_pickle(f'{output_directory}/session_table_{"".join(date.split("-"))}_{time_list[i]}_{isp}_telnet_pcap.pickle')

print("Finish!")
end = time.time() # 執行時間
print("Execution time:", end - start)
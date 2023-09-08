import pandas as pd
from scapy.packet import Padding
from scapy.utils import rdpcap
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP
from scapy.layers.l2 import Ether
import os
import re
import csv
import matplotlib.pyplot as plt
from scapy.compat import raw
from scapy.all import *




def remove_ether_header(packet):
    if Ether in packet:
        return packet[Ether].payload

    return packet

def mask_ip(packet):
    if IP in packet:
        packet[IP].src = '0.0.0.0'
        packet[IP].dst = '0.0.0.0'

    return packet

def pad_udp(packet):
    if UDP in packet:
        # get layers after udp
        layer_after = packet[UDP].payload.copy()

        # build a padding layer
        pad = Padding()
        pad.load = '\x00' * 12

        layer_before = packet.copy()
        layer_before[UDP].remove_payload()
        packet = layer_before / pad / layer_after

        return packet

    return packet
    
def should_omit_packet(packet):
    # SYN, ACK or FIN flags set to 1 and no payload
    if TCP in packet and (packet.flags & 0x13):
        # not payload or contains only padding
        layers = packet[TCP].payload.layers()
        if not layers or (Padding in layers and len(layers) == 1):
            return True

    # DNS segment
    if DNS in packet:
        return True

    return False

def transform_packet(packet):
    # if should_omit_packet(packet):
    #     return None

    packet = remove_ether_header(packet)
    packet = pad_udp(packet)
    packet = mask_ip(packet)

    return packet

def isValidSource(packet,moIP):
    if IP in packet:
        if (packet[IP].src == moIP ):
             return True
    return False

def mostOccuredIPFinder(file):
    ipsSet =set((p[IP].src, p[IP].dst,p[IP].proto) for p in PcapReader(file) if IP in p)
    mostOccuredIp=""
    if(len(ipsSet)<=2):
        for i in ipsSet:
            ipss=i;
            break;
        mostOccuredIp = ipss[0]
        if mostOccuredIp == "172.16.100.7":
            mostOccuredIp = ipss[1]
    else:
        uniqueB=[]
        for i in ipsSet:
            uniqueB.append(i[1])
            
        from collections import Counter
        occurence_count = Counter(uniqueB)
        mostOccuredIp = occurence_count.most_common(1)[0][0]
    return mostOccuredIp

def read_pcap(filename, fields=[], display_filter="", timeseries=False, strict=False):
    if timeseries:
        fields = ["frame.time_epoch"] + fields
    fieldspec = " ".join("-e %s" % f for f in fields)
    display_filters = fields if strict else []
    if display_filter:
        display_filters.append(display_filter)
    filterspec = "-R '%s'" % " and ".join(f for f in display_filters)
    options = "-r %s -2 -T fields -Eheader=y" % filename
    cmd = "tshark %s %s" % (options, fieldspec)
    proc = subprocess.Popen(cmd, shell = True,stdout=subprocess.PIPE)
    df = pd.read_table(proc.stdout)
    return df

def _replaceitem(x):
    if x < 4:
        return 0
    else:
        return x


path_to_dir = r"D:\Ammar\0 - Dataset (PCAPs)\Videos\Gap Dataset PCAPs\1080p\BPS-LiveTesting\Remaining"
out_path = r"D:\Ammar\OneDrive - Higher Education Commission\11- PAT\Result\1080(C50-F55).csv"
#path_of_csv = "D:\Work\SIS_Collection\Flowpics\ForSIS\output\360.csv"
dirlist = os.listdir(path_to_dir)
PAT = pd.DataFrame()

total_counter = 0

for dirName in dirlist:
    sub_counter = 0
    total_fold = len(dirlist)
    total_progress = (total_counter/total_fold)*100
    total_progress = round(total_progress ,2)
    
    dirPath = path_to_dir +"\\" +dirName +"\\"
    fileList = os.listdir(dirPath)
    for file in fileList:
        sub_fold = len(fileList)
        sub_progress = (sub_counter/sub_fold)*100
        sub_progress = round(sub_progress,2)
        
        path_to_file = dirPath+file
        ImgName = file.split(".")[0]

        Allpackets=rdpcap(path_to_file)
        moIP = mostOccuredIPFinder(path_to_file)
        print(ImgName,"\t current progress: ",sub_progress,"\t total progress: ",total_progress)
        
        packet_info = pd.DataFrame()
        packet_length = []
        packet_time = []
        
        for p in Allpackets:
            # check = isValidSource(packet,moIP)
            # if check:
            packet=transform_packet(p)
            if packet is not None:
               packet_length.append(len(packet))
               # print(p.time)
               # print(len(packet))
               # time.sleep(2)
               packet_time.append(p.time)

        packet_info = packet_info.append(pd.DataFrame({'Packet_Length':packet_length,'Packet_Arrival':packet_time})) 
        
        packet_info['Packet_Arrival'] = (packet_info['Packet_Arrival']-min(packet_info['Packet_Arrival']))/(max(packet_info['Packet_Arrival'])-min(packet_info['Packet_Arrival']))
        #print( packet_info['Packet_Arrival'])
        
        packet_info['Packet_Arrival'] = packet_info['Packet_Arrival'] * 120
        seconds = [i for i in range(120)]
        sample_PAT = []
        for i in seconds:
            # df = packet_info.loc((packet_info['Packet_Arrival']>=i) & (packet_info['Packet_Arrival']<i+1) )
            df_second = packet_info[  (packet_info['Packet_Arrival']>=i) & (packet_info['Packet_Arrival']<i+1) ]
            aggr = df_second['Packet_Length'].sum()
            sample_PAT.append(aggr)
        
        sample_PAT.append(str(dirName))
        sample_PAT.append(str(ImgName))
        with open (out_path,'a',newline="") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(sample_PAT)
        
        # sample_PAT = pd.Series(sample_PAT)
        # PAT = PAT.append(sample_PAT,ignore_index=True)
        sub_counter+=1
    total_counter+=1
        
    
    # PAT.to_csv(out_path+"\\output_PAT.csv",encoding='utf-8',index=False,header=False)
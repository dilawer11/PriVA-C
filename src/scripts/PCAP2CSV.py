import sys
import os
import argparse
import tqdm
import json
from multiprocessing import Pool, cpu_count
from iotpackage.Utils import loadCaptureFromPath
from iotpackage.DNSMapping import DNSMapper
from iotpackage.Configs import CaptureConfig

# sys.path.append(os.getcwd())

# def loadDNSFileList(dns_dir):
#     file_list = []
#     for root, _, files in os.walk(dns_dir):
#         for name in files:
#             if os.path.splitext(name)[1] == '.csv':
#                 file_list.append(os.path.join(root, name))
#     return file_list

def createDNSMapping(dns_dir, output_path):
    dns_mapper = DNSMapper(None)
    dns_csvs = loadCaptureFromPath(dns_dir)
    # dns_csvs = loadDNSFileList(dns_dir)
    print("Total files found:", len(dns_csvs))
    dns_mapping = {}
    print(dns_csvs)
    for dns_csv in tqdm.tqdm(dns_csvs):
        try:
            dns_mapping = dns_mapper.processDNSMapping(dns_csv, dns_mapping=dns_mapping)
        except Exception as e:
            print("EXCEPTION:", e)
            print("dns_csv:", dns_csv)

    with open(output_path, 'w+') as f:
        json.dump(dns_mapping, f, indent=4)
    print("Output saved to:", output_path)    
    
    return

class PCAP2CSVConverter:
    pcapDir = None
    csvDir = None
    dnsDir = None
    def __init__(self, pcap_dir, csv_dir, dns_dir):
        self.pcapDir = pcap_dir
        self.csvDir = csv_dir
        self.dnsDir = dns_dir
        if not os.path.isdir(self.csvDir):
            os.makedirs(self.csvDir)
        if not os.path.isdir(self.dnsDir):
            os.makedirs(self.dnsDir)

        return

    def getRelativePath(self, pcap_path, trim_ext=True):
        rel_path = os.path.relpath(pcap_path, start=self.pcapDir)
        if trim_ext:
            rel_path, _ = os.path.splitext(rel_path)
        
        return rel_path

    def convertToCSV(self, pcap_path):
        cmd_unformatted = '''tshark -r {} -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e frame.len -e tcp.flags.ack -e tcp.flags.syn -e tcp.flags.fin -e tcp.flags.reset -e tcp.flags.push -e tcp.flags.urg -e _ws.col.Protocol -e tcp.len -E separator=, -E quote=d -E header=y > {}.csv 2> /dev/null'''
        relpath = self.getRelativePath(pcap_path)
        dirname = os.path.dirname(relpath)
        complete_dir = os.path.join(self.csvDir, dirname)
        if not os.path.isdir(complete_dir):
            os.makedirs(complete_dir)
        dest_path = os.path.join(self.csvDir, relpath)
        cmd = cmd_unformatted.format(pcap_path, dest_path)
        os.system(cmd)
        return

    def dnsFromPCAP(self, pcap_path):
        cmd_unformatted = '''tshark -r {} -R "dns.flags.response == 1" -2 -T fields -e frame.time_epoch -e dns.qry.name -e dns.a -e dns.aaaa -e dns.cname -e dns.resp.type -e dns.count.answers -E separator=, -E quote=d -E header=y > {}.csv 2> /dev/null'''
        relpath = self.getRelativePath(pcap_path)
        dirname = os.path.dirname(relpath)
        complete_dir = os.path.join(self.dnsDir, dirname)
        if not os.path.isdir(complete_dir):
            os.makedirs(complete_dir)
        dest_path = os.path.join(self.dnsDir, relpath)
        cmd = cmd_unformatted.format(pcap_path, dest_path)
        os.system(cmd)
        return

    def processPcap(self, pcap_path):
        self.convertToCSV(pcap_path)
        self.dnsFromPCAP(pcap_path)
        return

    def processPcaps(self, pcap_paths):
        for pcap in pcap_paths:
            self.processPcap(pcap)

    def divideListIntoLists(self, main_list, size_each=10):
        n = len(main_list)
        ret_list = []
        for i in range(0, n, size_each):
            file_list = main_list[i: i + size_each]
            ret_list.append(file_list)
        return ret_list
    
    def startParallel(self):
        file_list = []
        total_files = 0
        for root, _, files in os.walk(self.pcapDir):
            for name in files:
                if os.path.splitext(name)[1] == ".pcap":
                    total_files += 1
                    file_list.append(os.path.join(root, name))
        file_lists = self.divideListIntoLists(file_list)
        n = len(file_lists)
        print("Total files:", total_files)
        print("file_lists:", n)
        p = Pool(cpu_count())
        list(tqdm.tqdm(p.imap_unordered(self.processPcaps, file_lists), total=n))

    def startSingle(self):
        fileList = []
        for root, _, files in os.walk(self.pcapDir):
            for name in files:
                # if 'cap_' in os.path.split(name)[1]:
                if os.path.splitext(name)[1] == '.pcap':
                    fileList.append(os.path.join(root, name))
        for pcap in tqdm.tqdm(fileList):
            self.processPcap(pcap)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", dest="input_dir", help="The input directory", required=True)
    parser.add_argument("-p", dest="parallel", action="store_true", default=False, help="Multi processing")
    args = parser.parse_args()

    if not os.path.isdir(args.input_dir): raise FileNotFoundError(f"No such directory: input_dir={args.input_dir}")

    config = CaptureConfig(args.input_dir)

    if not os.path.isdir(config.PCAP_PATH): raise FileNotFoundError(f"No such directory: pcap_dir={config.PCAP_PATH}")
    
    if not os.path.isdir(config.CSV_PATH): os.mkdir(config.CSV_PATH)
    if not os.path.isdir(config.DNS_PATH): os.mkdir(config.DNS_PATH)
    
    p2c = PCAP2CSVConverter(pcap_dir=config.PCAP_PATH, csv_dir=config.CSV_PATH, dns_dir=config.DNS_PATH)
    if not args.parallel:
        p2c.startSingle()
    else:
        p2c.startParallel()

    print("Creating DNS Mapping...")
    
    if not os.path.isdir(config.DNS_PATH):
        raise FileNotFoundError(f"No such directory: {config.DNS_PATH}")
    createDNSMapping(config.DNS_PATH, config.DNS_MAPPING_FP)

if __name__ == "__main__":
    main()

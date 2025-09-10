import os
import argparse
import logging
from multiprocessing import cpu_count
import pandas as pd

from iotpackage.Utils import getPDPathFromIRPath, createParentDirectory, genIR
from iotpackage.PreProcessing import PreProcessor
from iotpackage.Configs import WindowsConfig, CaptureConfig
from iotpackage.__vars import defaultVals

l = logging.getLogger('CSV2Windows')

class CSV2Windows:
    pp = None
    low_packet_threshold = None
    def __init__(self, capture_config, windows_config):
        """
        PARAMETERS
        ----------
        target_ips, list(str): The internal IPs to focus on. Only devices (routers or homes) with these IPs will be considered as target. Traffic from other IPs will dropped
        protos, list(int): The list of protocols to consider default is TCP, UDP, default=[6, 17]
        hostname_method, str: The method to use for hostname mapping, 'live' means only passive DNS which can miss initial values which might have DNS traffic before capturing started. 'post' means the mapping created at the end of capture which might mark some incorrectly due to changing IPs. 'both' does live first and uses post for the missing ones
        inactive_flow_timeout, int: The timeout to use when a flow is not active according to netflow definitiion
        active_flow_timeout, int: The timeout value to use when a flow is actively sending traffic according to netflow definition
        new_flow_win_width, int: The 'm' value or the new flow win width value (default=10)
        va, str: The hint as to which VA is being used

        """
        self.pp = PreProcessor(capture_config=capture_config, windows_config=windows_config)
    
        self.inactive_flow_timeout = windows_config.INACTIVE_FLOW_TIMEOUT
        self.active_flow_timeout = windows_config.ACTIVE_FLOW_TIMEOUT

        self.before_st = 0
        self.after_st = self.active_flow_timeout

        self.new_flow_win_width = windows_config.NEW_FLOW_WIN_WIDTH

        self.flow_grouper = ['hostname', 'ip',
                             'ext.port', 'int.port', 'ip.proto']

        self.low_packet_threshold = windows_config.LOW_PACKET_THRESHOLD
        self.fixed_flows = []

        self.output_path = windows_config.WINDOWS_SUB_DIR
        self.ir_base_path = capture_config.IR_PATH
        return

    def __extractWindowData(self, data, window_start_time, window_end_time):
        invoke_pdata = data[(data['frame.time_epoch'] >= window_start_time) & (
            data['frame.time_epoch'] <= window_end_time)]
        return invoke_pdata

    def __saveInvokePacketData(self, invoke_pdata, ir_path):
        pd_path = getPDPathFromIRPath(
            ir_path, self.ir_base_path, self.output_path)
        createParentDirectory(pd_path)

        num_packets = invoke_pdata.shape[0]
        size_packets = invoke_pdata['frame.len'].sum()
        if num_packets < self.low_packet_threshold and size_packets:
            err_msg = f"Not saving IR too low data: {num_packets}, {size_packets}, {ir_path}"
            l.error(err_msg)
            print('ERROR: Some window data not saved. Check logs')
        else:
            invoke_pdata.to_csv(pd_path, index=False)

    def getFlowsinWindow(self, packets, wst, wet):
        win_idx = (packets['frame.time_epoch'] >= wst) & (
            packets['frame.time_epoch'] < wet)
        flows = packets[win_idx].groupby(self.flow_grouper).groups.keys()
        return set(flows)

    def isFixedFlow(self, x, fixed_flows):
        for fixed_flow in fixed_flows:
            all_attribute_match = True
            for idx, flow_attribute in enumerate(self.flow_grouper):
                if flow_attribute in fixed_flow and x[idx] != fixed_flow[flow_attribute]:
                    all_attribute_match = False
                    break
            if all_attribute_match:
                return True
        return False

    def getFixedFlows(self, all_flows):
        flow_list = [flow for flow in all_flows if self.isFixedFlow(
            flow, self.fixed_flows)]
        return set(flow_list)

    def getFlowsToTrack(self, packets, invoke_ts):
        delta_win_s_ts = invoke_ts
        delta_win_e_ts = invoke_ts + self.new_flow_win_width
        active_flows = self.getFlowsinWindow(
            packets, delta_win_s_ts - self.inactive_flow_timeout, delta_win_s_ts)
        all_flows = self.getFlowsinWindow(
            packets, delta_win_s_ts, delta_win_e_ts)
        new_flows = all_flows - active_flows
        fixed_flows = self.getFixedFlows(all_flows)
        tracked_flows = new_flows.union(fixed_flows)
        return tracked_flows

    def getTrackedTraffic(self, packets, invoke_ts):
        def addTrafficFromGroup(gdata):
            try:
                gname = gdata.name
            except:
                print('ERROR: gdata.name:', gdata.shape, gdata)
                return
            if gname not in tracked_flows:
                return
            last_pkt_time = gdata['frame.time_epoch'].iloc[0]
            for i, pkt in gdata.iterrows():
                pkt_time = pkt['frame.time_epoch']
                if (pkt_time > (invoke_ts + self.new_flow_win_width)) and (pkt_time > (last_pkt_time + self.inactive_flow_timeout)):
                    return
                if pkt_time > invoke_ts + self.active_flow_timeout:
                    return
                if pkt_time >= invoke_ts:
                    idxs.append(i)
                last_pkt_time = pkt_time

        idxs = []
        tracked_flows = self.getFlowsToTrack(packets, invoke_ts)
        packets.groupby(self.flow_grouper).apply(addTrafficFromGroup)
        return packets.loc[idxs, :].sort_index()

    def run(self):
        l.info("Starting CSV2Windows")
        pdgen = self.pp.genPdata()
        irgen = genIR(irs=self.ir_base_path, load_stop=False)
        pdata, pst, pet = next(pdgen)
        l.debug(f"pdata.shape: {pdata.shape}, pst={pst}, pet={pet}")
        for ir_fp, ir_data, status in irgen:
            if status != 'U': continue
            st = ir_data['invoke_time']
            wst = st - self.before_st
            wet = st + self.after_st
            l.debug(f"IR Info: st={st}, wst={wst}, wet={wet}")

            if wst < pst:
                err_msg = f'Not enough data for IR: {ir_fp}'
                l.warning(err_msg)
                print('WARNING:', err_msg)
            wpdata_arr = []
            while wst > pet:
                pdata, pst, pet = next(pdgen)
                l.debug(f"pdata.shape: {pdata.shape}, pst={pst}, pet={pet}")
            while True:
                wpdata = self.__extractWindowData(pdata, wst, wet)
                wpdata_arr.append(wpdata.reset_index(drop=True))
                if pet < wet:
                    try: 
                        pdata, pst, pet = next(pdgen)
                        l.debug(f"pdata.shape: {pdata.shape}, pst={pst}, pet={pet}")
                    except StopIteration: break
                else:
                    break

            wpdata = pd.concat(wpdata_arr, ignore_index=True)
            if self.new_flow_win_width: wpdata = self.getTrackedTraffic(wpdata, st)
            # DIL: To only extract window traffic
            wpdata = self.__extractWindowData(wpdata, st, wet) 
            self.__saveInvokePacketData(wpdata, ir_fp)
        return


def main(args):
    capture_config = CaptureConfig(input_dir=args.input_dir)
    windows_config = WindowsConfig(input_dir=args.input_dir, new_flow_win_width=args.new_flow_win_width, 
                                     hostname_method=args.hostname_method, inactive_flow_timeout=args.inactive_flow_timeout,
                                     active_flow_timeout=args.active_flow_timeout, target_ips=capture_config.TARGET_IPS)
    
    csv_input_dir = capture_config.CSV_PATH
    if not os.path.isdir(csv_input_dir): raise FileNotFoundError(f'csv_input_dir not found: {csv_input_dir}. Did you run PCAP2CSV script on this input directory')

    ir_dir = capture_config.IR_PATH
    if not os.path.isdir(ir_dir): raise FileNotFoundError(f'ir_dir not found: {ir_dir}. It seems like invoke records are missing/not where expected')

    windows_path = windows_config.WINDOWS_PATH
    if not os.path.exists(windows_path): os.mkdir(windows_path)

    feature_data_path = windows_config.getFeatureDataPath()

    windows_subdir = windows_config.WINDOWS_SUB_DIR

    l_path = os.path.join(windows_subdir, 'windows.log')
    print('logging_path:', l_path)
    logging.basicConfig(filename=l_path, filemode='w+',
                        level=logging.DEBUG, force=True)
    l = logging.getLogger("windows")
    l.info("Starting...")
    l.info(f"feature_data_path: {feature_data_path}")

    e = CSV2Windows(capture_config=capture_config, windows_config=windows_config)
    e.run()
    l.info("Finished CSV2Windows")

    return

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-i', dest='input_dir', required=True, help="The input directory")
    parser.add_argument('--new-flow-win-width', type=int, default=defaultVals['windows']['new_flow_win_width'],
                               help=f"The win_width for new flows to start in. (default={defaultVals['windows']['new_flow_win_width']}")
    parser.add_argument('--inactive-flow-timeout', type=int, default=defaultVals['windows']['inactive_flow_timeout'],
                               help=f"The inactive flow timeout determines after how many seconds of no traffic is a flow considered over. (default={defaultVals['windows']['inactive_flow_timeout']}")
    parser.add_argument('--active-flow-timeout', type=int, default=defaultVals['windows']['active_flow_timeout'],
                               help=f"The active flow timeout determines after how many seconds of traffic (even continous) is a flow considered over. (default={defaultVals['windows']['active_flow_timeout']}")
    parser.add_argument('--hostname-method', type=str, default=defaultVals['windows']['hostname_method'],
                               help=f"Which hostname method to use. Options are 'live', 'post' or 'both'. (default='{defaultVals['windows']['hostname_method']}')")
    parser.add_argument('--max-jobs', default=cpu_count(), type=int, help="The max number of processes to create in the pool")

    args = parser.parse_args()
    main(args)
    print("\nScript Completed Execution")

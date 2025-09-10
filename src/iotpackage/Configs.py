import os
from datetime import datetime
from iotpackage.__vars import defaultVals
from iotpackage.Utils import READ_JSON, STORE_JSON

def loadSetupFromMetadata(load, metadata_path):
    METADATA = READ_JSON(metadata_path)
    if load == "latest":
        date_key = max(METADATA.keys(), key=dateKey)
    else:
        date_key = load
    setup_info = METADATA[date_key]
    return setup_info, date_key

def addSetupToMetadata(setup_info, metadata_path):
    # Add the setup above to metadata
    sub_dir_name = subDirName()
    if not os.path.exists(metadata_path):
        METADATA = {}
    else:
        METADATA = READ_JSON(metadata_path)
    METADATA[sub_dir_name] = setup_info
    STORE_JSON(metadata_path, METADATA)
    return sub_dir_name


# TODO: Add to all configs

def printConfig(self):
    print('-------------RUN CONFIG-------------')
    print('Train Datasets    ->', self.trainDatasets)
    print('Test Datasets     ->', self.testDatasets)
    print('Cross Validation  ->', self.cv)
    print('Label             ->', self.label_col)
    print('Run Type          ->', self.runType)
    print('-----------------------------------')

# Default Vals

# Configurations
class CaptureConfig:
    captures_dir_name = "captures"
    pcap_dir_name = "pcap"
    dns_dir_name = "dns"
    csv_dir_name = "csv"
    dns_mapping_fn = "dns_mapping.json"
    ir_dir_name = "invoke_records"

    metadata_name = "METADATA.json"
    # Vars
    TARGET_IPS = None
    def __init__(self, input_dir:str):
        self.input_dir = input_dir
        if not os.path.isdir(self.input_dir): raise FileNotFoundError(f"input_dir not found: {self.input_dir}. Did you use the correct path?")

        self.CAPTURE_PATH = os.path.join(self.input_dir, self.captures_dir_name)
        self.PCAP_PATH = os.path.join(self.CAPTURE_PATH, self.pcap_dir_name)
        self.IR_PATH = os.path.join(self.CAPTURE_PATH, self.ir_dir_name)

        self.DNS_PATH = os.path.join(self.CAPTURE_PATH, self.dns_dir_name)
        self.CSV_PATH = os.path.join(self.CAPTURE_PATH, self.csv_dir_name)
        self.DNS_MAPPING_FP = os.path.join(self.CAPTURE_PATH, self.dns_mapping_fn)

        self.METADATA_PATH = os.path.join(self.CAPTURE_PATH, self.metadata_name)
        self.loadMetadata()

    def __repr__(self) -> str:
        return f"CaptureConfig(input_dir={self.input_dir}, TARGET_IPS={self.TARGET_IPS}, CAPTURE_PATH={self.CAPTURE_PATH}, PCAP_PATH={self.PCAP_PATH}, IR_PATH={self.IR_PATH}, DNS_PATH={self.DNS_PATH}, CSV_PATH={self.CSV_PATH}, DNS_MAPPING_FP={self.DNS_MAPPING_FP}, METADATA_PATH={self.METADATA_PATH})"
    def loadMetadata(self):
        metadata = READ_JSON(self.METADATA_PATH)
        self.TARGET_IPS = [metadata['device_ip']]
        return

def dateKey(date):
    # Get the date key for the passed date
    return datetime.strptime(date, "%d-%b-%Y_%H%M")

def subDirName():
    # Get the directory name for the current time
    dt = datetime.now()
    return datetime.strftime(dt, "%d-%b-%Y_%H%M")

    
class WindowsConfig():
    windows_dir = "windows"
    
    fdata_fn = "fdata.pkl"
    metadata_name = "METADATA.json"
    
    TARGET_IPS = None

    NEW_FLOW_WIN_WIDTH= None
    HOSTNAME_METHOD = None
    INACTIVE_FLOW_TIMEOUT = None
    ACTIVE_FLOW_TIMEOUT = None
    
    OTHER = None

    PROTOS = [6, 17]
    LOW_PACKET_THRESHOLD = 100

    def __init__(self, input_dir, target_ips=None, new_flow_win_width:int=defaultVals['windows']['new_flow_win_width'],
                  hostname_method:str=defaultVals['windows']['hostname_method'], inactive_flow_timeout:int=defaultVals['windows']['inactive_flow_timeout'],
                  active_flow_timeout:int=defaultVals['windows']['active_flow_timeout'], load=None, other=None):
        
        self.input_dir = input_dir
        if not os.path.isdir(self.input_dir): raise FileNotFoundError(f"input_dir not found: {self.input_dir}. Did you use the correct path?")

        self.WINDOWS_PATH = os.path.join(self.input_dir, self.windows_dir)
        if not os.path.exists(self.WINDOWS_PATH): os.mkdir(self.WINDOWS_PATH)

        self.METADATA_PATH = os.path.join(self.WINDOWS_PATH, self.metadata_name)

        self.OTHER = other

        if load is not None:
            self.initLoad(load)
        else:
            self.NEW_FLOW_WIN_WIDTH = new_flow_win_width
            self.HOSTNAME_METHOD = hostname_method
            self.INACTIVE_FLOW_TIMEOUT = inactive_flow_timeout
            self.ACTIVE_FLOW_TIMEOUT = active_flow_timeout

            if target_ips is None: raise AttributeError(f"target_ips should not be None")
            self.TARGET_IPS = target_ips
            self.WINDOWS_SUB_DIR = None

            return
        
    def __repr__(self) -> str:
        return f"ADWindowsConfig(input_dir={self.input_dir}, target_ips={self.TARGET_IPS}, new_flow_win_width={self.NEW_FLOW_WIN_WIDTH}, hostname_method={self.HOSTNAME_METHOD}, inactive_flow_timeout={self.INACTIVE_FLOW_TIMEOUT}, active_flow_timeout={self.ACTIVE_FLOW_TIMEOUT}, windows_sub_dir={self.WINDOWS_SUB_DIR}, other={self.OTHER})"
    
    def initLoad(self, load):
        setup_info, date_key = loadSetupFromMetadata(load, self.METADATA_PATH)
        self.NEW_FLOW_WIN_WIDTH = setup_info['new_flow_win_width']
        self.HOSTNAME_METHOD = setup_info['hostname_method']
        self.INACTIVE_FLOW_TIMEOUT = setup_info['inactive_flow_timeout']
        self.ACTIVE_FLOW_TIMEOUT = setup_info['active_flow_timeout']
        self.TARGET_IPS = setup_info['target_ips']
        self.PROTOS = setup_info['protos']
        self.OTHER = setup_info['other'] if 'other' in setup_info else None
        self.WINDOWS_SUB_DIR = os.path.join(self.WINDOWS_PATH, date_key)
        return
        
    def initSubDir(self):
        setup_info = {
            "new_flow_win_width": self.NEW_FLOW_WIN_WIDTH,
            "hostname_method": self.HOSTNAME_METHOD,
            "inactive_flow_timeout": self.INACTIVE_FLOW_TIMEOUT,
            "active_flow_timeout": self.ACTIVE_FLOW_TIMEOUT,
            "target_ips": self.TARGET_IPS,
            "protos": self.PROTOS,
            "input_dir": self.input_dir,
        }
        if self.OTHER is not None: setup_info['other'] = self.OTHER
        sub_dir_name = addSetupToMetadata(setup_info=setup_info, metadata_path=self.METADATA_PATH)
        sub_dir_path = os.path.join(self.WINDOWS_PATH, sub_dir_name)
        if os.path.exists(sub_dir_path): raise FileExistsError(f"sub_dir={sub_dir_path} already exists")
        else: os.mkdir(sub_dir_path)
        self.WINDOWS_SUB_DIR = sub_dir_path
        return sub_dir_path
    
    def getWindowsSubDir(self):
        if self.WINDOWS_SUB_DIR is None: self.initSubDir()
        return self.WINDOWS_SUB_DIR
    
    def getFeatureDataPath(self):
        return os.path.join(self.getWindowsSubDir(), self.fdata_fn)

class TrainConfig():
    metadata_name = "METADATA.json"
    train_dir = "spying_train"

    def __init__(self, input_dir, windows_config=None, fs_vals=None, mt_vals=None, load=None):
        
        self.input_dir = input_dir
        self.windows_config = windows_config
        self.TRAIN_PATH = os.path.join(self.input_dir, self.train_dir)
        if not os.path.exists(self.TRAIN_PATH): os.mkdir(self.TRAIN_PATH)
        
        self.METADATA_PATH = os.path.join(self.TRAIN_PATH, self.metadata_name)

        if load is not None:
            self.initLoad(load)
        else:
            self.fs_vals = fs_vals
            self.mt_vals = mt_vals
            self.TRAIN_SUB_DIR = None
        return
        
    def __repr__(self) -> str:
        return f"ADTrainConfig(input_dir={self.input_dir}, windows_config={self.windows_config}, fs_vals={self.fs_vals}, mt_vals={self.mt_vals}, train_dir={self.train_dir})"
    def initLoad(self, load):
        setup_info, date_key = loadSetupFromMetadata(load, self.METADATA_PATH)
        self.fs_vals = setup_info['fs_vals']
        self.mt_vals = setup_info['mt_vals']
        
        self.WINDOWS_SUB_DIR = os.path.join(self.WINDOWS_PATH, date_key)
        return

    def initSubDir(self):
        setup_info = {
            "fs_vals": self.fs_vals,
            "mt_vals": self.mt_vals,
            "input_dir": self.input_dir,
            "windows_dir": self.windows_config.WINDOWS_SUB_DIR,
            "feature_data_path": self.getFeatureDataPath(),
        }

        sub_dir_name = addSetupToMetadata(setup_info=setup_info, metadata_path=self.METADATA_PATH)
        sub_dir_path = os.path.join(self.TRAIN_PATH, sub_dir_name)
        if os.path.exists(sub_dir_path): raise FileExistsError(f"sub_dir={sub_dir_path} already exists")
        else: os.mkdir(sub_dir_path)
        self.TRAIN_SUB_DIR = sub_dir_path
        return sub_dir_path
    
    def getTrainPath(self):
        if self.TRAIN_SUB_DIR is None: self.initSubDir()
        return self.TRAIN_SUB_DIR
    
    def getFeatureDataPath(self):
        feature_data_path = self.windows_config.getFeatureDataPath()
        if not os.path.exists(feature_data_path): raise FileNotFoundError(f"feature_data_path={feature_data_path} not found")
        return feature_data_path

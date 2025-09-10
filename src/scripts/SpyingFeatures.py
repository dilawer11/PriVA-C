import os
import argparse
import json
from multiprocessing import Pool, cpu_count
import pandas as pd
from tqdm import tqdm

from iotpackage.FeatureExtraction import FeatureExtracter
from iotpackage.Utils import labelledCSVFileLoader
from iotpackage.Configs import WindowsConfig, CaptureConfig


def loadConfigFromPath(config_path):
    with open(config_path, 'r') as f:
        config_data = json.load(f)
    return config_data


def loadConfig(config_name, config_dir=None):
    if config_dir is None:
        IOTBASE = os.getenv('IOTBASE')
        if IOTBASE is None:
            raise ValueError(f"Environment Variable 'IOTBASE' not set")
        config_dir = os.path.join(IOTBASE, 'model_configs')
    config_path = os.path.join(config_dir, config_name)
    return loadConfigFromPath(config_path)


def extractFeaturesFromCSV(args):
    label = args[0]
    csv_path = args[1]

    # Sanity Checks
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f'No such file found: {csv_path}')

    # Load the packets from csv file
    packets = pd.read_csv(csv_path)
    
    # Extract The Features
    fe = FeatureExtracter()
    feature_data = fe.run(packets)
    feature_data['label'] = label
    
    return feature_data

def CSV2FeatureData(csv_dir, ir_dir, feature_data_path, max_jobs):
    # Load the labelled CSV file list for feature extraction
    labelled_csv_list = labelledCSVFileLoader(csv_dir, ir_dir)

    print("Extracting Features from CSV files...")
    # Create a job pool for parralel feature extraction
    pool = Pool(max_jobs)
    # feature_data = pool.starmap(extractFeaturesFromCSV, labelled_csv_list)
    feature_data = list(tqdm(pool.imap(extractFeaturesFromCSV, labelled_csv_list), total=len(labelled_csv_list)))
    pool.close()
    pool.join()

    print("Saving features...")
    # Save the feature data to a file
    feature_data = pd.concat(feature_data, ignore_index=True)
    _, oext = os.path.splitext(feature_data_path)
    if oext == '.pkl':
        feature_data.to_pickle(feature_data_path)
    elif oext == '.json':
        feature_data.to_json(feature_data_path)

    print("Features saved to:", feature_data_path)
    return


def main(args):
    capture_config = CaptureConfig(input_dir=args.input_dir)
    windows_config = WindowsConfig(input_dir=args.input_dir, load=args.load)
    
    ir_dir = capture_config.IR_PATH
    if not os.path.isdir(ir_dir): raise FileNotFoundError(f'ir_dir not found: {ir_dir}. It seems like invoke records are missing/not where expected')

    windows_path = windows_config.WINDOWS_PATH
    if not os.path.exists(windows_path): os.mkdir(windows_path)

    feature_data_path = windows_config.getFeatureDataPath()

    windows_subdir = windows_config.WINDOWS_SUB_DIR

    CSV2FeatureData(csv_dir=windows_subdir, ir_dir=ir_dir, feature_data_path=feature_data_path, max_jobs=args.max_jobs)

    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-i', dest='input_dir', required=True, help="The input directory")
    parser.add_argument('-s', dest="load", type=str, default="latest",
                              help="The setup name to use. Default='latest'")
    parser.add_argument('--max-jobs', default=cpu_count(), type=int, help="The max number of processes to create in the pool")
    args = parser.parse_args()

    main(args)

    print("\nScript Completed Execution")

import os
import argparse
import copy

import iotpackage.ModelTraining as mt
from iotpackage.Utils import  READ_JSON
from iotpackage.Configs import WindowsConfig, TrainConfig
from iotpackage.__vars import defaultVals

def main(args):
    if not os.path.isdir(args.input_dir):
        raise FileNotFoundError(f"input_dir='{args.input_dir}' does not exist")
    
    # Setup feature selector vals
    fs_vals = copy.deepcopy(defaultVals['feature_selector'])
    if args.fs_config != "" and os.path.exists(args.fs_config):
        config_fs_vals = READ_JSON(args.fs_config)
        fs_vals.update(config_fs_vals)

    # Setup model training vals
    mt_vals = copy.deepcopy(defaultVals['model_training'])
    if args.mt_config != "" and os.path.exists(args.mt_config):
        config_mt_vals = READ_JSON(args.mt_config)
        mt_vals.update(config_mt_vals)
    
    windows_config = WindowsConfig(input_dir=args.input_dir, load=args.load)
    print(windows_config)
    train_config = TrainConfig(input_dir=args.input_dir, windows_config=windows_config, fs_vals=fs_vals, mt_vals=mt_vals)
    print(train_config)
    # Train using RandomForestModel
    model = mt.Classifier(train_config=train_config)
    model.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', dest='input_dir',
                              required=True, help='The input directory')
    parser.add_argument('-s', dest="load", type=str, default="latest",
                              help="The setup name to use. Default='latest'")
    parser.add_argument('--fs-config', type=str, default="",
                              help="The feature selector config. Each default config field is overriden by the config provided here.")
    parser.add_argument('--mt-config', type=str, default="",
                              help="The model training config. Each default config field is overriden by the config provided here.")

    args = parser.parse_args()

    main(args)

    print("\nScript Completed Execution")

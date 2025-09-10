import pandas as pd
import numpy as np
import logging
import os
from multiprocessing import cpu_count
from autogluon.tabular import TabularPredictor
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from xgboost import XGBClassifier
import pickle

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

from iotpackage.Utils import loadFeatureData, computeMetrics, createFeatureList, getFeatureGroup
from iotpackage.FeatureSelection import FeatureSelector

l = logging.getLogger("ModelTraining")

CPU_CORES = cpu_count()

class LabelEncoder:
    label_to_encoded = None
    encoded_to_label = None
    def __init__(self):
        self.label_to_encoded = {}
        self.encoded_to_label = {}
        return

    def fit(self, y):
        y_unique = None
        if isinstance(y, pd.Series):
            y_unique = list(y.unique())
        elif isinstance(y, np.ndarray) or isinstance(y, list):
            y_unique = list(set(y))
        else:
            raise TypeError(f'Unexpected type: {type(y)}')
        for i, label in enumerate(y_unique):
            self.label_to_encoded[label] = i
            self.encoded_to_label[i] = label
        return

    def transform(self, y):
        if isinstance(y, pd.Series):
            return y.apply(lambda x: self.label_to_encoded[x])
        if isinstance(y, np.ndarray) or isinstance(y, list):
            return [self.label_to_encoded[x] for x in y]
        else:
            raise TypeError(f'Unexpected type: {type(y)}')

    def reverse(self, y):
        if isinstance(y, pd.Series):
            return y.apply(lambda x: self.encoded_to_label[x])
        if isinstance(y, np.ndarray) or isinstance(y, list):
            return [self.encoded_to_label[x] for x in y]
        else:
            raise TypeError(f'Unexpected type: {type(y)}')
        
class BaseClassifier:
    def __init__(self):
        return
    
    def fit(self, X, y):
        raise NotImplementedError()
    
    def predict(self, X):
        raise NotImplementedError()
    
    def predict_proba(self, X):
        raise NotImplementedError()
    
    def feature_importance_single(self, X, y):
        raise NotImplementedError()
    
    def feature_importance_group(self, X, y):
        raise NotImplementedError()
    
    def load(self):
        raise NotImplementedError()
    
    def save(self):
        raise NotImplementedError()
    
class AutoGluonTabular(BaseClassifier):
    path = None
    __predictor = None
    def __init__(self, path="auto-gluon"):
        self.path = path
        self.label_col = 'label'

    def fit(self, X, y):
        X['label'] = y
        self.__predictor = TabularPredictor(label=self.label_col, path=self.path)
        self.__predictor.fit(X)
        self.__predictor.delete_models(models_to_keep='best', dry_run=False)
        return

    def load(self):
        self.__predictor = TabularPredictor.load(self.path)
        self.__predictor.persist_models('best')
    
    def predict(self, X):
        return self.__predictor.predict(X)

    def predict_proba(self, X):
        return self.__predictor.predict_proba(X)
    
    def feature_importance_single(self, X, y):
        # Compute feature importance for each feature. AutoGluon has a built-in method to compute feature permutation importance for each single feature
        if self.__predictor is None: raise Exception(f"Please call 'fit' or 'load' before calling feature importance")
        X['label'] = y
        feature_importances = self.__predictor.feature_importance(X)
        feature_importances.index.name = "feature"
        return feature_importances.reset_index(drop=False)
    
    def feature_importance_group(self, X, y):
        # Compute feature importance for each group. AutoGluon has a built-in method to compute feature permutation importance for each feature group
        if self.__predictor is None: raise Exception(f"Please call 'fit' or 'load' before calling feature importance")
        X['label'] = y

        feature_lists = createFeatureList(self.__predictor.features())
        feature_importances = self.__predictor.feature_importance(X, features=feature_lists)
        feature_importances.index.name = "feature_group"
        return feature_importances.reset_index(drop=False)

class RFClassifier(BaseClassifier):
    path = None
    __predictor = None
    def __init__(self, path='random-forest'):
        self.path = path
        self.model_fp = os.path.join(self.path, 'model.pkl')
    
    def load(self):
        if not os.path.exists(self.model_fp): raise FileNotFoundError(f"No model file: {self.model_fp}")
        with open(self.model_fp, 'rb') as f:
            self.__predictor = pickle.load(f)
        return

    def save(self, verbose=True):
        if not os.path.isdir(self.path): os.makedirs(self.path)
        with open(self.model_fp, 'wb') as f:
            pickle.dump(self.__predictor, f)
        if verbose: print('Model saved to:', self.model_fp)
        return

    def fit(self, X, y):
        self.__predictor = RandomForestClassifier(n_estimators=100, n_jobs=CPU_CORES)
        self.__predictor.fit(X, y)
        self.save()
        return

    def predict(self, X):
        return self.__predictor.predict(X)

    def predict_proba(self, X):
        return self.__predictor.predict_proba(X)

    def feature_importance_single(self, X, y):
        # Compute Feature Importance for each feature. Random Forest has a built-in method to compute feature importance for each single feature
        if self.__predictor is None: raise Exception(f"Please call 'fit' or 'load' before calling feature importance")
        feature_importances = pd.DataFrame(self.__predictor.feature_importances_, index = list(self.__predictor.feature_names_in_), columns=['importance']).sort_values('importance', ascending=False)
        feature_importances.index.name = "feature"
        return feature_importances.reset_index(drop=False)
    
    def feature_importance_group(self, X, y):
        # Compute Feature Importance for each group. Using sum of each individual feature as the feature importance for the group
        feature_importance = self.feature_importance_single(X, y)
        feature_importance['feature_group'] = feature_importance['feature'].apply(getFeatureGroup)
        feature_importance.drop(columns=['feature'], inplace=True)
        feature_importance = feature_importance.groupby('feature_group').sum().sort_values(by='importance', ascending=False).reset_index(drop=False)
        return feature_importance

class KNNClassifier(BaseClassifier):
    path = None
    __predictor = None
    def __init__(self, path='knn-classifier'):
        self.path = path
        self.model_fp = os.path.join(self.path, 'model.pkl')
    def load(self):
        if not os.path.exists(self.model_fp): raise FileNotFoundError(f"No model file: {self.model_fp}")
        with open(self.model_fp, 'rb') as f:
            self.__predictor = pickle.load(f)
        return

    def save(self, verbose=True):
        if not os.path.isdir(self.path): os.makedirs(self.path)
        with open(self.model_fp, 'wb') as f:
            pickle.dump(self.__predictor, f)
        if verbose: print('Model saved to:', self.model_fp)
        return

    def fit(self, X, y):
        self.__predictor = KNeighborsClassifier()
        self.__predictor.fit(X, y)
        self.save()
        return

    def predict(self, X):
        return self.__predictor.predict(X)

    def predict_proba(self, X):
        return self.__predictor.predict_proba(X)

class XGBoost(BaseClassifier):
    __predictor = None
    __label_encoder_fn = 'label-encoder.pkl'
    __model_fn = 'model.pkl'
    def __init__(self, path='xgb-boost'):
        self.__label_encoder = LabelEncoder()
        self.path = path
        self.label_encoder_fp = os.path.join(self.path, self.__label_encoder_fn)
        self.model_fp = os.path.join(self.path, self.__model_fn)
        return 
    
    def save(self, verbose=True):
        if not os.path.isdir(self.path): os.makedirs(self.path)
        with open(self.label_encoder_fp, 'wb') as f:
            pickle.dump(self.__label_encoder, f)
            if verbose: print('Label Encoder saved to:', self.label_encoder_fp)
        with open(self.model_fp, 'wb') as f:
            pickle.dump(self.__predictor, f)
            if verbose: print('Model saved to:', self.model_fp)
        return
    
    def load(self, verbose=True):
        with open(self.label_encoder_fp, 'rb') as f:
            self.__label_encoder = pickle.load(f)
        if verbose: print('Label Encoder loaded from:', self.label_encoder_fp)
        with open(self.model_fp, 'rb') as f:
            self.__predictor = pickle.load(f)
        if verbose: print('Model loaded from:', self.model_fp)

    def fit(self, X, y):
        self.__predictor = XGBClassifier()
        self.__label_encoder.fit(y)
        y_encoded = self.__label_encoder.transform(y)
        self.__predictor.fit(X, y_encoded)
        self.save()
        return None

    def predict(self, X):
        y_encoded = self.__predictor.predict(X)
        y = self.__label_encoder.reverse(y_encoded)
        return y


class Classifier:
    clf = None
    fs = None
    label_col = None

    def __init__(self, train_config):
        self.train_config = train_config
        self.save_path = self.train_config.getTrainPath()
        self.label_col = self.train_config.mt_vals['label_col']
        self.remove_threshold = self.train_config.mt_vals['remove_threshold']
        self.fs = FeatureSelector(vals=train_config.fs_vals, save_path=self.save_path)

    def initClf(self):
        clf_path = os.path.join(self.save_path, 'classifier')
        if not os.path.exists(clf_path): os.mkdir(clf_path)
        model_name = self.train_config.mt_vals['model_name']
        if model_name == 'AutoMLClassifier':
            self.clf = AutoGluonTabular(clf_path)
        elif model_name == "RandomForestClassifier":
            self.clf = RFClassifier(clf_path)
        else:
            raise ValueError(f'Unexpected model_name: {model_name}')

    def removeLessThan(self, data):
        # Explicity set to device to ensure devices less than the threshold get removed
        vc = data[self.label_col].value_counts()
        return data[data[self.label_col].isin(list(vc[vc >= self.remove_threshold].index))]
    
    def loadData(self):
        # Load the data, remove the stop label and remove the labels with less than threshold sampels
        feature_data_path = self.train_config.getFeatureDataPath()
        data = loadFeatureData(feature_data_path)
        data = data[data[self.label_col] != 'stop'].reset_index(drop=True)
        data = self.removeLessThan(data)
        if self.label_col not in list(data.columns): raise AttributeError(f"label_col='{self.label_col}', not found in train_data.columns={list(data.columns)}")
        return data

    @staticmethod
    def computeFeatureImportances(clf, X, y,top_n=None, save_path=None, print_features=False):
        try:
            feature_importance_single = clf.feature_importance_single(X, y)
            if top_n:
                feature_importance_single = feature_importance_single.iloc[:top_n,:]
            if save_path is not None:
                feature_importance_single.to_csv(os.path.join(save_path, 'feature_importance_single.csv'), index=False)
            if print_features:
                print(feature_importance_single)

            feature_importance_group = clf.feature_importance_group(X, y)
            if top_n:
                feature_importance_group = feature_importance_group.iloc[:top_n,:]
            if save_path is not None:
                feature_importance_group.to_csv(os.path.join(save_path, 'feature_importance_group.csv'), index=False)
            if print_features:
                print(feature_importance_group)
                
            return
        except NotImplementedError:
            print("Feature Importance: Not Implemented")
        except Exception as e:
            l.exception(e)
            print("Feature Importance: Error. See logs")

    @staticmethod
    def getPerLabelMetrics(y_true, y_pred, save_path=None, verbose=0):
        per_label_metrics = pd.DataFrame()
        vc = y_true.value_counts()
        per_label_metrics.loc[:, 'Label'] = list(vc.index)
        precisions, recalls, _ ,_ = precision_recall_fscore_support(y_true, y_pred, labels=list(vc.index), average=None)
        per_label_metrics.loc[:, 'Precision'] = precisions
        per_label_metrics.loc[:, 'Recall'] = recalls
        per_label_metrics.loc[:, 'Count'] = list(vc)
        if save_path is not None:
            per_label_metrics.to_csv(save_path + '.csv', index=False)
        if verbose:
            print(per_label_metrics.to_string())
    
    @staticmethod
    def computeTopErrors(y_true, y_pred, save_path=None, verbose=0):
        predictions_fp = os.path.join(save_path, "test-predictions.csv")
        y_true = np.array(y_true)
        y_pred = np.array(y_pred)
        
        data = pd.DataFrame({ 'y_true': y_true, 'y_pred': y_pred})
        data.to_csv(predictions_fp, index=False)
        if verbose:
            error_tf = (y_true != y_pred)
            true_labels = y_true[error_tf]
            pred_labels = y_pred[error_tf]
            if true_labels.size != pred_labels.size:
                raise Exception(f'Sizes should be equal {true_labels.size} and {pred_labels.size}')
            counts = pd.DataFrame({
                'True Label': true_labels,
                'Pred Label': pred_labels,
            }).groupby(['True Label', 'Pred Label']).size()

            print('--- Top Errors ---' + '\n')
            print(counts.to_string())
        return
    
    @staticmethod
    def getMetrics(y_train_true:pd.Series, y_train_pred:pd.Series, y_test_true:pd.Series, y_test_pred:pd.Series, average:str='macro') -> tuple: 
        if average is None:
            average = 'macro'
        if (y_train_true is not None) and (y_train_pred is not None):
            train_accuracy = accuracy_score(y_train_true, y_train_pred)
        else:
            train_accuracy = None
        if (y_test_true is not None) and (y_test_pred is not None):
            test_accuracy = accuracy_score(y_test_true, y_test_pred)
            [precision, recall, fscore, support] = precision_recall_fscore_support(y_test_true, y_test_pred, average=average)
        else:
            test_accuracy = None
            precision = None
            recall = None
            fscore = None
        return test_accuracy, train_accuracy, precision, recall, fscore
    
    def fitClassifier(self, X, y):
        X.fillna(0, inplace=True)
        X.reset_index(drop=True, inplace=True)
        y.reset_index(drop=True, inplace=True)
    
        self.initClf()
        self.clf.fit(X, y)
        self.fs.save()

    def predict(self, X):
        X.reset_index(drop=True, inplace=True)
        return self.clf.predict(X)
    
    def predict_probs(self, X):
        preds = self.clf.predict_proba(X)
        return preds

    def main(self, train_data, test_data=None):
        metric_average = self.train_config.mt_vals['metric_average']
        errors = self.train_config.mt_vals['errors']
        per_label_metrics = self.train_config.mt_vals['per_label_metrics']
        plot_cm = self.train_config.mt_vals['plot_cm']
        print_metrics = self.train_config.mt_vals['print_metrics']
        features = self.train_config.mt_vals['features']

        if not isinstance(train_data, pd.DataFrame): raise ValueError(f'train_data should be pd.DataFrame given {type(train_data)}')
        y_train = train_data[self.label_col]
        self.fs.fit(train_data)
        X_train = self.fs.transform(train_data)
        self.fitClassifier(X_train, y_train)
        y_train_pred = self.predict(X_train)
        print("---Train Metrics---")
        computeMetrics(y_train, y_train_pred, average=metric_average, print_metrics=print_metrics, result_path=os.path.join(self.save_path, "train_metrics"))
            
        if not isinstance(test_data, pd.DataFrame):
            X_test = None
            y_test = None
            y_test_pred = None
            return
        
        X_test = self.fs.transform(test_data)
        y_test = test_data[self.label_col]
        y_test_pred = self.predict(X_test)
        print("---Test Metrics---")
        computeMetrics(y_test, y_test_pred, average=metric_average, print_metrics=True, result_path=os.path.join(self.save_path, "test_metrics"))

        if features:
            self.computeFeatureImportances(self.clf, X_train, y_train, save_path=self.save_path)
        if errors:
            self.computeTopErrors(y_test, y_test_pred, save_path=self.save_path)
        if per_label_metrics and y_test_pred is not None: 
            self.getPerLabelMetrics(y_test, y_test_pred, save_path=os.path.join(self.save_path, 'per_label'), verbose=0)

    def run(self):
        data = self.loadData()
        test_size = self.train_config.mt_vals['test_size']
        max_samples = self.train_config.mt_vals['max_samples']
                
        # Shuffle the data
        data = data.sample(frac=1).reset_index(drop=True)

        # Split the data
        if test_size > 0:
            train_data, test_data = train_test_split(data, test_size=test_size)
            l.info(f'Splitting Train and Test Data: train_size={train_data.shape[0]}, test_size={test_data.shape[0]}')
        else:
            train_data, test_data = data, None
            l.info(f'Splitting Train and Test Data: train_size={train_data.shape[0]}, test_size=0')
        
        # If the max samples are limited. Take that many for each label
        if max_samples is not None:
            train_data = train_data.groupby(self.label_col, as_index=False).head(max_samples)
            l.info(f'Max Sampling Data: max_samples={max_samples}, train_size={train_data.shape[0]}, test_size={test_data.shape[0] if test_data is not None else 0}, unique_labels={train_data[self.label_col].nunique()}')
        
        # Fit the model
        self.main(train_data, test_data)


                
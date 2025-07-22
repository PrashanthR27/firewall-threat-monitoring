from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
import numpy as np

def run_isolation_forest(X):
    """
    Detect anomalies in a dataset using the Isolation Forest algorithm.

    Parameters:
        X (pandas.DataFrame): Feature set to fit the model on. Each row represents a data point.

    Returns:
        np.ndarray: An array of anomaly flags with shape (n_samples,):
                    -1 indicates an anomaly, and
                     1 indicates a normal point.
    """
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    return model.fit_predict(X)

def run_oneclass_svm(X):
    """
    Detect anomalies in a dataset using the One Class SVM algorithm.

    Parameters:
        X (pandas.DataFrame): Feature set to fit the model on. Each row represents a data point.

    Returns:
        np.ndarray: An array of anomaly flags with shape (n_samples,):
                    -1 indicates an anomaly, and
                     1 indicates a normal point.
    """
    model = OneClassSVM(kernel='rbf', gamma='scale', nu=0.05)
    return model.fit_predict(X)

def run_dbscan(X):
    """
    Detect anomalies in a dataset using the DBSCAN algorithm.

    Parameters:
        X (pandas.DataFrame): Feature set to fit the model on. Each row represents a data point.

    Returns:
        np.ndarray: An array of anomaly flags with shape (n_samples,):
                    -1 indicates an anomaly, and
                     1 indicates a normal point.
    """
    model = DBSCAN(eps=1.5, min_samples=10)
    cluster_labels = model.fit_predict(X)

    # Convert all non-outliers (not -1) to 1 (normal)
    binary_labels = np.where(cluster_labels == -1, -1, 1)
    return binary_labels


import pandas as pd
import yaml
from src.preprocessing import preprocess_data
from src.models import run_isolation_forest, run_oneclass_svm, run_dbscan
from src.utils import get_anomaly_summary_text, tag_threats

def main(filepath: str, algo: str = None):
    """
    Run firewall log anomaly detection and threat tagging pipeline.

    This function performs the following steps:
    1. Loads configuration settings from a YAML file.
    2. Preprocesses the raw log data to prepare features.
    3. Applies the selected anomaly detection algorithm (Isolation Forest, One-Class SVM, or DBSCAN).
    4. Attaches anomaly labels to the original log data.
    5. Tags threats based on predefined rules.
    6. Returns the final DataFrame with anomaly flags and threat types.

    Parameters:
        filepath (str): Path to the raw firewall log CSV file.
        algo (str, optional): Anomaly detection algorithm to use.
                              If not provided, uses the default from the YAML config.
                              Options: 'isolation_forest', 'oneclass_svm', 'dbscan'.

    Returns:
        pd.DataFrame: DataFrame with original log entries, anomaly labels (-1 for anomaly, 1 for normal),
                      and threat type tags.
    """

    with open('config/config.yaml') as f:
        config = yaml.safe_load(f)

    algo = algo or config['algorithm']
    df = preprocess_data(filepath)

    # Keep a copy of original (non-feature-engineered) data for threat tagging
    original_df = pd.read_csv(filepath)

    feature_cols = config['features'][algo]
    X = df[feature_cols]

    if algo == 'isolation_forest':
        df['anomaly'] = run_isolation_forest(X)
    elif algo == 'oneclass_svm':
        df['anomaly'] = run_oneclass_svm(X)
    elif algo == 'dbscan':
        df['anomaly'] = run_dbscan(X)
    else:
        raise ValueError("Unsupported algorithm")

    # Merge anomaly column back to original data
    original_df['anomaly'] = df['anomaly'].values

    # Apply threat tagging
    tagged_df = tag_threats(original_df)

    summary = get_anomaly_summary_text(df)
    print(summary)

    return tagged_df


if __name__ == "__main__":
    df = main('data/raw/log2.csv', algo = "dbscan")
    df.to_csv('data/result/anomaly_results.csv', index=False)


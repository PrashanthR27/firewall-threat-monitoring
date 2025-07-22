import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
import yaml

with open('config/config.yaml') as f:
    config = yaml.safe_load(f)

def create_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Generate additional features from firewall log data to support anomaly detection.

    This function adds the following engineered features:
    - `byte_ratio`: Ratio of bytes sent to bytes received (with smoothing).
    - `packet_ratio`: Ratio of packets sent to packets received (with smoothing).
    - `src_port_entropy_bin`: Binned category of source port based on entropy (Well-known, Registered, Dynamic).
    - `dst_port_entropy_bin`: Binned category of destination port based on entropy (Well-known, Registered, Dynamic).
    - `nat_port_shift`: Absolute difference between NAT destination port and actual destination port.
    - `is_suspicious_port`: Binary indicator (1/0) for whether the destination port is considered suspicious.

    Parameters:
        df (pd.DataFrame): The input dataframe containing raw firewall log data.

    Returns:
        pd.DataFrame: A dataframe with the original and newly engineered features.

    Note:
        This function depends on a global `config` dictionary that must define:
        - `port_bins`: List of port number boundaries for categorization.
        - `risky_ports`: Set of port numbers considered suspicious.
    """

    df['byte_ratio'] = (df['Bytes Sent'] + 1) / (df['Bytes Received'] + 1)
    df['packet_ratio'] = (df['pkts_sent'] + 1) / (df['pkts_received'] + 1)

    # Port categories
    df['src_port_entropy_bin'] = pd.cut(df['Source Port'], bins=config['port_bins'],
                                        labels=['Well-known', 'Registered', 'Dynamic'])
    df['dst_port_entropy_bin'] = pd.cut(df['Destination Port'], bins=config['port_bins'],
                                        labels=['Well-known', 'Registered', 'Dynamic'])

    # NAT port deviation 
    df['nat_port_shift'] = abs(df['NAT Destination Port'] - df['Destination Port'])

    # Suspicious destination ports (like SSH, RDP, SMB)
    df['is_suspicious_port'] = df['Destination Port'].apply(lambda x: 1 if x in config['risky_ports'] else 0)

    return df

def preprocess_data(filepath: str) -> pd.DataFrame:
    """
    Load and preprocess firewall log data for anomaly detection.

    This function performs the following preprocessing steps:
    - Loads the CSV data from the specified file path.
    - Fills missing values:
        - Numeric columns: filled with median values.
        - Non-numeric columns: filled with the mode.
    - Drops any remaining rows with missing values.
    - Creates engineered features (e.g., ratios, port binning, port risk indicators).
    - Encodes categorical columns using label encoding.
    - Scales only selected raw numerical features using standardization.

    Parameters:
        filepath (str): Path to the raw firewall log CSV file.

    Returns:
        pd.DataFrame: A fully preprocessed DataFrame ready for modeling.

    Notes:
        This function relies on a global `config` dictionary that must define:
        - 'categorical_columns': List of column names to be label-encoded.
        - 'scaling_features': List of raw features to be scaled.
        - `port_bins` and `risky_ports` used in `create_features()` function.
    """
    df = pd.read_csv(filepath)

    # Fill missing values for numeric columns using median
    num_cols = df.select_dtypes(include='number').columns
    df[num_cols] = df[num_cols].fillna(df[num_cols].median())

    # Fill missing values for non-numeric columns using mode
    non_num_cols = df.select_dtypes(exclude='number').columns
    for col in non_num_cols:
        if df[col].isnull().any():
            mode_val = df[col].mode(dropna=True)
            if not mode_val.empty:
                df[col].fillna(mode_val[0], inplace=True)

    # Optional: if still NaN's are present, drop rows 
    df.dropna(inplace=True)

    # create features
    df = create_features(df)

    # Encode categorical columns
    for col in config['categorical_columns']:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])

    # Scale only raw features
    scaler = StandardScaler()
    df[config['scaling_features']] = scaler.fit_transform(df[config['scaling_features']])

    return df
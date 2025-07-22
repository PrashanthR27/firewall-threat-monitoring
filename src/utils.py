import yaml

with open('config/config.yaml') as f:
    config = yaml.safe_load(f)

def tag_threats(df):
    """
    Tags rows in the firewall log DataFrame with a threat type based on anomaly prediction.

    Args:
        df (pd.DataFrame): Input DataFrame containing at least the columns:
            'anomaly', 'Action', 'Bytes', 'pkts_sent', 'pkts_received', 'Destination Port'

    Returns:
        pd.DataFrame: Updated DataFrame with a new 'threat_type' column.
    """
    risky_ports = config['risky_ports']
    byte_threshold = df['Bytes'].quantile(0.99)

    def tag_row(row):
        if row['anomaly'] == 1:
            return 'Normal'
        if row['Action'] in ['deny', 'reset-both']:
            return 'Intrusion Attempt'
        elif row['Bytes'] > byte_threshold:
            return 'Traffic Spike'
        elif row['pkts_sent'] == 0 or row['pkts_received'] == 0:
            return 'Packet Drop / Error'
        elif row['Destination Port'] in risky_ports:
            return 'Suspicious Port Activity'
        else:
            return 'Malware Communication'

    df['threat_type'] = df.apply(tag_row, axis=1)
    return df

def get_summary(df, timeframe='1H'):
    """
    Generates a summary of threat types over time by resampling the data.

    Groups and counts occurrences of each `threat_type` in the dataframe over a given
    resampling timeframe (e.g., hourly, every 12 hours, every 24 hours).

    Parameters:
        df (pandas.DataFrame): Input DataFrame that must contain a 'timestamp' column 
                               (datetime type) and a 'threat_type' column.
        timeframe (str): Resampling frequency string. Common values:
                         - '1H' for hourly
                         - '12H' for every 12 hours
                         - '24H' for every 24 hours

    Returns:
        pandas.DataFrame: A summary DataFrame where each row corresponds to a time window
                          and each column (besides 'timestamp') represents a threat type
                          with counts of its occurrences.
    """
    df_time = df.set_index('timestamp').copy()
    summary = df_time.resample(timeframe)['threat_type'].value_counts().unstack(fill_value=0)
    summary = summary.reset_index()
    return summary

def get_anomaly_summary_text(results):
    """
    Generate a markdown-formatted summary of anomaly detection results.

    This function counts the number of anomalies (-1) and normal records (1)
    from the 'anomaly' column of a given DataFrame and returns a markdown
    string displaying the counts and percentages.

    Parameters:
        results (pd.DataFrame): A DataFrame that must contain a column named 'anomaly'
                                with values -1 (anomaly) and 1 (normal).

    Returns:
        str: A markdown-formatted summary string showing the counts and percentages of
             anomalies and normal data points.
    """
    total = len(results)
    anomaly_count = (results['anomaly'] == -1).sum()
    normal_count = (results['anomaly'] == 1).sum()

    summary = f"""
                    ### 📊 Anomaly Detection Summary
                    | Type             | Count | Percentage |
                    |------------------|--------|-------------|
                    | 🔴 Anomalies     | {anomaly_count:,} | {anomaly_count / total:.2%} |
                    | 🟢 Normal        | {normal_count:,} | {normal_count / total:.2%} |
                    | 📁 Total Records | {total:,} | 100.00% |
                """
    return summary

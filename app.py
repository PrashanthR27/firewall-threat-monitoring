import streamlit as st
import pandas as pd
import plotly.express as px
from src.utils import get_summary, get_anomaly_summary_text
from main import main

# ------------------- Streamlit Page Setup -------------------
st.set_page_config(layout="wide")
st.title("🚨 Firewall Incident Monitoring Dashboard")

# ------------------- Sidebar Controls -------------------
algo = st.sidebar.selectbox(
    "Select Anomaly Detection Algorithm",
    options=['isolation_forest', 'oneclass_svm', 'dbscan'],
    format_func=lambda x: {
        'isolation_forest': 'Isolation Forest',
        'oneclass_svm': 'One-Class SVM',
        'dbscan': 'DBSCAN'
    }[x]
)

timeframe = st.sidebar.selectbox(
    "Select Time Window",
    ['1H', '12H', '24H'],
    format_func=lambda x: {
        '1H': 'Hourly', '12H': '12 Hours', '24H': '24 Hours'
    }[x]
)

# ------------------- Load Data -------------------
@st.cache_data(show_spinner=True)
def load_data(algo_choice):
    df = main('data/raw/log2.csv', algo=algo_choice)
    df['timestamp'] = pd.date_range(start='2024-01-01', periods=len(df), freq='T')
    return df

df = load_data(algo)

# ------------------- Compute Threat Summary -------------------
summary = get_summary(df, timeframe)

# ------------------- Display Outputs -------------------
st.subheader(f"🧾 Incident Summary - {timeframe}")
st.dataframe(summary)

# Plot: Stacked bar chart of threats over time
summary_melted = summary.melt(id_vars='timestamp', var_name='Threat Type', value_name='Count')
fig = px.bar(
    summary_melted,
    x='timestamp',
    y='Count',
    color='Threat Type',
    title="📊 Threat/Anomaly Counts Over Time",
    height=500
)
st.plotly_chart(fig, use_container_width=True)

# Show anomaly summary (constant regardless of timeframe)
st.markdown(get_anomaly_summary_text(df))

# Optional: View raw processed data
with st.expander("🔍 View Raw Processed Data"):
    st.dataframe(df.head(100), use_container_width=True)

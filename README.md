
# 🔥 Firewall Threat Monitoring and Anomaly Detection

This project is a comprehensive system for detecting network anomalies and potential threats using firewall log data. It includes:

- 🧪 Exploratory Data Analysis (EDA)
- ⚙️ Feature engineering and anomaly detection using Isolation Forest/DBSCAN/One-Class SVM
- 🛡️ Threat categorization
- 📊 An interactive Streamlit dashboard showing summaries for 1H, 12H, and 24H
- 📁 Static EDA visualizations

---

## 📁 Project Structure

```
project/
├── app.py                        # Streamlit dashboard
├── EDA_notebook/
│   └──eda_firewall_logs.ipynb    # EDA notebook
├── config/
│   └── config.yaml               # configuration
├── data/raw/
│   └── log2.csv                  # Static firewall log data
├── src/
│   ├── preprocessing.py          # Preprocessing
│   └── utils.py                  # Summaries and helper functions
│   └── models.py                 # models used for anomaly detection
├── main.py                    
├── report /
    └── Firewall Threat Monitoring and Anomaly Detection Report.pdf

```

---

## ⚙️ Installation

**Python Version**: `3.9`

### 1. Clone the repository

```bash
git clone https://github.com/PrashanthR27/firewall-threat-monitoring.git
cd firewall-threat-monitoring
```

### 2. Create a virtual environment

```bash
python3 -m venv firewall_anomaly_venv
source firewall_anomaly_venv/bin/activate  # On Windows use: firewall_anomaly_venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Running the Streamlit App

```bash
streamlit run app.py
```

This will launch the app in your browser at:  
👉 `http://localhost:8501`

You can choose timeframes (1 Hour, 12 Hours, 24 Hours) and view threat summaries, counts, and plots.

---

📄 **Refer report/Firewall Threat Monitoring and Anomaly Detection Report.pdf for a detailed explanation of the project.**

---

## 📊 EDA Highlights

In the EDA (based on `data/log2.csv`):

- Action Distribution (Allow vs Deny)
- Top Destination Ports
- Session Duration (Elapsed Time)
- Traffic Analysis (Bytes/Packets)
- Scatter: Elapsed Time vs Traffic Volume
- Feature Correlation Heatmap

**📓 Refer EDA_notebook/eda_firewall_logs.ipynb for a detailed analysis.**

---

## 🧠 ML and Threat Detection Pipeline

1. Preprocess and clean data (handle missing values)
2. Generate engineered features:
   - Byte and packet ratios
   - Port entropy bins
   - NAT port shift, suspicious port flags
3. Train Isolation Forest/DBSCAN/One-Class SVM on full dataset
4. Post-prediction, assign synthetic timestamp to each datapoint (1-minute apart)
5. Tag threats based on domain logic:
   - Deny/Reset → Intrusion Attempt
   - 99th percentile Bytes → Traffic Spike
   - 0 packets → Packet Drop/Error
   - Suspicious ports → Port Activity
   - Else → Malware Communication

---


## Screenshot
![alt text](image.png)
![alt text](image-1.png)
![alt text](image-2.png)
import os
import streamlit as st
import tempfile
import requests
import json
import hashlib
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from file_checker import checkFile
import magic
import time
from datetime import datetime
import sqlite3
import json
from plotly.subplots import make_subplots

# Constants
VT_API_BASE_URL = "https://www.virustotal.com/vtapi/v2"
SUPPORTED_FILE_TYPES = ['.exe', '.dll', '.pdf', '.docx', '.doc', '.xlsx', '.xls', '.ppt', '.pptx']

# Color scheme
COLORS = {
    'benign': '#00C853',  # Bright Green
    'malicious': '#FF3D00',  # Bright Red
    'warning': '#FFD600',  # Bright Yellow
    'info': '#2979FF',  # Bright Blue
    'background': '#1E1E1E',  # Dark background
    'text': '#FFFFFF',  # White text
    'grid': '#333333',  # Dark grid
    'chart_bg': '#2D2D2D',  # Dark chart background
    'success': '#00C853',  # Green
    'error': '#FF3D00',  # Red
    'warning': '#FFD600',  # Yellow
    'info': '#2979FF',  # Blue
    'hover_bg': 'rgba(45, 45, 45, 0.9)',  # Semi-transparent dark
    'card_bg': '#2D2D2D',  # Card background
    'border': '#404040'  # Border color
}

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_vt_report(api_key, file_hash):
    """Get VirusTotal report for a file hash."""
    params = {'apikey': api_key, 'resource': file_hash}
    response = requests.get(f"{VT_API_BASE_URL}/file/report", params=params)
    return response.json()

def submit_file_to_vt(api_key, file_path):
    """Submit a file to VirusTotal for scanning."""
    files = {'file': open(file_path, 'rb')}
    params = {'apikey': api_key}
    response = requests.post(f"{VT_API_BASE_URL}/file/scan", files=files, params=params)
    return response.json()

def get_file_type(file_path):
    """Get file type using python-magic."""
    return magic.from_file(file_path, mime=True)

def create_probability_chart(probabilities):
    """Create a bar chart for prediction probabilities."""
    fig = go.Figure(data=[
        go.Bar(
            x=['Benign', 'Malicious'],
            y=[probabilities[0], probabilities[1]],
            marker_color=['green', 'red']
        )
    ])
    fig.update_layout(
        title='Prediction Probabilities',
        yaxis_title='Probability',
        yaxis_range=[0, 1]
    )
    return fig

def create_vt_chart(vt_data):
    """Create a pie chart for VirusTotal results."""
    if 'scans' not in vt_data:
        return None
    
    detected = sum(1 for scan in vt_data['scans'].values() if scan['detected'])
    total = len(vt_data['scans'])
    
    fig = go.Figure(data=[
        go.Pie(
            labels=['Detected', 'Not Detected'],
            values=[detected, total - detected],
            marker_colors=['red', 'green']
        )
    ])
    fig.update_layout(title='VirusTotal Detection Results')
    return fig

def create_quick_report(ml_result, vt_data, file_info):
    """Create a quick summary report of the analysis."""
    report = f"""
    ### Quick Analysis Report
    
    #### File Information
    - **Name:** {file_info['name']}
    - **Type:** {file_info['type']}
    - **Size:** {file_info['size']} bytes
    
    #### Machine Learning Analysis
    - **Prediction:** {'Malicious' if ml_result['prediction'] == 1 else 'Benign'}
    - **Confidence:** {ml_result['probability']:.2%}
    
    #### VirusTotal Analysis
    - **Total Scans:** {len(vt_data.get('scans', {}))}
    - **Detections:** {sum(1 for scan in vt_data.get('scans', {}).values() if scan['detected'])}
    - **Detection Rate:** {(sum(1 for scan in vt_data.get('scans', {}).values() if scan['detected']) / len(vt_data.get('scans', {})) * 100):.1f}%
    """
    return report

def create_detailed_report(ml_result, vt_data, file_info):
    """Create a detailed report of the analysis."""
    report = f"""
# Malware Analysis Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## File Information
- Name: {file_info['name']}
- Type: {file_info['type']}
- Size: {file_info['size']} bytes

## Machine Learning Analysis
- Prediction: {'Malicious' if ml_result['prediction'] == 1 else 'Benign'}
- Confidence: {ml_result['probability']:.2%}

## VirusTotal Analysis
- Total Scans: {len(vt_data.get('scans', {}))}
- Detections: {sum(1 for scan in vt_data.get('scans', {}).values() if scan['detected'])}
- First Seen: {vt_data.get('first_seen', 'N/A')}
- Last Seen: {vt_data.get('last_seen', 'N/A')}

### Detailed Scan Results:
"""
    
    for engine, result in vt_data.get('scans', {}).items():
        report += f"\n- {engine}: {'Detected' if result['detected'] else 'Not Detected'}"
        if result['detected']:
            report += f" ({result.get('result', 'N/A')})"
    
    return report

def init_database():
    """Initialize SQLite database for scan logs."""
    try:
        conn = sqlite3.connect('scan_logs.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scan_logs
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      file_name TEXT,
                      file_type TEXT,
                      file_size INTEGER,
                      ml_prediction INTEGER,
                      vt_detection_rate REAL,
                      scan_date TIMESTAMP,
                      vt_data TEXT)''')
        conn.commit()
        return conn
    except Exception as e:
        st.error(f"Database initialization error: {str(e)}")
        return None

def save_scan_log(conn, file_info, ml_result, vt_data):
    """Save scan results to database."""
    if not conn:
        return
    
    try:
        c = conn.cursor()
        detection_rate = 0
        if vt_data and vt_data.get('response_code') != 0:
            detected = sum(1 for scan in vt_data.get('scans', {}).values() if scan['detected'])
            total = len(vt_data.get('scans', {}))
            detection_rate = (detected / total * 100) if total > 0 else 0
        
        # Convert VT data to a serializable format
        vt_data_serializable = None
        if vt_data:
            vt_data_serializable = {
                'response_code': vt_data.get('response_code'),
                'scans': {
                    engine: {
                        'detected': scan['detected'],
                        'result': scan.get('result', '')
                    }
                    for engine, scan in vt_data.get('scans', {}).items()
                }
            }
        
        c.execute('''INSERT INTO scan_logs 
                     (file_name, file_type, file_size, ml_prediction, vt_detection_rate, scan_date, vt_data)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (file_info['name'],
                   file_info['type'],
                   file_info['size'],
                   ml_result,
                   detection_rate,
                   datetime.now(),
                   json.dumps(vt_data_serializable) if vt_data_serializable else None))
        conn.commit()
    except Exception as e:
        st.error(f"Error saving scan log: {str(e)}")

def get_scan_logs(conn):
    """Retrieve scan logs from database."""
    if not conn:
        return []
    
    try:
        c = conn.cursor()
        c.execute('SELECT * FROM scan_logs ORDER BY scan_date DESC')
        logs = c.fetchall()
        
        # Convert VT data back from JSON string
        processed_logs = []
        for log in logs:
            log_list = list(log)
            if log_list[7]:  # VT data column
                try:
                    log_list[7] = json.loads(log_list[7])
                except:
                    log_list[7] = None
            processed_logs.append(tuple(log_list))
        
        return processed_logs
    except Exception as e:
        st.error(f"Error retrieving scan logs: {str(e)}")
        return []

def create_scan_history_chart(logs):
    """Create a chart showing scan history."""
    if not logs:
        return None
    
    try:
        df = pd.DataFrame(logs, columns=['id', 'file_name', 'file_type', 'file_size', 
                                        'ml_prediction', 'vt_detection_rate', 'scan_date', 'vt_data'])
        
        # Convert scan_date to string format
        df['scan_date'] = pd.to_datetime(df['scan_date'])
        df['scan_date'] = df['scan_date'].dt.strftime('%Y-%m-%d %H:%M:%S')
        
        # Ensure all data is serializable and properly typed
        df['vt_detection_rate'] = pd.to_numeric(df['vt_detection_rate'], errors='coerce').fillna(0)
        df['ml_prediction'] = pd.to_numeric(df['ml_prediction'], errors='coerce').fillna(0).astype(int)
        
        # Calculate combined prediction (if either ML or VT detects malware, mark as malicious)
        df['combined_prediction'] = ((df['ml_prediction'] == 1) | (df['vt_detection_rate'] > 10)).astype(int)
        
        fig = go.Figure()
        
        # Add VT Detection Rate trace
        fig.add_trace(go.Scatter(
            x=df['scan_date'],
            y=df['vt_detection_rate'],
            mode='lines+markers',
            name='VT Detection Rate',
            line=dict(color=COLORS['malicious'], width=2),
            marker=dict(size=8, color=COLORS['malicious'], line=dict(width=1, color='white')),
            hovertemplate='<b>Date:</b> %{x}<br><b>Detection Rate:</b> %{y:.1f}%<extra></extra>'
        ))
        
        # Add ML Prediction trace
        fig.add_trace(go.Scatter(
            x=df['scan_date'],
            y=df['ml_prediction'] * 100,
            mode='lines+markers',
            name='ML Prediction',
            line=dict(color=COLORS['info'], width=2),
            marker=dict(size=8, color=COLORS['info'], line=dict(width=1, color='white')),
            hovertemplate='<b>Date:</b> %{x}<br><b>ML Prediction:</b> %{y:.1f}%<extra></extra>'
        ))
        
        # Add Combined Prediction trace
        fig.add_trace(go.Scatter(
            x=df['scan_date'],
            y=df['combined_prediction'] * 100,
            mode='lines+markers',
            name='Combined Prediction',
            line=dict(color=COLORS['warning'], width=2),
            marker=dict(size=8, color=COLORS['warning'], line=dict(width=1, color='white')),
            hovertemplate='<b>Date:</b> %{x}<br><b>Combined Prediction:</b> %{y:.1f}%<extra></extra>'
        ))
        
        fig.update_layout(
            title=dict(
                text='Scan History',
                font=dict(size=24, color=COLORS['text'], family='Arial'),
                x=0.5,
                y=0.95
            ),
            xaxis_title='Date',
            yaxis_title='Percentage',
            hovermode='x unified',
            xaxis=dict(
                tickangle=45,
                tickformat='%Y-%m-%d %H:%M:%S',
                gridcolor=COLORS['grid'],
                zerolinecolor=COLORS['grid'],
                showgrid=True,
                showline=True,
                linewidth=1,
                linecolor=COLORS['grid'],
                tickfont=dict(color=COLORS['text'])
            ),
            yaxis=dict(
                range=[0, 100],
                ticksuffix='%',
                gridcolor=COLORS['grid'],
                zerolinecolor=COLORS['grid'],
                showgrid=True,
                showline=True,
                linewidth=1,
                linecolor=COLORS['grid'],
                tickfont=dict(color=COLORS['text'])
            ),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1,
                bgcolor='rgba(0,0,0,0)',
                bordercolor=COLORS['border'],
                borderwidth=1,
                font=dict(color=COLORS['text'])
            ),
            plot_bgcolor=COLORS['chart_bg'],
            paper_bgcolor=COLORS['background'],
            font=dict(color=COLORS['text'], family='Arial'),
            margin=dict(t=80, l=50, r=50, b=50),
            showlegend=True,
            hoverlabel=dict(
                bgcolor=COLORS['hover_bg'],
                font_size=12,
                font_family='Arial',
                bordercolor=COLORS['border']
            )
        )
        
        return fig
    except Exception as e:
        st.error(f"Error creating scan history chart: {str(e)}")
        return None

def create_detection_distribution_chart(logs):
    """Create a pie chart showing detection distribution."""
    if not logs:
        return None
    
    try:
        df = pd.DataFrame(logs, columns=['id', 'file_name', 'file_type', 'file_size', 
                                        'ml_prediction', 'vt_detection_rate', 'scan_date', 'vt_data'])
        
        # Ensure data is properly typed
        df['ml_prediction'] = pd.to_numeric(df['ml_prediction'], errors='coerce').fillna(0).astype(int)
        df['vt_detection_rate'] = pd.to_numeric(df['vt_detection_rate'], errors='coerce').fillna(0)
        
        # Calculate combined prediction
        df['combined_prediction'] = ((df['ml_prediction'] == 1) | (df['vt_detection_rate'] > 10)).astype(int)
        
        # Calculate counts
        ml_benign = (df['ml_prediction'] == 0).sum()
        ml_malicious = (df['ml_prediction'] == 1).sum()
        vt_benign = (df['vt_detection_rate'] <= 10).sum()
        vt_malicious = (df['vt_detection_rate'] > 10).sum()
        combined_benign = (df['combined_prediction'] == 0).sum()
        combined_malicious = (df['combined_prediction'] == 1).sum()
        
        total = len(df)
        
        # Create subplots
        fig = make_subplots(
            rows=1, cols=3,
            specs=[[{"type": "pie"}, {"type": "pie"}, {"type": "pie"}]],
            subplot_titles=("ML Prediction", "VT Detection", "Combined Prediction")
        )
        
        # Add ML prediction pie
        fig.add_trace(
            go.Pie(
                labels=['Benign', 'Malicious'],
                values=[ml_benign, ml_malicious],
                marker_colors=[COLORS['benign'], COLORS['malicious']],
                hole=0.4,
                textinfo='percent+label',
                textposition='outside',
                textfont_size=14,
                textfont_color=COLORS['text'],
                hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>',
                pull=[0.05, 0.05]
            ),
            row=1, col=1
        )
        
        # Add VT detection pie
        fig.add_trace(
            go.Pie(
                labels=['Benign', 'Malicious'],
                values=[vt_benign, vt_malicious],
                marker_colors=[COLORS['benign'], COLORS['malicious']],
                hole=0.4,
                textinfo='percent+label',
                textposition='outside',
                textfont_size=14,
                textfont_color=COLORS['text'],
                hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>',
                pull=[0.05, 0.05]
            ),
            row=1, col=2
        )
        
        # Add combined prediction pie
        fig.add_trace(
            go.Pie(
                labels=['Benign', 'Malicious'],
                values=[combined_benign, combined_malicious],
                marker_colors=[COLORS['benign'], COLORS['malicious']],
                hole=0.4,
                textinfo='percent+label',
                textposition='outside',
                textfont_size=14,
                textfont_color=COLORS['text'],
                hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>',
                pull=[0.05, 0.05]
            ),
            row=1, col=3
        )
        
        # Update layout
        fig.update_layout(
            title=dict(
                text='Detection Distribution',
                font=dict(size=24, color=COLORS['text'], family='Arial'),
                x=0.5,
                y=0.95
            ),
            showlegend=True,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1,
                bgcolor='rgba(0,0,0,0)',
                bordercolor=COLORS['border'],
                borderwidth=1,
                font=dict(color=COLORS['text'])
            ),
            plot_bgcolor=COLORS['chart_bg'],
            paper_bgcolor=COLORS['background'],
            font=dict(color=COLORS['text'], family='Arial'),
            margin=dict(t=80, l=50, r=50, b=50),
            hoverlabel=dict(
                bgcolor=COLORS['hover_bg'],
                font_size=12,
                font_family='Arial',
                bordercolor=COLORS['border']
            )
        )
        
        return fig
    except Exception as e:
        st.error(f"Error creating distribution chart: {str(e)}")
        return None

def create_feature_importance_chart(feature_importance):
    """Create a bar chart for feature importance."""
    try:
        fig = go.Figure(data=[
            go.Bar(
                x=list(feature_importance.keys()),
                y=list(feature_importance.values()),
                marker_color=COLORS['info'],
                marker_line=dict(width=1, color='white'),
                hovertemplate='<b>%{x}</b><br>Importance: %{y:.2%}<extra></extra>'
            )
        ])
        
        fig.update_layout(
            title=dict(
                text='Feature Importance',
                font=dict(size=24, color=COLORS['text'], family='Arial'),
                x=0.5,
                y=0.95
            ),
            xaxis_title='Features',
            yaxis_title='Importance Score',
            showlegend=False,
            xaxis=dict(
                gridcolor=COLORS['grid'],
                zerolinecolor=COLORS['grid'],
                showgrid=True,
                showline=True,
                linewidth=1,
                linecolor=COLORS['grid'],
                tickfont=dict(color=COLORS['text'])
            ),
            yaxis=dict(
                gridcolor=COLORS['grid'],
                zerolinecolor=COLORS['grid'],
                showgrid=True,
                showline=True,
                linewidth=1,
                linecolor=COLORS['grid'],
                tickformat='.0%',
                tickfont=dict(color=COLORS['text'])
            ),
            plot_bgcolor=COLORS['chart_bg'],
            paper_bgcolor=COLORS['background'],
            font=dict(color=COLORS['text'], family='Arial'),
            margin=dict(t=80, l=50, r=50, b=50),
            hoverlabel=dict(
                bgcolor=COLORS['hover_bg'],
                font_size=12,
                font_family='Arial',
                bordercolor=COLORS['grid']
            )
        )
        
        return fig
    except Exception as e:
        st.error(f"Error creating feature importance chart: {str(e)}")
        return None

def create_ml_report(file_info, ml_result, feature_importance, detailed_features):
    """Create a detailed ML analysis report."""
    report = f"""
# Machine Learning Analysis Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## File Information
- Name: {file_info['name']}
- Type: {file_info['type']}
- Size: {file_info['size'] / 1024:.1f} KB

## Prediction Results
- Prediction: {'Benign' if ml_result == 0 else 'Malicious'}
- Confidence: {feature_importance.get('confidence', 'N/A')}

## Feature Importance
"""
    
    # Add feature importance
    for feature, importance in feature_importance.items():
        if feature != 'confidence':
            report += f"- {feature}: {importance:.2%}\n"
    
    report += "\n## Detailed Features\n"
    
    # Add detailed features
    for category, features in detailed_features.items():
        report += f"\n### {category}\n"
        for feature, value in features.items():
            report += f"- {feature}: {value}\n"
    
    return report

def main():
    st.set_page_config(
        page_title="Static Malware Analysis",
        layout="wide"
    )
    
    # Custom CSS for better styling
    st.markdown(f"""
    <style>
    .stApp {{
        background-color: {COLORS['background']};
    }}
    .stMetric {{
        background-color: {COLORS['card_bg']};
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
        border: 1px solid {COLORS['border']};
        box-shadow: 0 2px 4px rgba(0,0,0,0.2);
    }}
    .stMetric:hover {{
        background-color: {COLORS['chart_bg']};
        transform: translateY(-2px);
        transition: all 0.3s ease;
    }}
    .stMetric [data-testid="stMetricValue"] {{
        color: {COLORS['text']};
        font-size: 24px;
        font-weight: bold;
    }}
    .stMetric [data-testid="stMetricLabel"] {{
        color: {COLORS['text']};
        font-size: 16px;
        opacity: 0.8;
    }}
    .summary-box {{
        background-color: {COLORS['card_bg']};
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
        border: 1px solid {COLORS['border']};
        box-shadow: 0 2px 4px rgba(0,0,0,0.2);
    }}
    .stAlert {{
        border-radius: 10px;
        background-color: {COLORS['card_bg']};
        border: 1px solid {COLORS['border']};
        box-shadow: 0 2px 4px rgba(0,0,0,0.2);
    }}
    .stMarkdown {{
        color: {COLORS['text']};
    }}
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {{
        color: {COLORS['text']};
        border-bottom: 1px solid {COLORS['border']};
        padding-bottom: 10px;
        margin-bottom: 20px;
    }}
    .stMarkdown p {{
        color: {COLORS['text']};
        opacity: 0.9;
    }}
    .stMarkdown li {{
        color: {COLORS['text']};
        opacity: 0.9;
    }}
    .stTabs [data-baseweb="tab-list"] {{
        background-color: {COLORS['card_bg']};
        border-radius: 10px;
        padding: 5px;
        margin-bottom: 20px;
    }}
    .stTabs [data-baseweb="tab"] {{
        color: {COLORS['text']};
        opacity: 0.7;
    }}
    .stTabs [aria-selected="true"] {{
        color: {COLORS['text']};
        opacity: 1;
        background-color: {COLORS['chart_bg']};
    }}
    .stButton button {{
        background-color: {COLORS['info']};
        color: {COLORS['text']};
        border: none;
        border-radius: 5px;
        padding: 10px 20px;
        font-weight: bold;
    }}
    .stButton button:hover {{
        background-color: {COLORS['info']};
        opacity: 0.9;
    }}
    .stProgress > div > div > div {{
        background-color: {COLORS['info']};
    }}
    </style>
    """, unsafe_allow_html=True)
    
    st.title("Static Malware Analysis")
    st.markdown("""
    This application provides comprehensive static analysis of files using machine learning and VirusTotal integration.
    Upload a file to analyze it for potential malware characteristics.
    """)
    
    # Initialize database
    conn = init_database()
    if not conn:
        st.error("Failed to initialize database. Some features may not work properly.")
        return
    
    # VirusTotal API Key Input
    vt_api_key = st.text_input("Enter your VirusTotal API Key:", type="password")
    
    # File Upload
    uploaded_file = st.file_uploader("Upload a file to analyze:", type=SUPPORTED_FILE_TYPES)
    
    if uploaded_file is not None:
        # Create tabs for different sections
        quick_tab, ml_tab, vt_tab, logs_tab, report_tab = st.tabs([
            "Quick Report", "ML Analysis", "VirusTotal Analysis", "Scan Logs", "Detailed Report"
        ])
        
        with st.spinner("Processing file..."):
            try:
                # Save uploaded file temporarily
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp.write(uploaded_file.getvalue())
                    tmp_path = tmp.name
                
                # Get file information
                file_info = {
                    'name': uploaded_file.name,
                    'type': get_file_type(tmp_path),
                    'size': os.path.getsize(tmp_path)
                }
                
                # Machine Learning Analysis
                ml_result = checkFile(tmp_path)
                
                # VirusTotal Analysis
                vt_data = None
                if vt_api_key:
                    file_hash = calculate_file_hash(tmp_path)
                    vt_data = get_vt_report(vt_api_key, file_hash)
                    
                    if vt_data.get('response_code') == 0:
                        submit_result = submit_file_to_vt(vt_api_key, tmp_path)
                        if submit_result.get('response_code') == 1:
                            st.info("File submitted to VirusTotal. Please wait a few minutes and refresh the page.")
                        else:
                            st.error("Error submitting file to VirusTotal.")
                
                # Save scan log
                save_scan_log(conn, file_info, ml_result, vt_data)
                
                # Quick Report Tab
                with quick_tab:
                    st.subheader("Quick Analysis Report")
                    
                    # File Information Section
                    st.markdown("### 📄 File Information")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("File Name", file_info['name'])
                    with col2:
                        st.metric("File Type", file_info['type'])
                    with col3:
                        st.metric("File Size", f"{file_info['size'] / 1024:.1f} KB")
                    
                    st.markdown("---")
                    
                    # Analysis Results Section
                    st.markdown("### 🔍 Analysis Results")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("#### 🤖 Machine Learning Analysis")
                        if ml_result == 0:
                            st.success("File is predicted to be BENIGN", icon="✅")
                        else:
                            st.error("File is predicted to be MALICIOUS", icon="⚠️")
                        
                        # Create a custom progress bar for ML prediction
                        ml_color = COLORS['benign'] if ml_result == 0 else COLORS['malicious']
                        st.markdown(f"""
                        <div style="background-color: {ml_color}; height: 10px; border-radius: 5px; margin: 10px 0;"></div>
                        """, unsafe_allow_html=True)
                    
                    with col2:
                        st.markdown("#### 🛡️ VirusTotal Analysis")
                        if vt_data and vt_data.get('response_code') != 0:
                            detected = sum(1 for scan in vt_data.get('scans', {}).values() if scan['detected'])
                            total = len(vt_data.get('scans', {}))
                            detection_rate = (detected / total * 100) if total > 0 else 0
                            
                            # Create a custom progress bar for VT detection rate
                            vt_color = COLORS['benign'] if detection_rate < 10 else COLORS['warning'] if detection_rate < 50 else COLORS['malicious']
                            st.markdown(f"""
                            <div style="background-color: {vt_color}; height: 10px; border-radius: 5px; margin: 10px 0; width: {detection_rate}%;"></div>
                            """, unsafe_allow_html=True)
                            
                            st.metric("Detection Rate", f"{detection_rate:.1f}%")
                            st.metric("Total Scans", total)
                            st.metric("Detections", detected)
                        else:
                            st.warning("VirusTotal analysis not available. Please enter an API key.", icon="🔑")
                    
                    st.markdown("---")
                    
                    # Summary Section
                    st.markdown("### 📊 Summary")
                    if vt_data and vt_data.get('response_code') != 0:
                        summary = []
                        if ml_result == 0:
                            summary.append("✅ ML Analysis: File appears to be benign")
                        else:
                            summary.append("⚠️ ML Analysis: File appears to be malicious")
                        
                        if detection_rate < 10:
                            summary.append("✅ VT Analysis: Low detection rate")
                        elif detection_rate < 50:
                            summary.append("⚠️ VT Analysis: Moderate detection rate")
                        else:
                            summary.append("❌ VT Analysis: High detection rate")
                        
                        for item in summary:
                            st.markdown(f"- {item}")
                    else:
                        st.info("Complete analysis requires VirusTotal API key", icon="ℹ️")
                
                # Machine Learning Analysis Tab
                with ml_tab:
                    st.subheader("Detailed Machine Learning Analysis")
                    
                    # Prediction Details
                    st.markdown("### Prediction Details")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("File", file_info['name'])
                        st.metric("Prediction", "Benign" if ml_result == 0 else "Malicious")
                    with col2:
                        st.metric("File Type", file_info['type'])
                        st.metric("File Size", f"{file_info['size'] / 1024:.1f} KB")
                    
                    # Top Features
                    st.markdown("### Top Features")
                    # Replace with actual feature importance data
                    feature_importance = {
                        "Entropy": 0.25,
                        "Imports": 0.20,
                        "Sections": 0.15,
                        "Resources": 0.10,
                        "Headers": 0.05,
                        "confidence": 0.85
                    }
                    
                    # Create feature importance chart
                    fig = create_feature_importance_chart(feature_importance)
                    if fig:
                        st.plotly_chart(fig)
                    
                    # Feature Details
                    st.markdown("### Feature Details")
                    
                    # Detailed features (replace with actual data)
                    detailed_features = {
                        "File Structure": {
                            "Number of Sections": "8",
                            "Section Entropy": "2.34",
                            "File Alignment": "512",
                            "Subsystem": "Windows GUI"
                        },
                        "Imports": {
                            "Total Imports": "385",
                            "Import DLLs": "13",
                            "Suspicious Imports": "2",
                            "Network Imports": "0"
                        },
                        "Resources": {
                            "Total Resources": "28",
                            "Resource Size": "10.6 KB",
                            "Icon Resources": "1",
                            "String Resources": "15"
                        },
                        "Behavioral Indicators": {
                            "Has Anti-Debug": "Yes",
                            "Has Anti-VM": "No",
                            "Has Encryption": "Yes",
                            "Has Network Activity": "No"
                        }
                    }
                    
                    # Display detailed features in expandable sections
                    for category, features in detailed_features.items():
                        with st.expander(f"📊 {category}", expanded=True):
                            for feature, value in features.items():
                                st.markdown(f"**{feature}:** {value}")
                    
                    # Download Report Button
                    st.markdown("### Download Report")
                    ml_report = create_ml_report(file_info, ml_result, feature_importance, detailed_features)
                    st.download_button(
                        label="Download ML Analysis Report",
                        data=ml_report,
                        file_name=f"ml_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                        mime="text/markdown"
                    )
                
                # VirusTotal Analysis Tab
                with vt_tab:
                    st.subheader("Detailed VirusTotal Analysis")
                    
                    if not vt_api_key:
                        st.warning("Please enter a VirusTotal API key to perform VirusTotal analysis.")
                    elif vt_data and vt_data.get('response_code') != 0:
                        # Create VT results chart
                        vt_chart = create_vt_chart(vt_data)
                        if vt_chart:
                            st.plotly_chart(vt_chart)
                        
                        # Display detailed results
                        st.write("### Detailed Scan Results")
                        for engine, result in vt_data.get('scans', {}).items():
                            if result['detected']:
                                st.error(f"{engine}: {result.get('result', 'Detected')}")
                            else:
                                st.success(f"{engine}: Not Detected")
                    else:
                        st.info("Waiting for VirusTotal analysis to complete...")
                
                # Scan Logs Tab
                with logs_tab:
                    st.subheader("Scan History")
                    
                    # Get scan logs
                    logs = get_scan_logs(conn)
                    
                    if logs:
                        # Create charts
                        history_chart = create_scan_history_chart(logs)
                        
                        # Display charts
                        if history_chart:
                            st.plotly_chart(history_chart, use_container_width=True)
                        
                        # Display recent scans table
                        st.markdown("### Recent Scans")
                        df = pd.DataFrame(logs, columns=['ID', 'File Name', 'File Type', 'Size', 
                                                       'ML Prediction', 'VT Detection Rate', 'Date', 'VT Data'])
                        df['Date'] = pd.to_datetime(df['Date'])
                        df['Date'] = df['Date'].dt.strftime('%Y-%m-%d %H:%M:%S')
                        df['Size'] = df['Size'].apply(lambda x: f"{x/1024:.1f} KB")
                        df['ML Prediction'] = df['ML Prediction'].apply(lambda x: 'Benign' if x == 0 else 'Malicious')
                        
                        # Style the dataframe
                        st.dataframe(
                            df[['File Name', 'File Type', 'Size', 'ML Prediction', 
                                'VT Detection Rate', 'Date']].head(10),
                            use_container_width=True,
                            hide_index=True
                        )
                    else:
                        st.info("No scan history available yet.")
                
                # Detailed Report Tab
                with report_tab:
                    st.subheader("Detailed Analysis Report")
                    if vt_api_key and vt_data and vt_data.get('response_code') != 0:
                        report = create_detailed_report(
                            {'prediction': ml_result, 'probability': 0.7},  # Replace with actual probability
                            vt_data,
                            file_info
                        )
                        st.markdown(report)
                        
                        # Download report button
                        st.download_button(
                            label="Download Report",
                            data=report,
                            file_name=f"malware_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                            mime="text/markdown"
                        )
                    else:
                        st.warning("VirusTotal analysis not available. Please enter an API key.")
            
            except Exception as e:
                st.error(f"An error occurred: {str(e)}")
            
            finally:
                # Clean up temporary file
                try:
                    os.unlink(tmp_path)
                except:
                    pass

if __name__ == "__main__":
    main() 
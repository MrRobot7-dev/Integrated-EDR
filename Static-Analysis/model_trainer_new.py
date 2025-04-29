import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pefile
from collections import defaultdict

def extract_features(file_path):
    """Extract the most distinctive features from PE files"""
    try:
        pe = pefile.PE(file_path)
        features = {}
        
        # Section Analysis
        features['AvgSectionEntropy'] = sum(section.get_entropy() for section in pe.sections) / len(pe.sections)
        features['MaxSectionEntropy'] = max(section.get_entropy() for section in pe.sections)
        features['NumSections'] = len(pe.sections)
        
        # Import Analysis
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            features['NumImportDLLs'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            features['NumImports'] = sum(len(module.imports) for module in pe.DIRECTORY_ENTRY_IMPORT)
            dll_names = [dll.dll.decode('utf-8', 'ignore').lower() for dll in pe.DIRECTORY_ENTRY_IMPORT]
            features['HasCryptoImports'] = int(any(name in dll_names for name in ['cryptsp', 'advapi32', 'crypt32']))
            features['HasNetworkImports'] = int(any(name in dll_names for name in ['ws2_32', 'wininet', 'wsock32']))
        else:
            features['NumImportDLLs'] = 0
            features['NumImports'] = 0
            features['HasCryptoImports'] = 0
            features['HasNetworkImports'] = 0
            
        # Resource Analysis
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            resources = []
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                resources.append(resource_lang.data.struct.Size)
            features['NumResources'] = len(resources)
            features['TotalResourceSize'] = sum(resources) if resources else 0
        else:
            features['NumResources'] = 0
            features['TotalResourceSize'] = 0
            
        # Header Analysis
        features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        features['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        
        return features
    except Exception as e:
        print(f"Error processing {os.path.basename(file_path)}: {str(e)}")
        return None

def collect_samples():
    """Collect samples from legitimate and malware directories"""
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    system_root = os.environ['SystemRoot']
    
    # Define sample files
    legitimate_files = [
        os.path.join(system_root, 'System32', 'notepad.exe'),
        os.path.join(system_root, 'System32', 'calc.exe'),
        os.path.join(system_root, 'System32', 'cmd.exe'),
        os.path.join(system_root, 'System32', 'mspaint.exe'),
        os.path.join(system_root, 'System32', 'write.exe'),
        os.path.join(system_root, 'System32', 'charmap.exe'),
        os.path.join(system_root, 'System32', 'snippingtool.exe'),
        os.path.join(system_root, 'System32', 'magnify.exe'),
        os.path.join(system_root, 'System32', 'winver.exe'),
        os.path.join(system_root, 'System32', 'winhlp32.exe')
    ]
    
    malware_dir = os.path.join(SCRIPT_DIR, "malwares", "Ransomware")
    malware_files = [
        os.path.join(malware_dir, "Ransomware.CoronaVirus.exe"),
        os.path.join(malware_dir, "Ransomware.NoMoreRansom.exe"),
        os.path.join(malware_dir, "Ransomware.WannaCrypt0r.v2.exe")
    ]
    
    # Collect features
    features = []
    labels = []
    
    print("Processing legitimate files...")
    for file_path in legitimate_files:
        if os.path.exists(file_path):
            file_features = extract_features(file_path)
            if file_features:
                features.append(file_features)
                labels.append(0)  # 0 for legitimate
    
    print("Processing malware files...")
    for file_path in malware_files:
        if os.path.exists(file_path):
            file_features = extract_features(file_path)
            if file_features:
                features.append(file_features)
                labels.append(1)  # 1 for malware
    
    return features, labels

def train_model():
    """Train a new model with the distinctive features"""
    print("Collecting samples...")
    features, labels = collect_samples()
    
    if not features or not labels:
        print("No valid samples collected. Exiting.")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(features)
    X = df.values
    y = np.array(labels)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train model
    print("\nTraining model...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight='balanced',
        random_state=42
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print("\nModel Evaluation:")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    
    # Print feature importance
    print("\nFeature Importance:")
    feature_importance = list(zip(df.columns, model.feature_importances_))
    feature_importance.sort(key=lambda x: x[1], reverse=True)
    for feature, importance in feature_importance:
        print(f"{feature}: {importance:.4f}")
    
    # Save model and features
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(SCRIPT_DIR, "model", "model_new_features.pkl")
    features_path = os.path.join(SCRIPT_DIR, "model", "features_new.pkl")
    
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    with open(features_path, 'wb') as f:
        pickle.dump(list(df.columns), f)
    
    print(f"\nModel saved to {model_path}")
    print(f"Features saved to {features_path}")

if __name__ == "__main__":
    train_model() 
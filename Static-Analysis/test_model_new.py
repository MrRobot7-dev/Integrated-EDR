import os
import pickle
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import pefile
from collections import defaultdict

def extract_features(file_path):
    """Extract features from PE files"""
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

def collect_test_files():
    """Collect a larger set of test files"""
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    system_root = os.environ['SystemRoot']
    
    # Define test files
    legitimate_files = [
        # System Utilities
        os.path.join(system_root, 'System32', 'notepad.exe'),
        os.path.join(system_root, 'System32', 'calc.exe'),
        os.path.join(system_root, 'System32', 'cmd.exe'),
        os.path.join(system_root, 'System32', 'mspaint.exe'),
        os.path.join(system_root, 'System32', 'write.exe'),
        os.path.join(system_root, 'System32', 'charmap.exe'),
        os.path.join(system_root, 'System32', 'snippingtool.exe'),
        os.path.join(system_root, 'System32', 'magnify.exe'),
        os.path.join(system_root, 'System32', 'winver.exe'),
        os.path.join(system_root, 'System32', 'winhlp32.exe'),
        # Additional System Files
        os.path.join(system_root, 'System32', 'taskmgr.exe'),
        os.path.join(system_root, 'System32', 'regedit.exe'),
        os.path.join(system_root, 'System32', 'msconfig.exe'),
        os.path.join(system_root, 'System32', 'dxdiag.exe'),
        os.path.join(system_root, 'System32', 'cleanmgr.exe'),
        # Windows Components
        os.path.join(system_root, 'explorer.exe'),
        os.path.join(system_root, 'System32', 'svchost.exe'),
        os.path.join(system_root, 'System32', 'services.exe'),
        os.path.join(system_root, 'System32', 'lsass.exe'),
        os.path.join(system_root, 'System32', 'winlogon.exe'),
        # Additional System Components
        os.path.join(system_root, 'System32', 'smss.exe'),
        os.path.join(system_root, 'System32', 'csrss.exe'),
        os.path.join(system_root, 'System32', 'wininit.exe'),
        os.path.join(system_root, 'System32', 'spoolsv.exe'),
        os.path.join(system_root, 'System32', 'dwm.exe'),
        # Windows Management Tools
        os.path.join(system_root, 'System32', 'mmc.exe'),
        os.path.join(system_root, 'System32', 'gpedit.msc'),
        os.path.join(system_root, 'System32', 'compmgmt.msc'),
        os.path.join(system_root, 'System32', 'devmgmt.msc'),
        os.path.join(system_root, 'System32', 'diskmgmt.msc')
    ]
    
    malware_dir = os.path.join(SCRIPT_DIR, "malwares", "Ransomware")
    malware_files = [
        os.path.join(malware_dir, "Ransomware.CoronaVirus.exe"),
        os.path.join(malware_dir, "Ransomware.NoMoreRansom.exe"),
        os.path.join(malware_dir, "Ransomware.WannaCrypt0r.v2.exe")
    ]
    
    return legitimate_files, malware_files

def test_model():
    """Test the model against a larger set of files"""
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    
    # Load model and features
    model_path = os.path.join(SCRIPT_DIR, "model", "model_new_features.pkl")
    features_path = os.path.join(SCRIPT_DIR, "model", "features_new.pkl")
    
    try:
        model = joblib.load(model_path)
        features = pickle.loads(open(features_path, 'rb').read())
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        return
    
    # Collect test files
    legitimate_files, malware_files = collect_test_files()
    
    # Test files
    results = {
        'legitimate': {'files': [], 'predictions': [], 'features': []},
        'malware': {'files': [], 'predictions': [], 'features': []}
    }
    
    print("Testing legitimate files...")
    for file_path in legitimate_files:
        if os.path.exists(file_path):
            features_dict = extract_features(file_path)
            if features_dict:
                # Convert features to array
                feature_values = [features_dict.get(f, 0) for f in features]
                prediction = model.predict([feature_values])[0]
                
                results['legitimate']['files'].append(os.path.basename(file_path))
                results['legitimate']['predictions'].append(prediction)
                results['legitimate']['features'].append(features_dict)
    
    print("\nTesting malware files...")
    for file_path in malware_files:
        if os.path.exists(file_path):
            features_dict = extract_features(file_path)
            if features_dict:
                # Convert features to array
                feature_values = [features_dict.get(f, 0) for f in features]
                prediction = model.predict([feature_values])[0]
                
                results['malware']['files'].append(os.path.basename(file_path))
                results['malware']['predictions'].append(prediction)
                results['malware']['features'].append(features_dict)
    
    # Calculate metrics
    y_true = [0] * len(results['legitimate']['predictions']) + [1] * len(results['malware']['predictions'])
    y_pred = results['legitimate']['predictions'] + results['malware']['predictions']
    
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)
    
    # Print results
    print("\nTest Results")
    print("=" * 80)
    print(f"Total files tested: {len(y_true)}")
    print(f"Legitimate files: {len(results['legitimate']['files'])}")
    print(f"Malware files: {len(results['malware']['files'])}")
    print("\nPerformance Metrics:")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    
    print("\nConfusion Matrix:")
    print("True Negative (Legitimate):", cm[0][0])
    print("False Positive:", cm[0][1])
    print("False Negative:", cm[1][0])
    print("True Positive (Malware):", cm[1][1])
    
    # Print detailed results
    print("\nDetailed Results")
    print("=" * 80)
    print("\nLegitimate Files:")
    for file, pred in zip(results['legitimate']['files'], results['legitimate']['predictions']):
        print(f"{file}: {'MALWARE' if pred == 1 else 'LEGITIMATE'}")
    
    print("\nMalware Files:")
    for file, pred in zip(results['malware']['files'], results['malware']['predictions']):
        print(f"{file}: {'MALWARE' if pred == 1 else 'LEGITIMATE'}")

if __name__ == "__main__":
    test_model() 
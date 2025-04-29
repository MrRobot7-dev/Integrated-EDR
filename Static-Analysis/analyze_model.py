import os
import pickle
import joblib
import numpy as np
import pefile
import pandas as pd
from collections import defaultdict
from file_checker import extract_info, get_entropy

def analyze_extended_features(file_path):
    """Analyze additional features of PE files"""
    try:
        pe = pefile.PE(file_path)
        features = {}
        
        # Section Analysis
        features['NumSections'] = len(pe.sections)
        features['AvgSectionEntropy'] = sum(section.get_entropy() for section in pe.sections) / len(pe.sections)
        features['MaxSectionEntropy'] = max(section.get_entropy() for section in pe.sections)
        features['ExecutableSection'] = any(section.Characteristics & 0x20000000 for section in pe.sections)
        
        # Import Analysis
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            features['NumImports'] = sum(len(module.imports) for module in pe.DIRECTORY_ENTRY_IMPORT)
            features['NumImportDLLs'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            dll_names = [dll.dll.decode('utf-8', 'ignore').lower() for dll in pe.DIRECTORY_ENTRY_IMPORT]
            features['HasCryptoImports'] = any(name in dll_names for name in ['cryptsp', 'advapi32', 'crypt32'])
            features['HasNetworkImports'] = any(name in dll_names for name in ['ws2_32', 'wininet', 'wsock32'])
        else:
            features['NumImports'] = 0
            features['NumImportDLLs'] = 0
            features['HasCryptoImports'] = False
            features['HasNetworkImports'] = False
            
        # Resource Analysis
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            features['HasResources'] = True
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
            features['HasResources'] = False
            features['NumResources'] = 0
            features['TotalResourceSize'] = 0
            
        # Header Analysis
        features['TimeDateStamp'] = pe.FILE_HEADER.TimeDateStamp
        features['IsDLL'] = pe.FILE_HEADER.Characteristics & 0x2000 > 0
        features['IsSystem'] = pe.FILE_HEADER.Characteristics & 0x1000 > 0
        
        # Optional Header Analysis
        features['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        
        return features
    except Exception as e:
        print(f"Error analyzing {os.path.basename(file_path)}: {str(e)}")
        return {}

def analyze_model():
    # Load the model and features
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(SCRIPT_DIR, "model", "model_new.pkl")
    features_path = os.path.join(SCRIPT_DIR, "model", "features.pkl")
    
    model = joblib.load(model_path)
    features = pickle.loads(open(features_path, 'rb').read())
    
    print("Extended PE File Analysis - Comprehensive Test")
    print("=" * 80)
    
    # Define test files
    system_root = os.environ['SystemRoot']
    files_to_analyze = {
        'Legitimate': [
            os.path.join(system_root, 'System32', 'notepad.exe'),
            os.path.join(system_root, 'System32', 'calc.exe'),
            os.path.join(system_root, 'System32', 'cmd.exe'),
            os.path.join(system_root, 'System32', 'explorer.exe')
        ],
        'Malware': [
            os.path.join(SCRIPT_DIR, "malwares", "Ransomware", "Ransomware.CoronaVirus.exe"),
            os.path.join(SCRIPT_DIR, "malwares", "Ransomware", "Ransomware.NoMoreRansom.exe"),
            os.path.join(SCRIPT_DIR, "malwares", "Ransomware", "Ransomware.WannaCrypt0r.v2.exe")
        ]
    }
    
    # Collect results
    results = defaultdict(list)
    feature_stats = defaultdict(lambda: {'min': float('inf'), 'max': float('-inf'), 'sum': 0, 'count': 0})
    
    for category, files in files_to_analyze.items():
        print(f"\nAnalyzing {category} files...")
        for file_path in files:
            if os.path.exists(file_path):
                print(f"  Processing {os.path.basename(file_path)}...")
                features = analyze_extended_features(file_path)
                if features:
                    results[category].append(features)
                    # Update statistics
                    for feature, value in features.items():
                        if isinstance(value, (int, float)):
                            stats = feature_stats[feature]
                            stats['min'] = min(stats['min'], value)
                            stats['max'] = max(stats['max'], value)
                            stats['sum'] += value
                            stats['count'] += 1
            else:
                print(f"  File not found: {file_path}")
    
    # Print detailed analysis
    print("\nFeature Analysis Summary")
    print("=" * 80)
    
    # Print statistics for each feature
    for feature, stats in feature_stats.items():
        if stats['count'] > 0:
            avg = stats['sum'] / stats['count']
            print(f"\n{feature}:")
            print(f"  Min: {stats['min']:.2f}")
            print(f"  Max: {stats['max']:.2f}")
            print(f"  Avg: {avg:.2f}")
    
    # Print comparison tables
    feature_groups = {
        'Section Analysis': ['NumSections', 'AvgSectionEntropy', 'MaxSectionEntropy', 'ExecutableSection'],
        'Import Analysis': ['NumImports', 'NumImportDLLs', 'HasCryptoImports', 'HasNetworkImports'],
        'Resource Analysis': ['HasResources', 'NumResources', 'TotalResourceSize'],
        'Header Analysis': ['TimeDateStamp', 'IsDLL', 'IsSystem', 'Subsystem', 'DllCharacteristics', 'FileAlignment']
    }
    
    for group_name, group_features in feature_groups.items():
        print(f"\n{group_name}")
        print("=" * 80)
        print(f"{'Feature':<25} {'Legitimate Avg':<15} {'Malware Avg':<15} {'Difference':<15}")
        print("-" * 80)
        
        for feature in group_features:
            legit_values = [r[feature] for r in results['Legitimate'] if feature in r]
            malware_values = [r[feature] for r in results['Malware'] if feature in r]
            
            legit_avg = sum(legit_values) / len(legit_values) if legit_values else 0
            malware_avg = sum(malware_values) / len(malware_values) if malware_values else 0
            diff = malware_avg - legit_avg
            
            print(f"{feature:<25} {legit_avg:<15.2f} {malware_avg:<15.2f} {diff:<15.2f}")

if __name__ == "__main__":
    analyze_model() 
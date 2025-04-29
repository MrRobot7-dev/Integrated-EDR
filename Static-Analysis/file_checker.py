# For testing if a file is a probable malware of not!

import array
import math
import os
import pickle
import time
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple
from data_manager import DataManager

import joblib
import pefile

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

logger = logging.getLogger('StaticAnalyzer')

def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurrences = array.array('L', [0] * 256)
    for x in data:
        occurrences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurrences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

    return entropy


def get_resources(pe):
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                                   resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources


def get_version_info(pe):
    """Return version info's"""
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
        res['os'] = pe.VS_FIXEDFILEINFO.FileOS
        res['type'] = pe.VS_FIXEDFILEINFO.FileType
        res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
        res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
        res['signature'] = pe.VS_FIXEDFILEINFO.Signature
        res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res


def extract_info(fpath):
    res = {}
    try:
        pe = pefile.PE(fpath)
    except pefile.PEFormatError:
        return {}
    
    # Section Analysis
    entropy = [section.get_entropy() for section in pe.sections]
    res['AvgSectionEntropy'] = sum(entropy) / len(entropy) if entropy else 0
    res['MaxSectionEntropy'] = max(entropy) if entropy else 0
    res['NumSections'] = len(pe.sections)
    
    # Enhanced Section Analysis
    section_names = [section.Name.decode('utf-8', 'ignore').strip('\x00') for section in pe.sections]
    res['HasSuspiciousSectionNames'] = int(any(name.lower() in ['.text', '.data', '.rdata', '.bss'] for name in section_names))
    res['HasUnusualSectionNames'] = int(any(name.lower() not in ['.text', '.data', '.rdata', '.bss', '.rsrc', '.reloc'] for name in section_names))
    
    # Import Analysis
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        res['NumImportDLLs'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = entry.dll.decode('utf-8', 'ignore').lower()
                imports.extend([imp.name.decode('utf-8', 'ignore').lower() for imp in entry.imports if imp.name])
            except:
                continue
        
        res['NumImports'] = len(imports)
        res['HasCryptoImports'] = int(any(name in ['cryptsp', 'advapi32', 'crypt32'] for name in imports))
        res['HasNetworkImports'] = int(any(name in ['ws2_32', 'wininet', 'wsock32'] for name in imports))
        
        # Enhanced Import Analysis
        suspicious_imports = ['virtualalloc', 'virtualprotect', 'createthread', 'writeprocessmemory',
                            'openprocess', 'regsetvalue', 'regcreatekey', 'getprocaddress', 'loadlibrary']
        res['HasSuspiciousImports'] = int(any(name in suspicious_imports for name in imports))
    else:
        res['NumImportDLLs'] = 0
        res['NumImports'] = 0
        res['HasCryptoImports'] = 0
        res['HasNetworkImports'] = 0
        res['HasSuspiciousImports'] = 0
        
    # Resource Analysis
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        resources = []
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            resources.append(resource_lang.data.struct.Size)
        res['NumResources'] = len(resources)
        res['TotalResourceSize'] = sum(resources) if resources else 0
    else:
        res['NumResources'] = 0
        res['TotalResourceSize'] = 0
        
    # Header Analysis
    res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    
    # Timestamp Analysis
    try:
        compile_time = pe.FILE_HEADER.TimeDateStamp
        res['IsRecentCompile'] = int(compile_time > (time.time() - 31536000))  # Within 1 year
    except:
        res['IsRecentCompile'] = 0
    
    # Ensure all features are present
    required_features = [
        'AvgSectionEntropy', 'MaxSectionEntropy', 'NumSections',
        'HasSuspiciousSectionNames', 'HasUnusualSectionNames',
        'NumImportDLLs', 'NumImports', 'HasCryptoImports', 
        'HasNetworkImports', 'HasSuspiciousImports',
        'NumResources', 'TotalResourceSize', 
        'DllCharacteristics', 'FileAlignment', 'Subsystem',
        'IsRecentCompile'
    ]
    
    for feature in required_features:
        if feature not in res:
            res[feature] = 0
    
    return res


def checkFile(file):
    model_path = os.path.join(SCRIPT_DIR, "model", "model_enhanced.pkl")
    features_path = os.path.join(SCRIPT_DIR, "model", "features_enhanced.pkl")
    
    model = joblib.load(model_path)
    features = pickle.loads(open(features_path, 'rb').read())
    data = extract_info(file)
    
    print("\nDebug Information:")
    print("File:", os.path.basename(file))
    print("Extracted Features:", data)
    
    if data != {}:
        pe_features = list(map(lambda x: data[x], features))
        print("Features used for prediction:", dict(zip(features, pe_features)))
        res = model.predict([pe_features])[0]
        print("Prediction:", "MALWARE" if res == 1 else "LEGITIMATE")
    else:
        res = 1
        print("Error: Could not extract features")
    
    return res

class StaticAnalyzer:
    def __init__(self, data_manager: DataManager):
        self.running = False
        self.thread = None
        self.data_manager = data_manager
        self.model = None
        self.stats = {
            'total_files_analyzed': 0,
            'malicious_files': 0,
            'legitimate_files': 0,
            'analysis_time': 0,
            'analysis_history': []
        }
        self._load_model()

    def _load_model(self):
        """Load the trained model"""
        try:
            model_path = os.path.join(os.path.dirname(__file__), 'model', 'model_enhanced.pkl')
            features_path = os.path.join(os.path.dirname(__file__), 'model', 'features_enhanced.pkl')
            if os.path.exists(model_path) and os.path.exists(features_path):
                self.model = joblib.load(model_path)
                self.features = pickle.loads(open(features_path, 'rb').read())
                logger.info("Model and features loaded successfully")
            else:
                logger.error(f"Model or features file not found: {model_path} or {features_path}")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
    
    def _should_analyze_file(self, file_path: str) -> bool:
        """Check if a file should be analyzed"""
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                logger.warning(f"File does not exist: {file_path}")
                return False
                
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                logger.warning(f"File is empty: {file_path}")
                return False
            if file_size > 100 * 1024 * 1024:  # 100MB limit
                logger.warning(f"File too large: {file_path}")
                return False
                
            # Check file extension
            _, ext = os.path.splitext(file_path)
            ext = ext.lower()
            analyzable_types = ['.exe', '.dll', '.bat', '.ps1', '.vbs']
            if ext not in analyzable_types:
                logger.info(f"File type not analyzable: {file_path}")
                return False
                
            return True
        except Exception as e:
            logger.error(f"Error checking file: {file_path}: {e}")
            return False
    
    def analyze_file(self, file_path: str) -> Optional[Dict]:
        """Analyze a file for potential malware"""
        try:
            if not self._should_analyze_file(file_path):
                return None
                
            start_time = time.time()
            
            # Extract features
            features = self._extract_features(file_path)
            if not features:
                logger.error(f"Failed to extract features from: {file_path}")
                return None
            
            # Make prediction
            prediction = self.model.predict([features])[0]
            probability = self.model.predict_proba([features])[0][1]
            
            # Update statistics
            self.stats['total_files_analyzed'] += 1
            if prediction == 1:
                self.stats['malicious_files'] += 1
                severity = 'high' if probability > 0.8 else 'medium'
            else:
                self.stats['legitimate_files'] += 1
                severity = 'low'
            
            analysis_time = time.time() - start_time
            self.stats['analysis_time'] += analysis_time
            
            # Add to analysis history
            self.stats['analysis_history'].append({
                'timestamp': time.time(),
                'file_path': file_path,
                'prediction': int(prediction),
                'probability': float(probability),
                'analysis_time': analysis_time
            })
            
            # Keep only last 100 entries
            if len(self.stats['analysis_history']) > 100:
                self.stats['analysis_history'] = self.stats['analysis_history'][-100:]
            
            # Update data manager
            self.data_manager.update_static_analysis_stats(self.stats)
            
            # Create alert if malicious
            if prediction == 1:
                alert = {
                    'timestamp': time.time(),
                    'type': 'static_analysis',
                    'severity': severity,
                    'message': f"Potential malware detected: {file_path}",
                    'details': {
                        'file_path': file_path,
                        'probability': float(probability),
                        'analysis_time': analysis_time
                    }
                }
                self.data_manager.add_alert(alert)
            
            return {
                'file_path': file_path,
                'prediction': int(prediction),
                'probability': float(probability),
                'analysis_time': analysis_time
            }
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return None
    
    def _extract_features(self, file_path: str) -> Optional[List[float]]:
        """Extract features from a file"""
        try:
            features = []
            
            # File size
            file_size = os.path.getsize(file_path)
            features.append(math.log(file_size + 1))
            
            # Entropy
            entropy = self._calculate_entropy(file_path)
            features.append(entropy)
            
            # Resource analysis
            resource_features = self._analyze_resources(file_path)
            features.extend(resource_features)
            
            # Import analysis
            import_features = self._analyze_imports(file_path)
            features.extend(import_features)
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features from {file_path}: {e}")
            return None
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of a file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
                
            counts = array.array('L', [0] * 256)
            for byte in data:
                counts[byte] += 1
                
            entropy = 0
            for count in counts:
                if count:
                    p = count / len(data)
                    entropy -= p * math.log2(p)
                    
            return entropy
            
        except Exception as e:
            logger.error(f"Error calculating entropy for {file_path}: {e}")
            return 0.0
    
    def _analyze_resources(self, file_path: str) -> List[float]:
        """Analyze file resources"""
        # Placeholder for resource analysis
        return [0.0] * 5
    
    def _analyze_imports(self, file_path: str) -> List[float]:
        """Analyze file imports"""
        # Placeholder for import analysis
        return [0.0] * 10

    def start_analysis(self):
        if self.running:
            print("[!] Static analysis already running")
            return
        self.running = True
        self.thread = threading.Thread(target=self._analysis_loop)
        self.thread.daemon = True
        self.thread.start()
        print("[+] Static analysis started")

    def stop_analysis(self):
        if not self.running:
            print("[!] Static analysis not running")
            return
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("[+] Static analysis stopped")

    def _analysis_loop(self):
        print("[*] Static analysis loop started")
        while self.running:
            try:
                # Example: Analyze files in a directory
                target_dir = os.path.join(SCRIPT_DIR, "test_files")
                if os.path.exists(target_dir):
                    for file in os.listdir(target_dir):
                        if not self.running:
                            break
                            
                        file_path = os.path.join(target_dir, file)
                        if os.path.isfile(file_path):
                            self.analyze_file(file_path)
                
                time.sleep(5)  # Wait before next scan
                
            except Exception as e:
                print(f"[!] Error in static analysis: {e}")
                time.sleep(5)  # Wait before retrying

if __name__ == "__main__":
    # Create a data manager instance for standalone testing
    data_manager = DataManager()
    analyzer = StaticAnalyzer(data_manager)
    analyzer.start_analysis()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        analyzer.stop_analysis()

import os
import json
from typing import Dict, List, Optional
import logging

logger = logging.getLogger('DataManager')

class DataManager:
    def __init__(self):
        self.analysis_results = {}
        self.stats = {
            'total_files_analyzed': 0,
            'malicious_files': 0,
            'legitimate_files': 0,
            'errors': 0
        }
        
    def save_analysis_result(self, file_path: str, result: Dict) -> None:
        """Save the analysis result for a file."""
        self.analysis_results[file_path] = result
        self._update_stats(result)
        
    def get_analysis_result(self, file_path: str) -> Optional[Dict]:
        """Get the analysis result for a file if it exists."""
        return self.analysis_results.get(file_path)
        
    def _update_stats(self, result: Dict) -> None:
        """Update statistics based on analysis result."""
        self.stats['total_files_analyzed'] += 1
        if result.get('is_malicious'):
            self.stats['malicious_files'] += 1
        else:
            self.stats['legitimate_files'] += 1
        if result.get('error'):
            self.stats['errors'] += 1
            
    def get_stats(self) -> Dict:
        """Get current analysis statistics."""
        return self.stats.copy()
        
    def clear_results(self) -> None:
        """Clear all analysis results and reset statistics."""
        self.analysis_results.clear()
        self.stats = {
            'total_files_analyzed': 0,
            'malicious_files': 0,
            'legitimate_files': 0,
            'errors': 0
        } 
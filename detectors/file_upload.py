# File upload detector
import os
import magic
from pathlib import Path

def scan_file(file_path, filename):
    """
    Scan uploaded file for security issues
    
    Args:
        file_path: Path to the uploaded file
        filename: Original filename
    
    Returns:
        dict: Scan results with threats and recommendations
    """
    results = {
        'threats': [],
        'safe': True,
        'file_type': None,
        'file_size': 0,
        'recommendations': []
    }
    
    try:
        # Get file stats
        if os.path.exists(file_path):
            results['file_size'] = os.path.getsize(file_path)
            
            # Get file type
            try:
                file_type = magic.from_file(file_path, mime=True)
                results['file_type'] = file_type
            except:
                # Fallback to extension-based detection
                ext = Path(filename).suffix.lower()
                results['file_type'] = f"file/{ext[1:]}" if ext else "unknown"
            
            # Check file size (10MB limit)
            if results['file_size'] > 10 * 1024 * 1024:
                results['threats'].append({
                    'type': 'size_limit',
                    'severity': 'medium',
                    'description': 'File size exceeds 10MB limit',
                    'file': filename
                })
                results['safe'] = False
            
            # Check for dangerous extensions
            dangerous_extensions = ['.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js']
            ext = Path(filename).suffix.lower()
            if ext in dangerous_extensions:
                results['threats'].append({
                    'type': 'dangerous_extension',
                    'severity': 'high',
                    'description': f'Potentially dangerous file extension: {ext}',
                    'file': filename
                })
                results['safe'] = False
            
            # Check for double extensions
            if filename.count('.') > 1:
                results['threats'].append({
                    'type': 'double_extension',
                    'severity': 'medium',
                    'description': 'File has multiple extensions which could be used to hide malicious content',
                    'file': filename
                })
                results['safe'] = False
                
        else:
            results['threats'].append({
                'type': 'file_not_found',
                'severity': 'high',
                'description': 'Uploaded file not found on server',
                'file': filename
            })
            results['safe'] = False
            
    except Exception as e:
        results['threats'].append({
            'type': 'scan_error',
            'severity': 'medium',
            'description': f'Error scanning file: {str(e)}',
            'file': filename
        })
        results['safe'] = False
    
    # Add recommendations
    if not results['safe']:
        results['recommendations'] = [
            'Review file content manually before processing',
            'Use antivirus scanning before file execution',
            'Implement file type restrictions',
            'Consider using sandboxed environment for file processing'
        ]
    
    return results

def get_file_signature(file_path):
    """Get file signature/magic bytes"""
    try:
        with open(file_path, 'rb') as f:
            signature = f.read(16).hex()
        return signature
    except:
        return None
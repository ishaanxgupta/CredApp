#!/usr/bin/env python3
"""
Debug the specific parsing issues with learner name and issuer name
"""

import sys
import os

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.services.ocr_service import OCRService

def debug_parsing_issues():
    """Debug the specific parsing issues"""
    
    print("🔍 Debugging Parsing Issues")
    print("=" * 60)
    
    ocr_service = OCRService()
    
    # Test with the exact NPTEL certificate text
    nptel_text = """NPTEL ONLINE CERTIFICATION
Funded by the MoE, Govt. of India
Skill India
68ed41a1b47720c296ee00c3
This Certificate is awarded to
Ishaan Gupta
for successfully completing the course
Introduction To The Psychology
NSQF Level : 5
Issued Date: 25th December 2024
July - Oct
12 Week Course
Indian Institute of Technology Kharagpur
FREE ONLINE EDUCATION
swayam
शिक्षित भारत उन्नत भारत"""
    
    print("📄 NPTEL Certificate Text:")
    print(nptel_text)
    print("\n" + "="*60)
    
    # Test line by line parsing
    lines = nptel_text.split('\n')
    print("\n🔍 Line-by-line analysis:")
    
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
            
        print(f"\nLine {i}: '{line}'")
        
        # Test "This Certificate is awarded to" pattern
        if "AWARDED TO" in line.upper():
            print(f"  ✅ Contains 'AWARDED TO'")
            if i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                print(f"  → Next line: '{next_line}'")
                # Check if it's blocked
                blocked_keywords = ['ISSUED', 'CERTIFICATE', 'STUDENT', 'ID:', 'FOR SUCCESSFULLY', 'NSQF', 'LEVEL', 'FUNDED', 'GOVT', 'SKILL']
                is_blocked = any(keyword in next_line.upper() for keyword in blocked_keywords)
                print(f"  → Is blocked: {is_blocked}")
                if not is_blocked:
                    print(f"  → Would set learner_name to: '{next_line}'")
                else:
                    print(f"  → Blocked by keywords: {[kw for kw in blocked_keywords if kw in next_line.upper()]}")
        
        # Test issuer detection
        if any(keyword in line.lower() for keyword in ['university', 'college', 'institute', 'academy', 'school', 'technology']):
            print(f"  ✅ Contains institution keyword")
            print(f"  → Would set issuer_name to: '{line}'")
    
    print("\n" + "="*60)
    print("📋 Final parsing result:")
    result = ocr_service._parse_certificate_text(nptel_text)
    
    for key, value in result.items():
        if key != 'raw_text':  # Skip raw_text as it's too long
            print(f"   {key}: {value}")

if __name__ == "__main__":
    debug_parsing_issues()

#!/usr/bin/env python3
"""
Debug script to test QR code detection on the AWS certificate
"""

import base64
import io
import json
from PIL import Image
import fitz  # PyMuPDF
import pyzbar.pyzbar as pyzbar

def test_qr_detection():
    """Test QR code detection with simulated PDF data"""
    
    print("🔍 Testing QR Code Detection...")
    
    # Simulate the PDF data (in real scenario, this would come from the uploaded file)
    # For testing, we'll create a simple PDF-like structure
    print("\n1. Creating test PDF document...")
    
    try:
        # Create a simple PDF document for testing
        doc = fitz.open()  # Create empty PDF
        page = doc.new_page(width=595, height=842)  # A4 size
        
        # Add some text to simulate the certificate
        page.insert_text((100, 100), "AWS SOLUTIONS ARCHITECT", fontsize=20)
        page.insert_text((100, 150), "IS AWARDED TO", fontsize=12)
        page.insert_text((100, 200), "Ishaan Gupta", fontsize=16)
        page.insert_text((100, 300), "Amazon Web Services", fontsize=12)
        page.insert_text((100, 350), "January 30, 2023", fontsize=12)
        
        # Get the PDF as bytes
        pdf_bytes = doc.tobytes()
        doc.close()
        
        print("✅ Test PDF created successfully")
        
    except Exception as e:
        print(f"❌ Error creating test PDF: {e}")
        return
    
    # Now test the QR detection logic
    print("\n2. Testing QR detection logic...")
    
    try:
        # Open PDF from bytes (simulating the endpoint logic)
        pdf_document = fitz.open(stream=pdf_bytes, filetype="pdf")
        print(f"✅ PDF opened successfully, pages: {pdf_document.page_count}")
        
        qr_codes_found = []
        
        # Process each page
        for page_num in range(pdf_document.page_count):
            print(f"\n📄 Processing page {page_num + 1}...")
            page = pdf_document[page_num]
            
            # Convert page to image with different zoom levels
            for zoom in [1, 2, 3, 4]:
                print(f"  🔍 Trying zoom level {zoom}x...")
                
                mat = fitz.Matrix(zoom, zoom)
                pix = page.get_pixmap(matrix=mat)
                img_data = pix.tobytes("png")
                
                # Convert to PIL Image
                image = Image.open(io.BytesIO(img_data))
                print(f"    📐 Image size: {image.size}")
                
                # Detect QR codes
                qr_codes = pyzbar.decode(image)
                print(f"    🔍 QR codes found: {len(qr_codes)}")
                
                if qr_codes:
                    for i, qr_code in enumerate(qr_codes):
                        try:
                            qr_data = qr_code.data.decode('utf-8')
                            print(f"    ✅ QR Code {i+1}: {qr_data[:50]}...")
                            
                            qr_codes_found.append({
                                "page": page_num + 1,
                                "zoom": zoom,
                                "qr_data": qr_data,
                                "quality": qr_code.quality
                            })
                            
                        except Exception as e:
                            print(f"    ❌ Error decoding QR code {i+1}: {e}")
                else:
                    print(f"    ⚠️  No QR codes detected at {zoom}x zoom")
        
        pdf_document.close()
        
        print(f"\n📊 Final Results:")
        print(f"   Total QR codes found: {len(qr_codes_found)}")
        
        if qr_codes_found:
            for i, qr in enumerate(qr_codes_found):
                print(f"   QR {i+1}: Page {qr['page']}, Zoom {qr['zoom']}x, Quality {qr['quality']}")
                print(f"           Data: {qr['qr_data']}")
        else:
            print("   ⚠️  No QR codes found in any page at any zoom level")
            
            # Additional debugging
            print("\n🔧 Debugging suggestions:")
            print("   1. The test PDF doesn't contain actual QR codes")
            print("   2. Try with a real certificate PDF")
            print("   3. Check if pyzbar is properly installed")
            print("   4. Verify the image quality and resolution")
            
    except Exception as e:
        print(f"❌ Error in QR detection: {e}")
        import traceback
        traceback.print_exc()

def test_pyzbar_installation():
    """Test if pyzbar is working correctly"""
    print("\n🧪 Testing pyzbar installation...")
    
    try:
        # Test with a simple image
        from PIL import Image
        import pyzbar.pyzbar as pyzbar
        
        # Create a simple test image
        img = Image.new('RGB', (100, 100), color='white')
        
        # Try to decode (should return empty list for plain image)
        result = pyzbar.decode(img)
        print(f"✅ pyzbar working correctly, decoded {len(result)} codes from test image")
        
        return True
        
    except Exception as e:
        print(f"❌ pyzbar installation issue: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Starting QR Detection Debug...")
    
    # Test pyzbar installation first
    if test_pyzbar_installation():
        test_qr_detection()
    else:
        print("❌ Cannot proceed without working pyzbar installation")
    
    print("\n✅ Debug complete!")

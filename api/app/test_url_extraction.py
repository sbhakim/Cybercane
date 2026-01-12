#!/usr/bin/env python3
"""
Test script for URL extraction functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from extract_url import extract_urls_from_text

def test_url_extraction():
    """Test the URL extraction function with various examples"""
    
    test_cases = [
        {
            "text": "Visit our website at https://example.com for more information.",
            "expected": "https://example.com"
        },
        {
            "text": "Check out http://google.com and https://github.com for resources.",
            "expected": "http://google.com,https://github.com"
        },
        {
            "text": "Our site is www.example.org and also visit subdomain.example.com/path",
            "expected": "www.example.org,subdomain.example.com/path"
        },
        {
            "text": "Email us at user@example.com or visit https://secure.example.com/login",
            "expected": "https://secure.example.com/login"
        },
        {
            "text": "No URLs in this text at all.",
            "expected": ""
        },
        {
            "text": "Multiple URLs: https://site1.com, http://site2.org/page, www.site3.net",
            "expected": "https://site1.com,http://site2.org/page,www.site3.net"
        },
        {
            "text": "Visit localhost:8080 or 192.168.1.1:3000 for local development",
            "expected": "localhost:8080,192.168.1.1:3000"
        },
        {
            "text": "Check https://api.example.com:443/v1/data and www.test.org:8080/path",
            "expected": "https://api.example.com:443/v1/data,www.test.org:8080/path"
        },
        {
            "text": "Visit sds.fdfd.543.fds or abc.123.def.ghi for testing",
            "expected": "sds.fdfd.543.fds,abc.123.def.ghi"
        },
        {
            "text": "Check out test123.domain456.net and sub.domain.co.uk",
            "expected": "test123.domain456.net,sub.domain.co.uk"
        },
        {
            "text": "Visit api-v2.service-name.internal:8080 and dev.test.local",
            "expected": "api-v2.service-name.internal:8080,dev.test.local"
        },
        {
            "text": "The version is 4.5 and the price is 123.456 dollars",
            "expected": ""
        },
        {
            "text": "Visit example.com but ignore version 2.1.3 and price 99.99",
            "expected": "example.com"
        },
        {
            "text": "Check out test123.domain456.net but not 1.2.3.4.5",
            "expected": "test123.domain456.net"
        }
    ]
    
    print("Testing URL extraction function...")
    print("=" * 50)
    
    for i, test_case in enumerate(test_cases, 1):
        result = extract_urls_from_text(test_case["text"])
        expected = test_case["expected"]
        
        print(f"Test {i}:")
        print(f"  Input: {test_case['text']}")
        print(f"  Expected: {expected}")
        print(f"  Got: {result}")
        print(f"  Status: {'✓ PASS' if result == expected else '✗ FAIL'}")
        print()

if __name__ == "__main__":
    test_url_extraction()

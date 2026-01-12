import pandas as pd
import re
import os
from urllib.parse import urlparse

def extract_urls_from_text(text):
    """
    Extract URLs from text using comprehensive regex pattern.
    Returns a comma-separated string of URLs found in the text.
    """
    if pd.isna(text) or text == '':
        return ''
    
    # Comprehensive URL regex pattern - more inclusive
    url_pattern = re.compile(
        r'''(?xi)
        \b
        (?:                         # Optional protocol or www
          (?:https?:\/\/)           # Protocol
          |(?:www\.)                # OR www.
        )?
        (?:                         # Host/IP part
            (?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+  # Domain name (more flexible)
            |(?:\d{1,3}\.){3}\d{1,3}           # OR IPv4
            |localhost                        # OR localhost
        )
        (?::\d+)?                    # Optional port
        (?:\/[^\s]*)?                # Optional path/query/anchor
        (?=\b|[^a-zA-Z0-9\/@\-\.])   # End at word boundary or invalid URL char
        '''
    )
    
    # Find all URLs in the text
    urls = url_pattern.findall(str(text))
    
    # Process and normalize URLs
    processed_urls = []
    for url in urls:
        # url is a tuple from the capture groups, we want the full match
        # The pattern captures the full URL, so we need to get the complete match
        pass
    
    # Let's use finditer to get the full matches
    processed_urls = []
    for match in url_pattern.finditer(str(text)):
        url = match.group(0)
        
        # Validate the URL without normalizing it
        if not url.startswith(('http://', 'https://', 'www.')):
            # Check if it looks like a valid domain/IP
            if ('.' in url and 
                (url.count('.') >= 1) and  # At least one dot
                not url.startswith('.') and  # Doesn't start with dot
                not url.endswith('.') and    # Doesn't end with dot
                len(url) > 3):               # Reasonable length
                
                # Additional validation to exclude decimal numbers
                # Check if it's just numbers and dots (like "4.5", "123.456")
                if re.match(r'^[\d\.]+$', url):
                    continue  # Skip decimal numbers
                
                # Check if it has at least one letter or hyphen (domain-like)
                if not re.search(r'[a-zA-Z\-]', url):
                    continue  # Skip if no letters or hyphens
            else:
                continue  # Skip if it doesn't look like a valid URL
        
        # Keep the URL in its original format
        processed_urls.append(url)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for url in processed_urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    
    # Validate URLs using urlparse
    valid_urls = []
    for url in unique_urls:
        try:
            parsed = urlparse(url)
            if parsed.netloc:  # Has a valid domain
                valid_urls.append(url)
        except:
            continue
    
    # Return comma-separated string
    return ','.join(valid_urls)

def process_nazario_csv(input_file_path, output_file_path=None):
    """
    Process Nazario.csv to extract URLs from the 'body' column and create 'url_extracted' column.
    
    Args:
        input_file_path (str): Path to the input CSV file
        output_file_path (str, optional): Path to save the processed CSV file. 
                                        If None, overwrites the original file.
    """
    try:
        # Read the CSV file
        print(f"Reading CSV file: {input_file_path}")
        df = pd.read_csv(input_file_path)
        
        # Check if 'body' column exists
        if 'body' not in df.columns:
            print("Error: 'body' column not found in the CSV file.")
            print(f"Available columns: {list(df.columns)}")
            return
        
        print(f"Original data shape: {df.shape}")
        print(f"Columns: {list(df.columns)}")
        
        # Create the new 'url_extracted' column
        print("Processing body text to extract URLs...")
        df['url_extracted'] = df['body'].apply(extract_urls_from_text)
        
        # Show some statistics
        total_rows = len(df)
        rows_with_urls = len(df[df['url_extracted'] != ''])
        print(f"\nURL Extraction Statistics:")
        print(f"Total rows: {total_rows}")
        print(f"Rows with URLs: {rows_with_urls}")
        print(f"Percentage with URLs: {(rows_with_urls/total_rows)*100:.1f}%")
        
        # Show some examples of extracted URLs
        print("\nSample extracted URLs:")
        sample_data = df[df['url_extracted'] != ''][['body', 'url_extracted']].head(5)
        for idx, row in sample_data.iterrows():
            print(f"Row {idx}:")
            print(f"  Body preview: {str(row['body'])[:100]}...")
            print(f"  Extracted URLs: {row['url_extracted']}")
            print()
        
        # Determine output path
        if output_file_path is None:
            output_file_path = input_file_path
        
        # Save the processed data
        print(f"Saving processed data to: {output_file_path}")
        df.to_csv(output_file_path, index=False)
        
        print(f"Successfully processed {len(df)} rows.")
        print(f"New data shape: {df.shape}")
        print(f"New columns: {list(df.columns)}")
        
        return df
        
    except FileNotFoundError:
        print(f"Error: File '{input_file_path}' not found.")
    except Exception as e:
        print(f"Error processing file: {str(e)}")

def main():
    """
    Main function to process the Nazario.csv file.
    """
    # Define the dataset directory
    dataset_dir = "/Users/qizhao/Documents/PhD/Github/UMBC-hackathon/datasets"
    nazario_file = os.path.join(dataset_dir, "Nazario.csv")
    
    if os.path.exists(nazario_file):
        print("=" * 60)
        print("Processing Nazario.csv for URL extraction")
        print("=" * 60)
        process_nazario_csv(nazario_file)
    else:
        print(f"File not found: {nazario_file}")
        print("Please ensure the Nazario.csv file exists in the datasets directory.")

if __name__ == "__main__":
    main()

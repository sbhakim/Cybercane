import pandas as pd
import re
import os
import argparse

def extract_email_from_sender(sender_value):
    """
    Extract email address from sender field.
    If the value contains '<' and '>', extract the content between them.
    Otherwise, return the original value.
    """
    if pd.isna(sender_value) or sender_value == '':
        return sender_value
    
    sender_str = str(sender_value)
    
    # Check if the sender contains '<' and '>'
    if '<' in sender_str and '>' in sender_str:
        # Extract content between '<' and '>'
        match = re.search(r'<([^>]+)>', sender_str)
        if match:
            return match.group(1).strip()
    
    # If no angle brackets or no match found, return original value
    return sender_str

def strip_parenthesized_timezone_suffix(value: str):
    """
    Remove a trailing parenthesized timezone abbreviation, e.g., " (BRT)".
    """
    return re.sub(r"\s*\([^)]*\)\s*$", "", value)

def normalize_timestamp_string(value):
    """
    Convert various email date formats (e.g., "Fri, 30 Oct 2015 06:21:59 -0300 (BRT)")
    into an ISO-8601 string with timezone offset, which Postgres parses reliably.

    Returns empty string when parsing fails or value is blank/NaN.
    """
    if pd.isna(value):
        return ""

    candidate = str(value).strip()
    if candidate == "":
        return ""

    # Drop trailing parenthesized tz, e.g., (BRT)
    candidate = strip_parenthesized_timezone_suffix(candidate)

    # Drop leading weekday name like "Fri, " if present
    candidate = re.sub(r"^[A-Za-z]{3,9},\s+", "", candidate)

    # Ensure timezone offset has a colon, e.g., -0300 -> -03:00
    if re.search(r"([+-])([0-9]{2})([0-9]{2})$", candidate):
        candidate = re.sub(r"([+-])([0-9]{2})([0-9]{2})$", r"\1\2:\3", candidate)

    # Let pandas parse into timezone-aware timestamp if possible
    ts = pd.to_datetime(candidate, utc=False, errors='coerce')
    if pd.isna(ts):
        return ""

    try:
        return ts.isoformat()
    except Exception:
        return ""

def clean_dataset(input_file_path, output_file_path=None):
    """
    Clean the dataset for ingestion:
    - Ensure 'sender_email' exists (derive from 'sender' when missing/blank)
    - Normalize 'date'/'msg_date' to ISO-8601 in column 'msg_date'
    - Coerce 'urls' to 0/1 smallint and fill blanks with 0
    - Coerce 'label' to nullable smallint (0/1) and blanks -> NULL
    - Reorder columns to match COPY target
    """
    try:
        print(f"Reading CSV file: {input_file_path}")
        df = pd.read_csv(input_file_path)

        print(f"Original data shape: {df.shape}")
        print(f"Columns: {list(df.columns)}")

        # sender_email handling
        if 'sender_email' not in df.columns:
            if 'sender' in df.columns:
                df['sender_email'] = df['sender'].apply(extract_email_from_sender)
            else:
                df['sender_email'] = ''
        else:
            if 'sender' in df.columns:
                fallback = df['sender'].apply(extract_email_from_sender)
                df['sender_email'] = df['sender_email'].where(
                    df['sender_email'].notna() & (df['sender_email'].astype(str).str.strip() != ''),
                    fallback
                )

        # Timestamp normalization
        if 'msg_date' in df.columns:
            df['msg_date'] = df['msg_date'].apply(normalize_timestamp_string)
        elif 'date' in df.columns:
            df['msg_date'] = df['date'].apply(normalize_timestamp_string)
        else:
            df['msg_date'] = ''

        # urls -> 0/1 smallint, blanks -> 0
        if 'urls' in df.columns:
            def _to_binary_smallint(v):
                s = str(v).strip()
                if s == '':
                    return 0
                try:
                    i = int(float(s))  # tolerate '0.0' style
                    return 1 if i >= 1 else 0
                except Exception:
                    return 0
            df['urls'] = df['urls'].apply(_to_binary_smallint).astype('int16')
        else:
            df['urls'] = 0

        # label -> nullable smallint 0/1
        if 'label' in df.columns:
            def _to_nullable_binary_smallint(v):
                s = str(v).strip()
                if s == '':
                    return pd.NA
                try:
                    i = int(float(s))
                    if i in (0, 1):
                        return i
                    return pd.NA
                except Exception:
                    return pd.NA
            df['label'] = df['label'].apply(_to_nullable_binary_smallint).astype('Int16')
        else:
            df['label'] = pd.NA

        # Ensure required columns exist for COPY
        desired_cols = [
            'sender', 'receiver', 'msg_date', 'subject', 'body',
            'urls', 'label', 'sender_email', 'url_extracted'
        ]
        for col in desired_cols:
            if col not in df.columns:
                df[col] = '' if col not in ('urls', 'label') else (0 if col == 'urls' else pd.NA)

        # Reorder and export
        df_out = df[desired_cols]

        if output_file_path is None:
            base, ext = os.path.splitext(input_file_path)
            output_file_path = f"{base}.clean.csv"

        print(f"\nSaving cleaned data to: {output_file_path}")
        df_out.to_csv(output_file_path, index=False)

        print(f"Successfully processed {len(df_out)} rows.")
        print(f"New columns/order: {desired_cols}")
        return df_out
    except FileNotFoundError:
        print(f"Error: File '{input_file_path}' not found.")
    except Exception as e:
        print(f"Error processing file: {str(e)}")
    return None

def clean_sender_data(input_file_path, output_file_path=None):
    """Backward-compatible wrapper that calls clean_dataset."""
    return clean_dataset(input_file_path, output_file_path)

def main():
    parser = argparse.ArgumentParser(description="Clean CSV for DB ingestion (normalize timestamps, sender_email, urls/label)")
    parser.add_argument('-i', '--input', required=True, help='Path to input CSV file')
    parser.add_argument('-o', '--output', default=None, help='Path to write cleaned CSV (default: <input>.clean.csv)')
    args = parser.parse_args()

    clean_dataset(args.input, args.output)

if __name__ == "__main__":
    main()

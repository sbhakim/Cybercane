import pandas as pd
import os

def split_csv_file(input_file_path, output_file_1, output_file_2):
    """
    Split a CSV file into two equal parts.
    
    Args:
        input_file_path (str): Path to the input CSV file
        output_file_1 (str): Path for the first output CSV file
        output_file_2 (str): Path for the second output CSV file
    """
    try:
        # Read the CSV file
        print(f"Reading CSV file: {input_file_path}")
        df = pd.read_csv(input_file_path)
        
        # Get the total number of rows
        total_rows = len(df)
        print(f"Total rows in the file: {total_rows}")
        
        # Calculate the split point (middle of the dataset)
        split_point = total_rows // 2
        
        # Split the dataframe
        df_part1 = df.iloc[:split_point]
        df_part2 = df.iloc[split_point:]
        
        # Save the first part
        df_part1.to_csv(output_file_1, index=False)
        print(f"First part saved to: {output_file_1}")
        print(f"Rows in first part: {len(df_part1)}")
        
        # Save the second part
        df_part2.to_csv(output_file_2, index=False)
        print(f"Second part saved to: {output_file_2}")
        print(f"Rows in second part: {len(df_part2)}")
        
        print(f"\nSplit completed successfully!")
        print(f"Total rows: {total_rows}")
        print(f"Part 1: {len(df_part1)} rows")
        print(f"Part 2: {len(df_part2)} rows")
        
    except FileNotFoundError:
        print(f"Error: File '{input_file_path}' not found.")
    except Exception as e:
        print(f"Error: {str(e)}")

def main():
    # Define file paths
    input_file = "../../datasets/phishing_email.csv"
    output_file_1 = "../../datasets/phishing_email_1.csv"
    output_file_2 = "../../datasets/phishing_email_2.csv"
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' does not exist.")
        return
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file_1), exist_ok=True)
    
    # Split the CSV file
    split_csv_file(input_file, output_file_1, output_file_2)

if __name__ == "__main__":
    main()
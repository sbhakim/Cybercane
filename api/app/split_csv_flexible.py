import pandas as pd
import os
import argparse

def split_csv_file(input_file_path, output_file_1, output_file_2, split_ratio=0.5):
    """
    Split a CSV file into two parts with a specified ratio.
    
    Args:
        input_file_path (str): Path to the input CSV file
        output_file_1 (str): Path for the first output CSV file
        output_file_2 (str): Path for the second output CSV file
        split_ratio (float): Ratio for the first part (0.0 to 1.0)
    """
    try:
        # Read the CSV file
        print(f"Reading CSV file: {input_file_path}")
        df = pd.read_csv(input_file_path)
        
        # Get the total number of rows
        total_rows = len(df)
        print(f"Total rows in the file: {total_rows}")
        
        # Calculate the split point based on ratio
        split_point = int(total_rows * split_ratio)
        
        # Split the dataframe
        df_part1 = df.iloc[:split_point]
        df_part2 = df.iloc[split_point:]
        
        # Save the first part
        df_part1.to_csv(output_file_1, index=False)
        print(f"First part saved to: {output_file_1}")
        print(f"Rows in first part: {len(df_part1)} ({len(df_part1)/total_rows*100:.1f}%)")
        
        # Save the second part
        df_part2.to_csv(output_file_2, index=False)
        print(f"Second part saved to: {output_file_2}")
        print(f"Rows in second part: {len(df_part2)} ({len(df_part2)/total_rows*100:.1f}%)")
        
        print(f"\nSplit completed successfully!")
        print(f"Total rows: {total_rows}")
        print(f"Part 1: {len(df_part1)} rows ({len(df_part1)/total_rows*100:.1f}%)")
        print(f"Part 2: {len(df_part2)} rows ({len(df_part2)/total_rows*100:.1f}%)")
        
    except FileNotFoundError:
        print(f"Error: File '{input_file_path}' not found.")
    except Exception as e:
        print(f"Error: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Split a CSV file into two parts')
    parser.add_argument('--input', '-i', default='../../datasets/phishing_email.csv', 
                       help='Input CSV file path')
    parser.add_argument('--output1', '-o1', default='../../datasets/phishing_email_1.csv',
                       help='First output CSV file path')
    parser.add_argument('--output2', '-o2', default='../../datasets/phishing_email_2.csv',
                       help='Second output CSV file path')
    parser.add_argument('--ratio', '-r', type=float, default=0.5,
                       help='Split ratio for first part (0.0 to 1.0, default: 0.5)')
    
    args = parser.parse_args()
    
    # Check if input file exists
    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' does not exist.")
        return
    
    # Validate ratio
    if not 0.0 <= args.ratio <= 1.0:
        print(f"Error: Split ratio must be between 0.0 and 1.0, got {args.ratio}")
        return
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(args.output1), exist_ok=True)
    
    # Split the CSV file
    split_csv_file(args.input, args.output1, args.output2, args.ratio)

if __name__ == "__main__":
    main()


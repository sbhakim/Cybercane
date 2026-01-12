import csv
import os

def split_csv_file(input_file_path, output_file_1, output_file_2, split_ratio=0.5):
    """
    Split a CSV file into two parts with a specified ratio using built-in csv module.
    
    Args:
        input_file_path (str): Path to the input CSV file
        output_file_1 (str): Path for the first output CSV file
        output_file_2 (str): Path for the second output CSV file
        split_ratio (float): Ratio for the first part (0.0 to 1.0)
    """
    try:
        # Read the CSV file and count rows
        print(f"Reading CSV file: {input_file_path}")
        
        with open(input_file_path, 'r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            rows = list(reader)
        
        total_rows = len(rows)
        print(f"Total rows in the file: {total_rows}")
        
        # Calculate the split point based on ratio
        split_point = int(total_rows * split_ratio)
        
        # Split the rows
        rows_part1 = rows[:split_point]
        rows_part2 = rows[split_point:]
        
        # Write the first part
        with open(output_file_1, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerows(rows_part1)
        
        print(f"First part saved to: {output_file_1}")
        print(f"Rows in first part: {len(rows_part1)} ({len(rows_part1)/total_rows*100:.1f}%)")
        
        # Write the second part
        with open(output_file_2, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerows(rows_part2)
        
        print(f"Second part saved to: {output_file_2}")
        print(f"Rows in second part: {len(rows_part2)} ({len(rows_part2)/total_rows*100:.1f}%)")
        
        print(f"\nSplit completed successfully!")
        print(f"Total rows: {total_rows}")
        print(f"Part 1: {len(rows_part1)} rows ({len(rows_part1)/total_rows*100:.1f}%)")
        print(f"Part 2: {len(rows_part2)} rows ({len(rows_part2)/total_rows*100:.1f}%)")
        
    except FileNotFoundError:
        print(f"Error: File '{input_file_path}' not found.")
    except Exception as e:
        print(f"Error: {str(e)}")

def main():
    # Define file paths
    input_file = "../../datasets/phishing_email.csv"
    output_file_1 = "../../datasets/phishing_email_1.csv"
    output_file_2 = "../../datasets/phishing_email_2.csv"
    split_ratio = 0.5  # 50/50 split
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' does not exist.")
        return
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file_1), exist_ok=True)
    
    # Split the CSV file
    split_csv_file(input_file, output_file_1, output_file_2, split_ratio)

if __name__ == "__main__":
    main()


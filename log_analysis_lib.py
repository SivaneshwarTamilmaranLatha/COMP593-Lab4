import sys 
import os 
import re
import pandas as pd

def main():
    # Retrieve the patrh of the log file  from the command line where the log file is located.
    log_path = get_file_path_from_cmd_line() 
 
    # Conduct a study on the gateway log 
    filtered_records, _ = filter_log_by_regex(log_path, 'error', print_summary=True, print_records=True)
 
    # Pull information from the gateway log 
    filtered_records, extracted_data = filter_log_by_regex(log_path, r'SRC=(.*?) DST=(.*?) LEN=(.*?)')
    extracted_df = pd.DataFrame(extracted_data, columns=('Source IP', 'Destination IP', 'Length')) 

def get_file_path_from_cmd_line(param_num=1):
    # Verify if the parameter from the command line was provided 
    if len(sys.argv) < param_num + 1:
        print(f'Error: Pass log file path as command line parameter {param_num} expected to be missing. ') 
        sys.exit('Script execution aborted')
    
    # Call the stored procedure and get the parameter value and store it in full path 
    log_path = os.path.abspath(sys.argv[param_num]) 
 
    # Perform a test to know if the file is present 
    if not os.path.isfile(log_path):
        print(f'Error: "{log_path}" does not point to any file. ') 
        sys.exit('Script execution aborted')
    
    return log_path 
 
def filter_log_by_regex(log_path, regex, ignore_case=True, print_summary=False, print_records=False):
    # Initalize lists returned by function
    filtered_records = []
    captured_data = []

    # Set the regex search flag for case sensitivity
    search_flags = re.IGNORECASE if ignore_case else 0

    # Iterate the log file line by line
    with open(log_path, 'r') as file:
        for record in file:
            # Check each line for regex match
            match = re.search(regex, record, search_flags)
            if match:
                # Add lines that match to list of filtered records
                filtered_records.append(record.strip()) # Remove the trailing new line
                # Check if regex match contains any capture groups
                if match.lastindex:
                    # Add tuple of captured data to captured data list
                    captured_data.append(match.groups())

    # Print all records, if enabled
    if print_records:
        print(*filtered_records, sep='\n', end='\n')

    # Print summary of results, if enabled
    if print_summary:
        print(f'The log file contains {len(filtered_records)} records that case-{"in" if ignore_case else ""}sensitive match the regex "{regex}".')

    return (filtered_records, captured_data)

if __name__ == '__main__': 
    main() 

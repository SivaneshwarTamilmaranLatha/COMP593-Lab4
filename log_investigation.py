import re 
import pandas as pd 
import log_analysis_lib

# Get the log file path from the command line
# Because this is outside of any function, log_path is a global variable
log_path = log_analysis_lib.get_file_path_from_cmd_line()

def main():
    # Determine how much traffic is on each port
    port_traffic = tally_port_traffic(log_path)

    # Per step 9, generate reports for ports that have 100 or more records
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(log_path, port)

    # Generate report of invalid user login attempts
    generate_invalid_user_report(log_path)

    # Generate log of records from source IP 220.195.35.40
    generate_source_ip_log(log_path, '220.195.35.40')

def tally_port_traffic(log_path):
    port_tally = {}

    with open(log_path, 'r') as file:
        for record in file:
            # Get destination port with the use of regex
            match = re.search(r'DPT=(\d+)', record)
            if match:
                dpt = match.group(1)
                if dpt in port_tally:
                    port_tally[dpt] += 1
                else:
                    port_tally[dpt] = 1

    return port_tally

def generate_port_traffic_report(log_path, destination_port):
    report_data = []

    with open(log_path, 'r') as file:
        for record in file:
            # Identify and catches the field that correpond
            match = re.search(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+.*SRC=(.*?) DST=(.*?) SPT=(.*?) DPT=(%s)' % destination_port, 
                record
            )
            if match:
                date_time, src_ip, dst_ip, src_port, dst_port = match.groups()
                date, time = date_time.split(' ', 1)
                report_data.append((date, time, src_ip, dst_ip, src_port, dst_port))

    # DataFrame to CSV
    report_df = pd.DataFrame(report_data, columns=['Date', 'Time', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port'])
    report_df.to_csv(f'destination_port_{destination_port}_report.csv', index=False)

def generate_invalid_user_report(log_path):
    report_data = []

    with open(log_path, 'r') as file:
        for record in file:
            # Identify and catch the fields for invalid user login attempts
            match = re.search(
                r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+.*Invalid user (\w+) from (.*?)\s', 
                record
            )
            if match:
                date_time, username, ip_address = match.groups()
                date, time = date_time.split(' ', 1)
                report_data.append((date, time, username, ip_address))

    # DataFrame to CSV
    report_df = pd.DataFrame(report_data, columns=['Date', 'Time', 'Username', 'IP Address'])
    report_df.to_csv('invalid_users.csv', index=False)

def generate_source_ip_log(log_path, ip_address): 
    matching_records = [] 
    
    with open(log_path, 'r') as file:
        for record in file: 
            # Determine if this record extracts the source IP 
            if f'SRC={ip_address}' in record:
                matching_records.append(record.strip()) 
 
    # Name output file name
    output_file_name = f'source_ip_{ip_address.replace(".", "_")}.log' 
 
    # Next, the records that has matched in both files are copied to the output file. 
    with open(output_file_name, 'w') as output_file:
        for record in matching_records:
            output_file.write(record + '\n')

if __name__ == '__main__':
    main()
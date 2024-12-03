import re
import pandas as pd
from tabulate import tabulate

class LogAnalyzer:
    def __init__(self, filename):
        self.filename = filename
        self.log_df = self.convert_log_to_df()

    def convert_log_to_df(self):
        log_pattern = r'(\S+) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+|-) ?(.*)?'
        parsed_logs = []
        with open(self.filename, 'r') as f:
            for line in f:
                line = line.strip()
                match = re.match(log_pattern, line)
                if match:
                    ip, timestamp, request, status, size, message = match.groups()
                    parsed_logs.append({
                        "IP": ip,
                        "Timestamp": timestamp,
                        "Request": request,
                        "Status": int(status),
                        "Size": int(size) if size.isdigit() else None,
                        "Message": message if message else None
                    })
        f.close()

        df = pd.DataFrame(parsed_logs)
        return df

    def count_requests_per_ip(self):
        request_ips = self.log_df.groupby("IP").size().reset_index(name="Number of requests")
        return request_ips

    def most_frequent_endpoint(self):
        endpoint_counts = self.log_df.groupby("Request").size().reset_index(name="Frequency")
        max_req_endpoint = endpoint_counts.loc[endpoint_counts["Frequency"].idxmax(), "Request"].split()[1]
        max_req = endpoint_counts["Frequency"].max()
        return max_req_endpoint, max_req

    def suspicious_activity(self, threshold, status_code, message):
        failed_attempts = self.log_df[
            (self.log_df["Status"] == status_code) | (self.log_df["Message"] == message)
        ]
        failed_ip_count = failed_attempts["IP"].value_counts()
        suspicious_ips = failed_ip_count[failed_ip_count > threshold].reset_index(name="Failed login attempts")
        return suspicious_ips

    def write_data_to_csv(self, ip_requests_count, endpoint, access_count, suspicious_ips):
        output_filename = "log_analysis_output.csv"
        data_to_save = {
            "Metric": ["Number of Requests per IP", "Most Frequent Endpoint", "Suspicious Activity"],
            "Details": [
                ip_requests_count.to_dict(orient="records"),
                f"{endpoint} (Accessed {access_count} times)",
                suspicious_ips.to_dict(orient="records")
            ]
        }
        output_df = pd.DataFrame(data_to_save)
        output_df.to_csv(output_filename, index=False)

    def formatted_print(self, df):
        print(tabulate(df, headers='keys', tablefmt='grid', showindex=False))

def main():
    log_analyzer = LogAnalyzer('sample.log')
    
    ip_requests_count = log_analyzer.count_requests_per_ip()
    print("\nNumber of Requests from each IP")
    log_analyzer.formatted_print(ip_requests_count)
    
    endpoint, access_count = log_analyzer.most_frequent_endpoint()
    print(f'\nMost frequently accessed endpoint\n{endpoint} (Accessed {access_count} times)')
    
    suspicious_ips = log_analyzer.suspicious_activity(5, 401, "Invalid Credentials")
    print("\nSuspicious IPs")
    log_analyzer.formatted_print(suspicious_ips)

    log_analyzer.write_data_to_csv(ip_requests_count, endpoint, access_count, suspicious_ips)

if __name__ == '__main__':
    main()

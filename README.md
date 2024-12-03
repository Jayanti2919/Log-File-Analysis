# Log Analyzer

This Python script is designed to analyze log files, count requests by IP, identify the most frequently accessed endpoints, and detect potential brute force login attempts. The results can be displayed in the console and are written to a CSV file for further analysis.

## Features
- **Log Parsing**: Converts a log file into a structured DataFrame.
- **IP Request Counting**: Calculates the number of requests made by each unique IP address.
- **Most Frequent Endpoint**: Identifies the most frequently accessed endpoint.
- **Suspicious Activity Detection**: Flags IPs with failed login attempts exceeding a specified threshold (e.g., HTTP status code 401 or specific failure messages like "Invalid Credentials").
- **Formatted Output**: Displays results in a tabular format using `tabulate`.
- **CSV Export**: Saves the analysis results to a CSV file.

## Requirements

To run this script, you need the following Python libraries:

- `pandas` - for data handling and manipulation
- `tabulate` - for nicely formatted output
- `re` - for regex pattern matching (part of Python standard library)

You can install the required libraries using `pip`:

```bash
pip install -r requirements.txt
```

## Usage

### Step 1: Prepare the Log File
Make sure you have a log file (e.g., `sample.log`) in the same directory as the script. The log file should follow a standard web server log format.
The `sample.log` file is already included in the repository.

Example log entry:

```
192.168.1.1 - - [03/Dec/2024:10:12:43 +0000] "GET /dashboard HTTP/1.1" 200 1024
203.0.113.5 - - [03/Dec/2024:10:12:44 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
```

### Step 2: Run the Script
Simply run the script using Python:

```bash
python log_analyzer.py
```

### Step 3: View the Results
After running the script, the following will happen:
1. The script will print the number of requests made by each IP address.
2. It will display the most frequently accessed endpoint.
3. It will list any suspicious IPs based on failed login attempts exceeding the threshold.
4. The results will be saved to a CSV file called `log_analysis_output.csv`.

### Example Output (Console)

```
Number of Requests from each IP
+-------------------+--------------------+
| IP                |   Number of requests |
+-------------------+--------------------+
| 192.168.1.1      |                  5 |
| 203.0.113.34     |                  8 |
| 192.168.1.100    |                 56 |
+-------------------+--------------------+

Most frequently accessed endpoint
POST /login HTTP/1.1 (Accessed 78 times)

Suspicious IPs
+-------------------+----------------------+
| IP                |   Failed login attempts |
+-------------------+----------------------+
| 192.168.1.100    |                   56 |
| 203.0.113.34     |                   12 |
+-------------------+----------------------+
```

### Example Output (CSV)

The results will be saved in a CSV file `log_analysis_output.csv` with the following structure:

| Metric                    | Details                                              |
|---------------------------|-----------------------------------------------------|
| Number of Requests per IP | [{'IP': '192.168.1.1', 'Number of requests': 5}, ...] |
| Most Frequent Endpoint    | POST /login HTTP/1.1 (Accessed 78 times)            |
| Suspicious Activity       | [{'IP': '192.168.1.100', 'Failed login attempts': 56}, ...] |

## Script Breakdown

### LogAnalyzer Class
The `LogAnalyzer` class encapsulates the following methods:

1. **`convert_log_to_df()`**: Parses the log file into a pandas DataFrame.
2. **`count_requests_per_ip()`**: Groups log entries by IP and counts the requests.
3. **`most_frequent_endpoint()`**: Identifies the most frequently accessed endpoint.
4. **`suspicious_activity()`**: Flags IPs with failed login attempts exceeding the threshold.
5. **`write_data_to_csv()`**: Saves the analysis results to a CSV file.
6. **`formatted_print()`**: Prints DataFrames in a nice tabular format.

### Main Function
The `main()` function is responsible for:
- Initializing the `LogAnalyzer` class with a log file.
- Calling methods to perform the analysis.
- Printing results to the console.
- Saving the results to a CSV file.

---

### Additional Notes:
- Make sure the log file format matches the expected format, or adjust the regex pattern as needed.
- You can modify the threshold for suspicious activity detection by changing the `threshold` argument in the `suspicious_activity()` method.

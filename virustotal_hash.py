import requests
import time

def check_with_virustotal(file_hash, api_key):
    """
    Queries the VirusTotal API for information about a file hash using the provided API key.
    """
    # Base URL for VirusTotal API
    VT_URL = 'https://www.virustotal.com/api/v3/files/'

    headers = {
        "x-apikey": api_key
    }

    try:
        start_time = time.time()  # Start timer for performance measurement
        response = requests.get(VT_URL + file_hash, headers=headers)

        # If the response status is 404, handle it specifically
        if response.status_code == 404:
            print(f"Hash {file_hash} not found in VirusTotal.")
            return

        response.raise_for_status()  # Raise an HTTPError for other bad responses (4xx, 5xx)
        result = response.json()

        if 'data' not in result:
            print(f"No data found for the given hash: {file_hash}")
            return

        data = result['data']
        attributes = data.get('attributes', {})

        # Extract general file info
        file_name = attributes.get('file_name', 'Unknown')
        date_submitted = attributes.get('date', 'Unknown')

        print("\n===== File Information =====")
        print(f"File Name       : {file_name}")
        print(f"Date Submitted  : {date_submitted}")
        print("="*30)

        # Extract hashes (MD5, SHA1, SHA256)
        md5_hash = attributes.get('md5', 'Unknown')
        sha1_hash = attributes.get('sha1', 'Unknown')
        sha256_hash = attributes.get('sha256', 'Unknown')

        print("\n===== Hashes =====")
        print(f"MD5             : {md5_hash}")
        print(f"SHA-1           : {sha1_hash}")
        print(f"SHA-256         : {sha256_hash}")
        print("="*30)

        # Extract additional file information
        vhash = attributes.get('vhash', 'Unknown')
        ssdeep = attributes.get('ssdeep', 'Unknown')

        print("\n===== Additional Information =====")
        print(f"Vhash           : {vhash}")
        print(f"SSDEEP          : {ssdeep}")
        print("="*30)

        # Extract analysis stats
        analysis_stats = attributes.get('last_analysis_stats', {})
        malicious_count = analysis_stats.get('malicious', 0)
        harmless_count = analysis_stats.get('harmless', 0)
        suspicious_count = analysis_stats.get('suspicious', 0)
        undetected_count = analysis_stats.get('undetected', 0)

        print("\n===== Analysis Stats =====")
        print(f"Malicious       : {malicious_count}")
        print(f"Harmless        : {harmless_count}")
        print(f"Suspicious      : {suspicious_count}")
        print(f"Undetected      : {undetected_count}")
        print("="*30)

        # Extract detailed analysis results
        scan_results = attributes.get('last_analysis_results', {})
        if malicious_count > 0:
            print("\n===== Malicious Engines Detected =====")
            for engine, result in scan_results.items():
                if result.get('category') == 'malicious':
                    engine_name = result.get('engine_name', 'Unknown')
                    result_message = result.get('result', 'Unknown')
                    print(f"  - {engine_name}: {result_message}")
        else:
            print("\nNo engines flagged as malicious.")

        print("="*30)

        # Time taken to analyze the file
        end_time = time.time()
        time_taken = end_time - start_time
        print(f"Time taken for analysis: {time_taken:.2f} seconds")

        # Track detection rates
        total_checked = malicious_count + harmless_count
        if total_checked > 0:
            detection_rate = (malicious_count / total_checked) * 100
            print(f"Detection Rate: {detection_rate:.2f}%")
        else:
            print("No analysis results available for detection.")

        # Improve efficiency statement
        estimated_time_per_hash = 10  # Hypothetical manual check time in seconds
        time_saved = estimated_time_per_hash - time_taken
        if time_saved > 0:
            print(f"Time saved per hash: {time_saved:.2f} seconds")

        print("="*30)

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to VirusTotal API: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    """
    Main function to handle user input and process a single hash.
    """
    # Prompt for the API key
    api_key = input("Enter your VirusTotal API key: ").strip()
    
    # Prompt for the hash to check
    file_hash = input("Enter the hash to check: ").strip()
    
    print(f"\nChecking hash: {file_hash}")
    check_with_virustotal(file_hash, api_key)

if __name__ == "__main__":
    main()

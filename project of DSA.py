import time

# Function to get traffic data dynamically
def get_traffic_data():
    # Predefined traffic data
    traffic_data = [
        {"ip": "192.168.1.1", "timestamp": 1609459200},  # Request 1
        {"ip": "192.168.1.1", "timestamp": 1609459210},  # Request 2
        {"ip": "192.168.1.1", "timestamp": 1609459220},  # Request 3
        {"ip": "192.168.1.1", "timestamp": 1609459230},  # Request 4
        {"ip": "192.168.1.1", "timestamp": 1609459240},  # Request 5
    ]
    
    print("Initial traffic data: ", traffic_data)
    print("You can add more traffic data or type 'done' to finish.")
    
    # Collect additional traffic data
    while True:
        entry = input("Traffic entry (IP,timestamp): ")
        if entry.lower() == 'done':
            break
        try:
            ip, timestamp = entry.split(",")
            traffic_data.append({"ip": ip.strip(), "timestamp": int(timestamp.strip())})
        except ValueError:
            print("Invalid format. Please use IP,timestamp.")
    
    print(f"Traffic data entered: {traffic_data}")
    return traffic_data

# Function to get email headers dynamically
def get_email_headers():
    from_field = input("Enter 'From' email address: ")
    reply_to_field = input("Enter 'Reply-To' email address: ")
    print(f"Email headers entered: From={from_field}, Reply-To={reply_to_field}")
    return {"From": from_field, "Reply-To": reply_to_field}

# Function to detect DoS attack
def detect_dos_attack(traffic_data, threshold, time_window):
    print(f"Threshold: {threshold}, Time Window: {time_window}s")
    ip_count = {}

    for request in traffic_data:
        ip = request["ip"]
        timestamp = request["timestamp"]

        if ip not in ip_count:
            ip_count[ip] = []

        ip_count[ip].append(timestamp)

        # Filter out requests older than the time window
        ip_count[ip] = [ts for ts in ip_count[ip] if timestamp - ts <= time_window]

        # Print debug info
        print(f"IP: {ip}, Requests in window: {ip_count[ip]}")

        # Check if the number of requests exceeds the threshold
        if len(ip_count[ip]) > threshold:
            print(f"Potential DoS attack detected from IP: {ip}")
            return True
    return False

# Function to check email headers for spoofing
def detect_email_spoofing(headers):
    from_field = headers.get("From", "")
    reply_to_field = headers.get("Reply-To", "")

    print(f"Checking email headers: From={from_field}, Reply-To={reply_to_field}")
    if from_field != reply_to_field:
        print(f"Potential email spoofing detected! From: {from_field}, Reply-To: {reply_to_field}")
        return True
    return False

# Main function to run both DoS detection and email spoofing detection
def main():
    print("=== Cybersecurity Monitoring System ===\n")

    # Dynamic input for network traffic data
    print("Provide network traffic data:")
    traffic_data = get_traffic_data()

    # Input for DoS detection parameters
    print("\nChecking for DoS attacks...\n")
    threshold = int(input("Enter the request threshold per IP to detect a DoS attack: "))
    time_window = int(input("Enter the time window (in seconds) for monitoring requests: "))

    # Run DoS detection
    if detect_dos_attack(traffic_data, threshold, time_window):
        print("Denial of Service attack detected!")
    else:
        print("No suspicious activity detected in the traffic data.")

    # Dynamic input for email headers
    print("\nProvide email headers for spoofing check:")
    email_headers = get_email_headers()

    # Run email spoofing detection
    print("\nChecking for email spoofing...\n")
    if detect_email_spoofing(email_headers):
        print("Email is likely spoofed!")
    else:
        print("Email seems legitimate.")

if __name__ == "__main__":
    main()

#!/bin/bash

# Start OpenVAS
sudo /usr/bin/gvm-start-edited

# Wait for OpenVAS to fully start up
echo "Waiting for OpenVAS to fully start..."
sleep 15

# Execute the main.py script and save both stdout and stderr to a logfile
echo "Executing main.py script..."
sudo /usr/bin/python3 /home/kali/Desktop/app_content/main2.py >> /home/kali/Desktop/logfile.log 2>&1

# Wait until the main.py script is fully executed
wait $!

# Stop OpenVAS
echo "Stopping OpenVAS..."
sudo gvm-stop

echo "Task completed. Next run tomorrow."

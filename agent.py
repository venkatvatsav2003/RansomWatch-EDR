import os
import time
import logging
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from entropy_calc import calculate_entropy

# Configuration
MONITOR_DIR = "./honeypot_dir"
ENTROPY_THRESHOLD = 7.5 # Out of 8.0 (High entropy implies encryption/compression)
MODIFICATION_RATE_THRESHOLD = 5 # files per second
TIME_WINDOW = 2 # seconds

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

class RansomwareDetectorHandler(FileSystemEventHandler):
    def __init__(self):
        self.modification_times = defaultdict(list)
        self.alerted = False

    def on_modified(self, event):
        if event.is_directory:
            return
        
        filepath = event.src_path
        self._analyze_file_change(filepath)

    def on_created(self, event):
        if event.is_directory:
            return
        
        filepath = event.src_path
        self._analyze_file_change(filepath)
        
    def _analyze_file_change(self, filepath):
        current_time = time.time()
        
        # Clean up old timestamps
        self.modification_times['global'] = [t for t in self.modification_times['global'] if current_time - t <= TIME_WINDOW]
        
        self.modification_times['global'].append(current_time)
        
        # Check rapid modification rate
        if len(self.modification_times['global']) / TIME_WINDOW >= MODIFICATION_RATE_THRESHOLD:
            if not self.alerted:
                logging.error(f"RAPID FILE MODIFICATION DETECTED: {len(self.modification_times['global'])} files in {TIME_WINDOW}s")
                self._trigger_response()
                self.alerted = True
                
        # Calculate entropy of the modified file
        try:
            entropy = calculate_entropy(filepath)
            if entropy > ENTROPY_THRESHOLD:
                logging.warning(f"HIGH ENTROPY DETECTED: {filepath} (Entropy: {entropy:.2f}). Possible encryption.")
        except Exception as e:
            # File might be locked or already deleted
            pass
            
    def _trigger_response(self):
        logging.critical("INITIATING THREAT RESPONSE PROTOCOL...")
        # In a real EDR, this would identify the PID causing the modifications and kill it via OS APIs
        logging.critical("Simulating isolation of process modifying files in honeypot directory.")

if __name__ == "__main__":
    if not os.path.exists(MONITOR_DIR):
        os.makedirs(MONITOR_DIR)
        logging.info(f"Created monitoring directory: {MONITOR_DIR}")

    event_handler = RansomwareDetectorHandler()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)
    
    logging.info(f"Starting RansomWatch EDR Agent on directory: {MONITOR_DIR}")
    observer.start()
    
    try:
        while True:
            time.sleep(1)
            # Reset alert state after a while for demonstration purposes
            event_handler.alerted = False 
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

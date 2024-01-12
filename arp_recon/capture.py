import os
import csv

class Capture:
    def __init__(self, arp_packet, directory, filename):
        self.arp_packet = arp_packet
        self.directory = directory
        self.filename = filename
        self.create_directory_if_not_exists()
        self.capture()

    def create_directory_if_not_exists(self):
        if not os.path.exists(self.directory):
            # print(f"Creating directory: {self.directory}")
            os.makedirs(self.directory)

    def capture(self):
        full_path = os.path.join(self.directory, self.filename)
        # print(f"Saving to file: {full_path}")
        try:
            with open(full_path, "a", newline='') as file:
                csv_writer = csv.writer(file)
                csv_writer.writerow(self.arp_packet.all_attributs()) 
        except Exception as e:
            print(f"Error while capturing: {str(e)}")

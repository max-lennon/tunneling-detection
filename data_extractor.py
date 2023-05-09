import argparse
import os
import pyshark
import pandas as pd

# parse the command line arguments
parser = argparse.ArgumentParser(description='Process packet capture files in a directory and save the results as CSV files')
parser.add_argument('directory', metavar='DIRECTORY', type=str, help='the root directory containing the packet capture files')
args = parser.parse_args()

# create an empty pandas DataFrame to store the packet information
packet_df = pd.DataFrame(columns=['timestamp', 'src', 'dst', 'protocol', 'length'])

# iterate over each file in the directory and its subdirectories
for root, dirs, files in os.walk(args.directory):
    for filename in files:

        # process each .pcapng file
        if filename.endswith('.pcapng'):
            # open the capture file with pyshark
            filepath = os.path.join(root, filename)
            capture = pyshark.FileCapture(filepath)

            # initialize variables to store client and server IP addresses
            client_ip = None
            server_ip = None

            # create a list to store packet information for this capture file
            packet_list = []

            # iterate over each packet in the capture file
            for i, packet in enumerate(capture):

                # determine the client and server IP addresses based on the first packet
                if client_ip is None:
                    if 'IP' in packet:
                        client_ip = packet.ip.src
                        server_ip = packet.ip.dst
                    else:
                        continue

                # extract the relevant packet information
                timestamp = float(packet.sniff_timestamp)
                if 'IP' in packet:
                    if packet.ip.src == client_ip:
                        src = 1
                        dst = 0
                    elif packet.ip.dst == client_ip:
                        src = 0
                        dst = 1
                    else:
                        src = -1
                        dst = -1
                    protocol = packet.transport_layer
                    length = int(packet.length)

                    # add the packet information to the list
                    packet_list.append({'timestamp': timestamp, 'src': src, 'dst': dst, 'protocol': protocol, 'length': length})

            # close the capture file
            capture.close()

            # convert the list to a pandas DataFrame and add it to the overall DataFrame
            packet_df = pd.concat([packet_df, pd.DataFrame(packet_list)], ignore_index=True)
            packet_df.insert(0, 'index', range(1, len(df) + 1))

            # save the pandas DataFrame to a CSV file with the same name as the capture file
            output_filename = os.path.splitext(filepath)[0] + '.csv'
            packet_df.to_csv(output_filename, index=False)

            # print a message indicating the name of the output file
            print('Packet information saved to ' + output_filename)

            # reset the pandas DataFrame for the next capture file
            packet_df = pd.DataFrame(columns=['timestamp', 'src', 'dst', 'protocol', 'length'])

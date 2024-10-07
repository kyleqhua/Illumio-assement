import csv
from collections import defaultdict

#Example log
#2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK

"""
0 Version: 2
1 Account ID: 123456789012
2 Network Interface ID: eni-0a1b2c3d
3 Source IP Address: 10.0.1.201
4 Destination IP Address: 198.51.100.2
5 Source Port: 49153
6 Destination Port: 443 (commonly used for HTTPS traffic)
7 Protocol: 6 (TCP)
Packets: 25
Bytes: 20000
Start Time: 1620140761 (Unix timestamp)
End Time: 1620140821 (Unix timestamp)
Action: ACCEPT
Log Status: OK
"""

class FlowLogsCounter:

    def __init__(self, lookupTablePath):
        self.lookup = self.parseLookUpTable(lookupTablePath)
        self.protocols = self.getProtocols()
    
    #Loads csv files, extracts dstport, protocol, and tag columns and returns a dict of (dstport, protocol):tag mappings. 
    #Checks for invalid inputs and errors as well.
    def parseLookUpTable(self, path):

        #checks if file is a csv
        if not path.endswith('.csv'):
            print(f"Error: The file '{path}' is not a CSV file.")
            return None  
        
        lookup = {}

        try:
            with open(path, "r") as f:

                #Checks the columns in csv file and makes sure all required columns are there
                columns = f.readline().strip().split(',')
                reqs = ['dstport', 'protocol', 'tag']
                for c in columns:
                    if c not in reqs:
                        print(f"Error: Missing required column '{c}' in CSV file.")
                        return None  
                

                #loads the content and adds value to map.
                f.seek(0)            
                table = csv.DictReader(f)
                for row in table:
                    dstport = row['dstport']
                    protocol = row['protocol'].lower()
                    tag = row['tag']
                    lookup[(dstport, protocol)] = tag
                return lookup
            
        except (FileNotFoundError, PermissionError, OSError) as e:
            print(f"An error occurred: {e}")
            return None
    
    def countFlowLog(self, path):
        #parses flow log file
        comboCount, tagCount = self.parseFlowLog(path)
        path = path[9:]
        #prints
        self.printReports(comboCount, tagCount, path[:-4])

    #loads flowlog file, extracts each log line and gets the dst port and protocol. Counts combo and tag.
    def parseFlowLog(self, path):
        tagCounts = defaultdict(int)
        ppComboCounts = defaultdict(int)

        try:
            with open(path, "r") as f:
                for l in f:
                    line = l.split()
                    if len(line) < 14:
                        continue
                    #print(line)
                    dstport = line[6]
                    protocolNum = line[7]

                    protocol = self.protocols.get(protocolNum, 'unknown')
                    combo = (dstport, protocol)

                    tag = self.lookup.get(combo, 'Untagged')

                    ppComboCounts[combo] += 1
                    tagCounts[tag] += 1
                
                return ppComboCounts, tagCounts
            
        except (FileNotFoundError, PermissionError, OSError) as e:
            print(f"An error occurred: {e}")
            return None, None
        
    #returns Lookup table dict
    def getLookUpTable(self):
        return self.lookup

    #Loads all protocols into a map. If the csv file containing all the protocols is not found, defaults to basic three.
    def getProtocols(self):
        protocols = {}

        try:
            with open("protocol-numbers-1.csv", "r") as f:
                table = csv.DictReader(f)
                for row in table:
                    number = row['Decimal']
                    protocol = row['Keyword'].lower()
                    protocols[number] = protocol

        except (FileNotFoundError, PermissionError, OSError) as e:
            print(f"An error occurred: {e}, defaulting to basic protocols.")
            protocols = {
                        '6': 'tcp',
                        '17': 'udp',
                        '1': 'icmp'
                    }

        return protocols
                 
    def printReports(self, comboCount, tagCount, fileName):
        if not comboCount or not tagCount:
            print("Error in parsing log files.")

        with open(f'counts/{fileName}_tag_counts.csv', 'w') as f:
            f.write('Tag,Count\n')
            for tag, count in tagCount.items():
                f.write(f'{tag},{count}\n')
    
        # Port/Protocol counts report
        with open(f'counts/{fileName}_port_protocol_counts.csv', 'w') as f:
            f.write('Port,Protocol,Count\n')
            for (port, protocol), count in comboCount.items():
                f.write(f'{port},{protocol},{count}\n')

    #TODO: take in a new lookup table and parse it and reset the counter's lookup table.
    def updateLookup(self, path):
        pass

def main():
   flows = FlowLogsCounter("lookupTables/lookup_table_ex1.csv")  
   
   flows.countFlowLog("flowLogs/flow_logs_ex1.txt")

if __name__ == '__main__':
    main()
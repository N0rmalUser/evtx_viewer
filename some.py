from evtx import Evtx

def read_evtx(file_path):
    with Evtx(file_path) as log:
        for record in log.records():
            print(record.xml())

# Replace with the path to your EVTX file
file_path = r'C:\Users\Alex\Desktop\Secretary\Security.evtx'
read_evtx(file_path)


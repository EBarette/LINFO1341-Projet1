import pyshark
import nest_asyncio
nest_asyncio.apply()

def process_domain_name(filename):
    cap = pyshark.FileCapture(filename)

    relative_time = None
    list = []
    for pkt in cap:
        if pkt.highest_layer == "DNS" and pkt.dns.qry_name:
            if relative_time is None:
                relative_time = float(pkt.sniff_timestamp)
            list.append([pkt.dns.qry_name, float(pkt.sniff_timestamp) - relative_time, pkt.number])
    return list

if __name__ == "__main__":
    print("imgToDrive.pcapng")
    for pkt in process_domain_name("WiresharkCapture/imgToDrive.pcapng"):
        print(pkt)
    
    print("imgToDrive2.pcapng")
    for pkt in process_domain_name("WiresharkCapture/imgToDrive2.pcapng"):
        print(pkt)
    
    print("imgToDrive3.pcapng")
    for pkt in process_domain_name("WiresharkCapture/imgToDrive3.pcapng"):
        print(pkt)
    
    print("imgToDrive4.pcapng")
    for pkt in process_domain_name("WiresharkCapture/imgToDrive4.pcapng"):
        print(pkt)
    
    print("imgToDrive5.pcapng")
    for pkt in process_domain_name("WiresharkCapture/imgToDrive5.pcapng"):
        print(pkt)
    
    print("Linux_Wifi_pdfTo&OffDrive.pcapng")
    for pkt in process_domain_name("WiresharkCapture/Linux_Wifi_pdfTo&OffDrive.pcapng"):
        print(pkt)
    
    print("Linux_Wifi_pdfToDrive.pcapng")
    for pkt in process_domain_name("WiresharkCapture/Linux_Wifi_pdfToDrive.pcapng"):
        print(pkt)
    
    print("Linux_Wifi_pdfToDrive2.pcapng")
    for pkt in process_domain_name("WiresharkCapture/Linux_Wifi_pdfToDrive2.pcapng"):
        print(pkt)
    
    print("Linux_Wifi_pdfToDrive3.pcapng")
    for pkt in process_domain_name("WiresharkCapture/Linux_Wifi_pdfToDrive3.pcapng"):
        print(pkt)
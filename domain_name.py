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
            uniqueDomainNames.add(pkt.dns.qry_name)
    return list

if __name__ == "__main__":
    uniqueDomainNames = set()

    # AJOUT DE FICHIER PCAPNG
    
    print("imgToDrive.pcapng")
    for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/imgToDrive.pcapng"):
        print(pkt)
    
    print("imgToDrive2.pcapng")
    for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/imgToDrive2.pcapng"):
        print(pkt)
    
    print("imgToDrive3.pcapng")
    for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/imgToDrive3.pcapng"):
        print(pkt)
    
    print("imgToDrive4.pcapng")
    for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/imgToDrive4.pcapng"):
        print(pkt)
    
    print("imgToDrive5.pcapng")
    for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/imgToDrive5.pcapng"):
        print(pkt)
    
    print("Linux_Wifi_pdfToDrive.pcapng")
    for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/Linux_Wifi_pdfToDrive.pcapng"):
        print(pkt)
    
    print("Linux_Wifi_pdfToDrive2.pcapng")
    for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/Linux_Wifi_pdfToDrive2.pcapng"):
        print(pkt)
    
    print("Linux_Wifi_pdfToDrive3.pcapng")
    for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/Linux_Wifi_pdfToDrive3.pcapng"):
        print(pkt)

    print("multipleFilesToDrive.pcapng")
    for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/multipleFilesToDrive.pcapng"):
        print(pkt)
    
    print("multipleFilesToDrive2.pcapng")
    for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/multipleFilesToDrive2.pcapng"):
        print(pkt)
    
    print("multipleFilesToDrive3.pcapng")
    for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/multipleFilesToDrive3.pcapng"):
        print(pkt)

    print("Unique domain names:")
    print(uniqueDomainNames)
    uniqueDomainNames.clear()

    # DELETE DE FICHIER PCAPNG
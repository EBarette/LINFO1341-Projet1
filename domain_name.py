import pyshark
import nest_asyncio
nest_asyncio.apply()

uniqueDomainNames = set()

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

    # # AJOUT DE FICHIER PCAPNG
    
    # print("\nimgToDrive.pcapng\n")
    # for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/imgToDrive.pcapng"):
    #     print(pkt)
    
    # print("\nimgToDrive2.pcapng\n")
    # for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/imgToDrive2.pcapng"):
    #     print(pkt)
    
    # print("\nimgToDrive3.pcapng\n")
    # for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/imgToDrive3.pcapng"):
    #     print(pkt)
    
    # print("\nimgToDrive4.pcapng\n")
    # for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/imgToDrive4.pcapng"):
    #     print(pkt)
    
    # print("\nimgToDrive5.pcapng\n")
    # for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/imgToDrive5.pcapng"):
    #     print(pkt)
    
    # print("\nLinux_Wifi_pdfToDrive.pcapng\n")
    # for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/Linux_Wifi_pdfToDrive.pcapng"):
    #     print(pkt)
    
    # print("\nLinux_Wifi_pdfToDrive2.pcapng\n")
    # for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/Linux_Wifi_pdfToDrive2.pcapng"):
    #     print(pkt)
    
    # print("\nLinux_Wifi_pdfToDrive3.pcapng\n")
    # for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/Linux_Wifi_pdfToDrive3.pcapng"):
    #     print(pkt)

    # print("\nmultipleFilesToDrive.pcapng\n")
    # for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/multipleFilesToDrive.pcapng"):
    #     print(pkt)
    
    # print("\nmultipleFilesToDrive2.pcapng\n")
    # for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/multipleFilesToDrive2.pcapng"):
    #     print(pkt)
    
    # print("\nmultipleFilesToDrive3.pcapng\n")
    # for pkt in process_domain_name("WiresharkCapture/AjoutDeFichiers/multipleFilesToDrive3.pcapng"):
    #     print(pkt)

    # print("\nUnique domain names:")
    # print(uniqueDomainNames)
    # uniqueDomainNames.clear()

    # CAS PARTICULIERS
    
    print("\ndeleteFromPhone.pcapng\n")
    for pkt in process_domain_name("WiresharkCapture/CasParticuliers/deleteFromPhone.pcapng"):
        print(pkt)
    
    print("\nLinux_Wifi_pdfTo&OffDrive.pcapng\n")
    for pkt in process_domain_name("WiresharkCapture/CasParticuliers/Linux_Wifi_pdfTo&OffDrive.pcapng"):
        print(pkt)
    
    print("\nmodifyFromPhone.pcapng\n")
    for pkt in process_domain_name("WiresharkCapture/CasParticuliers/modifyFromPhone.pcapng"):
        print(pkt)

    print("\nUnique domain names:")
    print(uniqueDomainNames)
    uniqueDomainNames.clear()

    # DELETE DE FICHIERS PCAPNG
    
    print("\ndeleteMultipleFiles.pcapng\n")
    for pkt in process_domain_name("WiresharkCapture/DeleteDeFichiers/deleteMultipleFiles.pcapng"):
        print(pkt)
    
    print("\ndeleteMultipleFiles2.pcapng\n")
    for pkt in process_domain_name("WiresharkCapture/DeleteDeFichiers/deleteMultipleFiles2.pcapng"):
        print(pkt)
    
    print("\ndeleteMultipleFiles3.pcapng\n")
    for pkt in process_domain_name("WiresharkCapture/DeleteDeFichiers/deleteMultipleFiles3.pcapng"):
        print(pkt)

    print("\nUnique domain names:")
    print(uniqueDomainNames)
    uniqueDomainNames.clear()

    # MODIF DE FICHIERS PCAPNG
    
    print("\nmodifyFileOnDrive.pcapng\n")
    for pkt in process_domain_name("WiresharkCapture/ModifDeFichiers/modifyFileOnDrive.pcapng"):
        print(pkt)
    
    print("\nmodifyFileOnDrive2.pcapng\n")
    for pkt in process_domain_name("WiresharkCapture/ModifDeFichiers/modifyFileOnDrive2.pcapng"):
        print(pkt)
    
    print("\nmodifyFileOnDrive3.pcapng\n")
    for pkt in process_domain_name("WiresharkCapture/ModifDeFichiers/modifyFileOnDrive3.pcapng"):
        print(pkt)

    print("\nUnique domain names:")
    print(uniqueDomainNames)
    uniqueDomainNames.clear()
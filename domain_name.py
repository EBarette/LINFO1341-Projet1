import pyshark
import nest_asyncio
nest_asyncio.apply()

uniqueDomainNames = set()

def process_domain_name(filename):
    cap = pyshark.FileCapture("WiresharkCapture/" + filename)

    relative_time = None
    list = []
    for pkt in cap:
        if pkt.highest_layer == "DNS" and pkt.dns.qry_name:
            if relative_time is None:
                relative_time = float(pkt.sniff_timestamp)
            list.append([pkt.dns.qry_name, pkt.dns.qry_type, float(pkt.sniff_timestamp) - relative_time, pkt.number])
            uniqueDomainNames.add(pkt.dns.qry_name)
    return list

def pretty_print(filename):
    print("\n" + filename + "\n")
    for pkt in process_domain_name(filename):
        print(pkt)

if __name__ == "__main__":

    # AJOUT DE FICHIER PCAPNG
    
    pretty_print("AjoutDeFichiers/imgToDrive.pcapng")
    
    pretty_print("AjoutDeFichiers/imgToDrive2.pcapng")
    
    pretty_print("AjoutDeFichiers/imgToDrive3.pcapng")
    
    pretty_print("AjoutDeFichiers/imgToDrive4.pcapng")
    
    pretty_print("AjoutDeFichiers/imgToDrive5.pcapng")
    
    pretty_print("AjoutDeFichiers/Linux_WifiUCL_pdfToDrive.pcapng")
    
    pretty_print("AjoutDeFichiers/Linux_WifiUCL_pdfToDrive2.pcapng")
    
    pretty_print("AjoutDeFichiers/Linux_Wifi_pdfToDrive3.pcapng")

    pretty_print("AjoutDeFichiers/multipleFilesToDrive.pcapng")
    
    pretty_print("AjoutDeFichiers/multipleFilesToDrive2.pcapng")
    
    pretty_print("AjoutDeFichiers/multipleFilesToDrive3.pcapng")

    pretty_print("AjoutDeFichiers/Linux_4G_ImageToDrive.pcapng")

    pretty_print("AjoutDeFichiers/Linux_4G_PdfToDrive.pcapng")
        
    print("\nUnique domain names:")
    print(uniqueDomainNames)
    uniqueDomainNames.clear()

    # CAS PARTICULIERS
    
    pretty_print("CasParticuliers/deleteFromPhone.pcapng")
    
    pretty_print("CasParticuliers/Linux_Wifi_pdfTo&OffDrive.pcapng")
    
    pretty_print("CasParticuliers/modifyFromPhone.pcapng")

    pretty_print("CasParticuliers/Linux_4G_PdfTo&OffDrive.pcapng")

    print("\nUnique domain names:")
    print(uniqueDomainNames)
    uniqueDomainNames.clear()

    # DELETE DE FICHIERS PCAPNG
    
    pretty_print("DeleteDeFichiers/deleteMultipleFiles.pcapng")
    
    pretty_print("DeleteDeFichiers/deleteMultipleFiles2.pcapng")
    
    pretty_print("DeleteDeFichiers/Phone_4G_ImageOffDrive.pcapng")

    pretty_print("DeleteDeFichiers/Linux_Wifi_pdfOffDrive1.pcapng")

    pretty_print("DeleteDeFichiers/Linux_4G_pdfOffDrive.pcapng")

    pretty_print("DeleteDeFichiers/Linux_4G_ImageOffDrive.pcapng")

    print("\nUnique domain names:")
    print(uniqueDomainNames)
    uniqueDomainNames.clear()

    # MODIF DE FICHIERS PCAPNG
    
    pretty_print("ModifDeFichiers/modifyFileOnDrive.pcapng")
    
    pretty_print("ModifDeFichiers/modifyFileOnDrive2.pcapng")
    
    pretty_print("ModifDeFichiers/modifyFileOnDrive3.pcapng")

    print("\nUnique domain names:")
    print(uniqueDomainNames)
    uniqueDomainNames.clear()

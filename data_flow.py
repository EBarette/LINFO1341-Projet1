import pyshark
import nest_asyncio
nest_asyncio.apply()

def process_data_flow(filename):
    cap = pyshark.FileCapture("WiresharkCapture/" + filename)
    data_flow = 0
    first_payload_time = None
    last_payload_time = None
    for pkt in cap:
        if (hasattr(pkt, "udp") and hasattr(pkt.udp, "payload")):
            if first_payload_time is None:
                first_payload_time = float(pkt.sniff_timestamp)
            last_payload_time = float(pkt.sniff_timestamp)
            data_flow += len(pkt.udp.payload)
        elif (hasattr(pkt, "tcp") and hasattr(pkt.tcp, "payload")):
            if first_payload_time is None:
                first_payload_time = float(pkt.sniff_timestamp)
            last_payload_time = float(pkt.sniff_timestamp)
            data_flow += len(pkt.tcp.payload)
    return data_flow / (last_payload_time - first_payload_time)

def pretty_print(filename):
    print(filename)
    data = process_data_flow(filename)
    print("Data flow: " + str(data) + "\n")
    return data


if __name__ == "__main__":

    # AJOUT DE FICHIER PCAPNG
    moyenne = 0
    
    moyenne += pretty_print("AjoutDeFichiers/imgToDrive.pcapng")
    
    moyenne += pretty_print("AjoutDeFichiers/imgToDrive2.pcapng")
    
    moyenne += pretty_print("AjoutDeFichiers/imgToDrive3.pcapng")
    
    moyenne += pretty_print("AjoutDeFichiers/imgToDrive4.pcapng")
    
    moyenne += pretty_print("AjoutDeFichiers/imgToDrive5.pcapng")
    
    moyenne += pretty_print("AjoutDeFichiers/Linux_WifiUCL_pdfToDrive.pcapng")
    
    moyenne += pretty_print("AjoutDeFichiers/Linux_WifiUCL_pdfToDrive2.pcapng")
    
    moyenne += pretty_print("AjoutDeFichiers/Linux_Wifi_pdfToDrive3.pcapng")

    moyenne += pretty_print("AjoutDeFichiers/multipleFilesToDrive.pcapng")
    
    moyenne += pretty_print("AjoutDeFichiers/multipleFilesToDrive2.pcapng")
    
    moyenne += pretty_print("AjoutDeFichiers/multipleFilesToDrive3.pcapng")

    moyenne += pretty_print("AjoutDeFichiers/Linux_4G_ImageToDrive.pcapng")

    moyenne += pretty_print("AjoutDeFichiers/Linux_4G_PdfToDrive.pcapng")

    print("Moyenne AjoutDeFichiers: " + str(moyenne/13) + "\n")
    moyenne = 0

    # CAS PARTICULIERS
    
    moyenne += pretty_print("CasParticuliers/deleteFromPhone.pcapng")
    
    moyenne += pretty_print("CasParticuliers/Linux_Wifi_pdfTo&OffDrive.pcapng")
    
    moyenne += pretty_print("CasParticuliers/modifyFromPhone.pcapng")

    moyenne += pretty_print("CasParticuliers/Linux_4G_PdfTo&OffDrive.pcapng")

    print("Moyenne CasParticuliers: " + str(moyenne/4) + "\n")
    moyenne = 0

    # DELETE DE FICHIERS PCAPNG
    
    moyenne += pretty_print("DeleteDeFichiers/deleteMultipleFiles.pcapng")
    
    moyenne += pretty_print("DeleteDeFichiers/deleteMultipleFiles2.pcapng")
    
    moyenne += pretty_print("DeleteDeFichiers/Phone_4G_ImageOffDrive.pcapng")

    moyenne += pretty_print("DeleteDeFichiers/Linux_Wifi_pdfOffDrive1.pcapng")

    moyenne += pretty_print("DeleteDeFichiers/Linux_4G_pdfOffDrive.pcapng")

    moyenne += pretty_print("DeleteDeFichiers/Linux_4G_ImageOffDrive.pcapng")

    print("Moyenne DeleteDeFichiers: " + str(moyenne/6) + "\n")
    moyenne = 0

    # MODIF DE FICHIERS PCAPNG
    
    moyenne += pretty_print("ModifDeFichiers/modifyFileOnDrive.pcapng")
    
    moyenne += pretty_print("ModifDeFichiers/modifyFileOnDrive2.pcapng")
    
    moyenne += pretty_print("ModifDeFichiers/modifyFileOnDrive3.pcapng")

    print("Moyenne ModifDeFichiers: " + str(moyenne/3) + "\n")
    moyenne = 0
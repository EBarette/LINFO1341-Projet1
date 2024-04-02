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
    print("Data flow: " + str(process_data_flow(filename)) + "\n")

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

    # CAS PARTICULIERS
    
    pretty_print("CasParticuliers/deleteFromPhone.pcapng")
    
    pretty_print("CasParticuliers/Linux_Wifi_pdfTo&OffDrive.pcapng")
    
    pretty_print("CasParticuliers/modifyFromPhone.pcapng")

    pretty_print("CasParticuliers/Linux_4G_PdfTo&OffDrive.pcapng")

    # DELETE DE FICHIERS PCAPNG
    
    pretty_print("DeleteDeFichiers/deleteMultipleFiles.pcapng")
    
    pretty_print("DeleteDeFichiers/deleteMultipleFiles2.pcapng")
    
    pretty_print("DeleteDeFichiers/Phone_4G_ImageOffDrive.pcapng")

    pretty_print("DeleteDeFichiers/Linux_Wifi_pdfOffDrive1.pcapng")

    pretty_print("DeleteDeFichiers/Linux_4G_pdfOffDrive.pcapng")

    pretty_print("DeleteDeFichiers/Linux_4G_ImageOffDrive.pcapng")

    # MODIF DE FICHIERS PCAPNG
    
    pretty_print("ModifDeFichiers/modifyFileOnDrive.pcapng")
    
    pretty_print("ModifDeFichiers/modifyFileOnDrive2.pcapng")
    
    pretty_print("ModifDeFichiers/modifyFileOnDrive3.pcapng")
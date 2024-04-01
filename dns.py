import pyshark
import csv
import nest_asyncio
nest_asyncio.apply()

# uniqueDomainNames = set()

def process_domain_name(filename):
    cap = pyshark.FileCapture("WiresharkCapture/" + filename)

    pkt_time = 0.0
    previous_time = float(cap[0].sniff_timestamp)
    list = []
    for pkt in cap:
        if pkt.highest_layer == "DNS" and pkt.dns.qry_name:
            pkt_time = float(pkt.sniff_timestamp)
            list.append([pkt.dns.qry_name, pkt.dns.qry_type, pkt.dns.count_add_rr, round(pkt_time - previous_time, 3), pkt.number])
            previous_time = pkt_time
            # uniqueDomainNames.add(pkt.dns.qry_name)
    return list

def pretty_print(filename, output):
    output.writerow([" "])
    output.writerow(["File: " + filename])
    output.writerow([" "])
    for pkt in process_domain_name(filename):
        output.writerow(pkt)

if __name__ == "__main__":
    outputFile = open('output_dns.csv', 'w', newline='')
    output = csv.writer(outputFile)
    output.writerow(["Domain Name", "Query Type", "Add Records", "Delta Time", "Packet Number"])
    # AJOUT DE FICHIER PCAPNG
    
    pretty_print("AjoutDeFichiers/imgToDrive.pcapng", output)
    
    pretty_print("AjoutDeFichiers/imgToDrive2.pcapng", output)
    
    pretty_print("AjoutDeFichiers/imgToDrive3.pcapng", output)
    
    pretty_print("AjoutDeFichiers/imgToDrive4.pcapng", output)
    
    pretty_print("AjoutDeFichiers/imgToDrive5.pcapng", output)
    
    pretty_print("AjoutDeFichiers/Linux_WifiUCL_pdfToDrive.pcapng", output)
    
    pretty_print("AjoutDeFichiers/Linux_WifiUCL_pdfToDrive2.pcapng", output)
    
    pretty_print("AjoutDeFichiers/Linux_Wifi_pdfToDrive3.pcapng", output)

    pretty_print("AjoutDeFichiers/multipleFilesToDrive.pcapng", output)
    
    pretty_print("AjoutDeFichiers/multipleFilesToDrive2.pcapng", output)
    
    pretty_print("AjoutDeFichiers/multipleFilesToDrive3.pcapng", output)

    pretty_print("AjoutDeFichiers/Linux_4G_ImageToDrive.pcapng", output)

    pretty_print("AjoutDeFichiers/Linux_4G_PdfToDrive.pcapng", output)
        
    # print("\nUnique domain names:")
    # print(uniqueDomainNames)
    # uniqueDomainNames.clear()

    # CAS PARTICULIERS
    
    pretty_print("CasParticuliers/deleteFromPhone.pcapng", output)
    
    pretty_print("CasParticuliers/Linux_Wifi_pdfTo&OffDrive.pcapng", output)
    
    pretty_print("CasParticuliers/modifyFromPhone.pcapng", output)

    pretty_print("CasParticuliers/Linux_4G_PdfTo&OffDrive.pcapng", output)

    # print("\nUnique domain names:")
    # print(uniqueDomainNames)
    # uniqueDomainNames.clear()

    # DELETE DE FICHIERS PCAPNG
    
    pretty_print("DeleteDeFichiers/deleteMultipleFiles.pcapng", output)
    
    pretty_print("DeleteDeFichiers/deleteMultipleFiles2.pcapng", output)
    
    pretty_print("DeleteDeFichiers/Phone_4G_ImageOffDrive.pcapng", output)

    pretty_print("DeleteDeFichiers/Linux_Wifi_pdfOffDrive1.pcapng", output)

    pretty_print("DeleteDeFichiers/Linux_4G_pdfOffDrive.pcapng", output)

    pretty_print("DeleteDeFichiers/Linux_4G_ImageOffDrive.pcapng", output)

    # print("\nUnique domain names:")
    # print(uniqueDomainNames)
    # uniqueDomainNames.clear()

    # MODIF DE FICHIERS PCAPNG
    
    pretty_print("ModifDeFichiers/modifyFileOnDrive.pcapng", output)
    
    pretty_print("ModifDeFichiers/modifyFileOnDrive2.pcapng", output)
    
    pretty_print("ModifDeFichiers/modifyFileOnDrive3.pcapng", output)

    # print("\nUnique domain names:")
    # print(uniqueDomainNames)
    # uniqueDomainNames.clear()

    outputFile.close()
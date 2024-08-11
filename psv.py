import pyshark
from datetime import timedelta
import pandas as pd
import csv

#ethFieldNames = packNetworkAttack[0].eth.field_names
#ipFieldNames = packNetworkAttack[0].ip.field_names
#tcpFieldNames = packNetworkAttack[0].tcp.field_names
#modbusFieldNames = packNetworkAttack[5].modbus.field_names

#Função para converter as informaçoes do pacote pcap em uma matriz

def parsePcapToMatrix(pcap, untilLine):
    matrix = []
    for index, pack in enumerate(pcap):
        if index >= untilLine:
            break
        matrixNewLine = []
        try:
            matrixNewLine.append(pack.sniff_time + timedelta(hours = 3))
            matrixNewLine.append(pack.length)
            matrixNewLine.append(pack.ip.src)
            matrixNewLine.append(pack.ip.dst)
            matrixNewLine.append(pack.ip.proto)
            matrixNewLine.append(pack.ip.ttl)
            matrixNewLine.append(pack.tcp.srcport)
            matrixNewLine.append(pack.tcp.dstport)
            matrixNewLine.append(pack.tcp.window_size)
            matrixNewLine.append(pack.tcp.seq_raw)
            matrixNewLine.append(pack.tcp.flags_res)
            matrixNewLine.append(pack.tcp.flags_ae)
            matrixNewLine.append(pack.tcp.flags_cwr)
            matrixNewLine.append(pack.tcp.flags_ece)
            matrixNewLine.append(pack.tcp.flags_urg)
            matrixNewLine.append(pack.tcp.flags_ack)
            matrixNewLine.append(pack.tcp.flags_push)
            matrixNewLine.append(pack.tcp.flags_reset)
            matrixNewLine.append(pack.tcp.flags_syn)
        except AttributeError:
            continue
        matrix.append(matrixNewLine)
    return matrix

#Carrega o pacote pcap da Wide Network com os attacks
pcapWideNetwork = pyshark.FileCapture('csv/network-wide-normal-0.pcap')

#Converte o arquivo pcap para uma matriz
matrixWideNetwork = parsePcapToMatrix(pcapWideNetwork, 90)
#92500

#Carrega os pacotes que sofreram ataques em um dataframe do pandas
dfAttacks = pd.read_csv('csv/02-01-2023-1.csv')
    
#Converte os objetos datetime da matriz matrixWideNetwork para strings no formato "%Y-%m-%d %H:%M:%S.%f")[:-3]
for pack in matrixWideNetwork:
    pack[0] = pack[0].strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

#Adiciona aos pacotes da matriz se os mesmo tiveram ataque, e o tipo de ataque
i = 0

for pack in matrixWideNetwork:
    if dfAttacks['Timestamp'].iloc[i] == pack[0]:
        pack.append(True)
        pack.append(dfAttacks['Attack'].iloc[i])
        i = i + 1
    else:
        pack.append(False)
        pack.append('N/A')
'''
# Salvar a matriz em um arquivo CSV
with open('wideNetwork.csv', mode='w', newline='') as file:
    writer = csv.writer(file, delimiter=',')
    writer.writerows(matrixWideNetwork)
'''   
'''
if dfAttacks['Timestamp'].iloc[2] == matrixWideNetwork[6993][0]:
    print(True)
'''
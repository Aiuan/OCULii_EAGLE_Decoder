import time

from oculii_np import OCULiiDecoderNetworkPackets
from oculii_db import OCULiiDecoderDataBin

def decode_network_packets():
    data_path = './data/20221209.pcap'
    output_path = './runs/test'

    odnp = OCULiiDecoderNetworkPackets(pcap_path=data_path, output_path=output_path, pcd_file_type='pcd')

    t_last = time.time()
    while 1:
        odnp.decode()
        t = time.time()
        print('    {:.2f} s'.format(t - t_last))
        print('='*100)
        t_last = time.time()

def decode_data_bin():
    data_path = './data/20221205_repoweron/radar_1/data.bin'
    output_path = './runs/test'

    oddb = OCULiiDecoderDataBin(bin_path=data_path, output_path=output_path, pcd_file_type='pcd')

    t_last = time.time()
    while 1:
        oddb.decode()
        t = time.time()
        print('    {:.2f} s'.format(t - t_last))
        print('=' * 100)
        t_last = time.time()

if __name__ == '__main__':
    decode_network_packets()
    # decode_data_bin()


import os
import time
import pandas as pd
import numpy as np
import dpkt
import socket

from utils import *

def read_uint8(data, idx):
  return data[idx]

def read_sint8(data, idx):
  val = read_uint8(data, idx)
  return val-256 if val > 127 else val

def read_uint16(data, idx):
  return data[idx] + data[idx+1]*256

def read_sint16(data, idx):
  val = read_uint16(data, idx)
  return val-2**16 if val > 2**15-1 else val

def read_uint32(data, idx):
  return data[idx] + data[idx+1]*256 + data[idx+2]*256*256 + data[idx+3]*256*256*256


class PtpTriggerPacket(object):
  @staticmethod
  def is_PtpTriggerPacket(bytes_stream):
    if len(bytes_stream) == 72:
      eth = dpkt.ethernet.Ethernet(bytes_stream)
      cmd = eth.data.data.data
      if cmd[0] == 10:
        return True
      else:
        return False
    else:
      return False

class HandshakePacket(object):
  def __init__(self, idx_packet, timestamp_packet_receive, bytes_stream):
    self.idx_packet = idx_packet
    assert len(bytes_stream) == 42 + 24
    self.timestamp_packet_receive = timestamp_packet_receive
    eth = dpkt.ethernet.Ethernet(bytes_stream)
    self.src = socket.inet_ntoa(eth.data.src)
    self.dst = socket.inet_ntoa(eth.data.dst)
    self.sport = eth.data.data.sport
    self.dport = eth.data.data.dport
    self.magic = eth.data.data.data[:8]
    self.frame_data_length = read_uint32(eth.data.data.data, 8)
    self.timestamp_nanoseconds = read_uint32(eth.data.data.data, 12)
    self.timestamp_seconds = read_uint32(eth.data.data.data, 16)
    self.flag = read_uint8(eth.data.data.data, 20)

    print(
      '[{:.6f}] idx_packet={}, HandshakePacket, src: {}:{} --> dst:{}:{}'.format(
        self.timestamp_packet_receive, self.idx_packet, self.src, self.sport, self.dst, self.dport
      )
    )
    self.timestamp_trigger = self.timestamp_seconds - 37 + self.timestamp_nanoseconds / 1e9

    # local time
    timestamp_packet_receive_local_time_str = time.strftime(
      '%Y-%m-%d %H:%M:%S', time.localtime(self.timestamp_packet_receive)
    ) + '.{:>03d}'.format(round((self.timestamp_packet_receive - int(self.timestamp_packet_receive)) * 1e3))
    print('    timestamp_receive: {:.9f} ({})'.format(self.timestamp_packet_receive,
                                                      timestamp_packet_receive_local_time_str))

    timestamp_trigger_local_time_str = time.strftime(
      '%Y-%m-%d %H:%M:%S', time.localtime(self.timestamp_trigger)
    )+'.{:>03d}'.format(round((self.timestamp_trigger - int(self.timestamp_trigger))*1e3))
    print('    timestamp_trigger: {:.9f} ({})'.format(self.timestamp_trigger, timestamp_trigger_local_time_str))

    delay = self.timestamp_packet_receive - self.timestamp_trigger
    assert delay >= 0
    print('    delay:{:.9f} s'.format(delay))

    # whether ptp sync?
    self.is_ptp_sync = (np.abs(delay) <= 10) and (self.flag > 0) and (self.flag < 120)

  @staticmethod
  def is_HandshakePacket(bytes_stream):
    if len(bytes_stream) == 66:
      eth = dpkt.ethernet.Ethernet(bytes_stream)
      magic = eth.data.data.data[:8]
      if magic == b'\x01\t\x08\t\x01\x00\x02\x02':
        return True
      else:
        return False
    else:
      return False

class BodyPacket_divided(object):
  def __init__(self, idx_packet, timestamp_packet_receive, bytes_stream):
    self.idx_packet = idx_packet
    assert len(bytes_stream) <= 42 + 256
    self.timestamp_packet_receive = timestamp_packet_receive
    eth = dpkt.ethernet.Ethernet(bytes_stream)
    self.src = socket.inet_ntoa(eth.data.src)
    self.dst = socket.inet_ntoa(eth.data.dst)
    self.sport = eth.data.data.sport
    self.dport = eth.data.data.dport
    self.data = eth.data.data.data

    print(
      '[{:.6f}] idx_packet={}, BodyPacket_divided[{}], src: {}:{} --> dst:{}:{}'.format(
        self.timestamp_packet_receive, self.idx_packet, len(self.data), self.src, self.sport, self.dst, self.dport
      )
    )

class BodyPacket(object):
  def __init__(self, pkgs):
    self.idx_packets = []
    self.timestamp_packet_receives = []
    self.srcs = []
    self.dsts = []
    self.sports = []
    self.dports = []
    self.data = bytes()
    for pkg in pkgs:
      self.idx_packets.append(pkg.idx_packet)
      self.timestamp_packet_receives.append(pkg.timestamp_packet_receive)
      self.srcs.append(pkg.src)
      self.dsts.append(pkg.dst)
      self.sports.append(pkg.sport)
      self.dports.append(pkg.dport)
      self.data += pkg.data

    self.header_block = HeaderBlock(self.data[:48])
    print('    frame_number: {}'.format(self.header_block.frame_number))

    self.footer_block = FooterBlock(self.data[-32:])

    print('    number_of_detection: {}'.format(self.header_block.number_of_detection))
    if self.header_block.number_of_detection > 0:
      self.detection_blocks = [DetectionBlock(self.data[48+8*i:48+8*(i+1)]) for i in range(self.header_block.number_of_detection)]

      self.range_accuracy = np.array([self.header_block.range_accuracy_idx_0, self.footer_block.range_accuracy_idx_1])
      self.doppler_accuracy = np.array([self.header_block.doppler_accuracy_idx_0, self.footer_block.doppler_accuracy_idx_1])
      self.azimuth_accuracy = np.array([self.header_block.azimuth_accuracy_idx_0, self.footer_block.azimuth_accuracy_idx_1])
      self.elevation_accuracy = np.array([self.header_block.elevation_accuracy_idx_0, self.footer_block.elevation_accuracy_idx_1])
      self.pts = self.calculate_pts()

    print('    number_of_tracks: {}'.format(self.header_block.number_of_tracks))
    if self.header_block.number_of_tracks > 0:
      self.tracker_blocks = [
        TrackerBlock(self.data[48+8*self.header_block.number_of_detection+32*i:48+8*self.header_block.number_of_detection+32*(i+1)])
        for i in range(self.header_block.number_of_tracks)
      ]

      self.tracks = self.calculate_tracks()


  def calculate_pts(self):
    pts = []
    for detection_block in self.detection_blocks:
      pt = {
        'flag': detection_block.flag,
        'range_index': detection_block.range_index,
        'doppler_index': detection_block.doppler_index,
        'azimuth_index': detection_block.azimuth_index,
        'elevation_index': detection_block.beta_index,
        'snr': detection_block.power_value,
      }
      pts.append(pt)
    pts = pd.DataFrame(pts)
    pts['range'] = pts['range_index'].values * self.range_accuracy[pts['flag'].values]
    pts['doppler'] = pts['doppler_index'].values * self.doppler_accuracy[pts['flag'].values]
    pts['azimuth'] = pts['azimuth_index'].values * self.azimuth_accuracy[pts['flag'].values]
    pts['elevation'] = pts['elevation_index'].values * self.elevation_accuracy[pts['flag'].values]

    pts['x'] = pts['range'].values * np.cos(pts['elevation'].values / 180 * np.pi) * np.sin(pts['azimuth'].values / 180 * np.pi)
    pts['y'] = pts['range'].values * np.sin(pts['elevation'].values / 180 * np.pi)
    pts['z'] = pts['range'].values * np.cos(pts['elevation'].values / 180 * np.pi) * np.cos(pts['azimuth'].values / 180 * np.pi)

    return pts

  def calculate_tracks(self):
    tracks = []
    for tracker_block in self.tracker_blocks:
      track = {
        'track_id': tracker_block.track_id,
        'XPos': tracker_block.XPos,
        'YPos': tracker_block.YPos,
        'ZPos': tracker_block.ZPos,
        'XDot': tracker_block.XDot,
        'YDot': tracker_block.YDot,
        'ZDot': tracker_block.ZDot,
        'flag': tracker_block.flag,
        'Class': tracker_block.Class,
        'Conf': tracker_block.Conf
      }
      tracks.append(track)
    tracks = pd.DataFrame(tracks)
    return tracks

class HeaderBlock(object):
  def __init__(self, bytes_stream):
    assert len(bytes_stream) == 48
    self.magic = bytes_stream[:8]
    assert self.magic == b'\x02\x01\x04\x03\x06\x05\x08\x07'
    self.frame_number = read_uint32(bytes_stream, 8)
    self.version_number = read_uint32(bytes_stream, 12)
    self.number_of_detection = read_uint16(bytes_stream, 16)
    self.number_of_tracks = read_uint16(bytes_stream, 18)
    self.host_speed = read_sint16(bytes_stream, 20) * 1.0 / 100  # m/s
    self.host_angle = read_sint16(bytes_stream, 22) * 1.0 / 100  # degrees
    self.range_accuracy_idx_0 = read_uint16(bytes_stream, 32) * 1.0 / 10000  # m
    self.doppler_accuracy_idx_0 = read_uint16(bytes_stream, 34) * 1.0 / 10000  # m/s
    self.azimuth_accuracy_idx_0 = read_uint16(bytes_stream, 36) * 1.0 / 10000  # degree
    self.elevation_accuracy_idx_0 = read_uint16(bytes_stream, 38) * 1.0 / 10000  # degree
    self.dsp_workload = read_uint8(bytes_stream, 40)  # %
    self.arm_workload = read_uint8(bytes_stream, 41)  # %

class FooterBlock(object):
  def __init__(self, bytes_stream):
    assert len(bytes_stream) == 32
    self.range_accuracy_idx_1 = read_uint16(bytes_stream, 8) * 1.0 / 10000  # m
    self.doppler_accuracy_idx_1 = read_uint16(bytes_stream, 10) * 1.0 / 10000  # m/s
    self.azimuth_accuracy_idx_1 = read_uint16(bytes_stream, 12) * 1.0 / 10000  # degree
    self.elevation_accuracy_idx_1 = read_uint16(bytes_stream, 14) * 1.0 / 10000  # degree

class DetectionBlock(object):
  def __init__(self, bytes_stream):
    assert len(bytes_stream) == 8
    # reversal
    bytes_stream = self.bytes_stream_reverse(bytes_stream)

    self.denoise_flag = 1 if bytes_stream[0] & int('10000000', 2) else 0
    self.flag = 1 if bytes_stream[0] & int('01000000', 2) else 0
    self.doppler_correction_flag = 1 if bytes_stream[0] & int('00100000', 2) else 0
    self.dot_flags = bytes_stream[0] >> 3

    self.power_value = (bytes_stream[1] * 256 + bytes_stream[2]) * 1.0 / 100

    beta_bits = ((bytes_stream[3] & int('11111111', 2)) << 2) | ((bytes_stream[4] & int('11000000', 2)) >> 6)
    self.beta_index = self.bits2index(beta_bits)
    azimuth_bits = ((bytes_stream[4] & int('00111111', 2)) << 4) | ((bytes_stream[5] & int('11110000', 2)) >> 4)
    self.azimuth_index = self.bits2index(azimuth_bits)
    doppler_bits = ((bytes_stream[5] & int('00001111', 2)) << 6) | ((bytes_stream[6] & int('11111100', 2)) >> 2)
    self.doppler_index = self.bits2index(doppler_bits)
    range_bits = ((bytes_stream[6] & int('00000011', 2)) << 8) | ((bytes_stream[7] & int('11111111', 2)) >> 0)
    self.range_index = range_bits

  def bytes_stream_reverse(self, bytes_stream):
    res = bytes()
    for i in range(len(bytes_stream)):
      res += bytes_stream[len(bytes_stream) - 1 - i].to_bytes(1, 'little')
    return res

  def bits2index(self, bits):
    val = (bits & int('0111111111', 2)) - (bits & int('1000000000', 2))
    return val

class TrackerBlock(object):
  def __init__(self, bytes_stream):
    assert len(bytes_stream) == 32
    self.track_id = read_uint32(bytes_stream, 0)
    self.XPos = read_sint16(bytes_stream, 4) * 1.0 / 100  # m
    self.YPos = read_sint16(bytes_stream, 6) * 1.0 / 100  # m
    self.ZPos = read_sint16(bytes_stream, 8) * 1.0 / 100  # m
    self.XDot = read_sint16(bytes_stream, 10) * 1.0 / 100  # m/s
    self.YDot = read_sint16(bytes_stream, 12) * 1.0 / 100  # m/s
    self.ZDot = read_sint16(bytes_stream, 14) * 1.0 / 100  # m/s
    self.flag = read_uint16(bytes_stream, 22)
    self.Class = read_uint16(bytes_stream, 24)
    self.Conf = read_uint16(bytes_stream, 26)

    classnames = [
      'Unknown Class',
      'Pedestrian',
      'Motorcycle/Bike',
      'Vehicle and SUV',
      'Bus and Truck',
      'Background'
    ]
    self.classname = classnames[self.Class]

class OCULiiDecoderNetworkPackets(object):
    def __init__(self, pcap_path, output_path, pcd_file_type='pcd'):
      print('=' * 100)
      print('Initialization\n')

      assert pcap_path.split('.')[-1] == 'pcap'
      self.pcap_path = pcap_path
      print('Reading data from: {}\n'.format(self.pcap_path))

      self.output_path = output_path
      if not os.path.exists(self.output_path):
        os.makedirs(self.output_path)
        print('Create output folder: {}'.format(self.output_path))

      self.pcd_file_type = pcd_file_type

      self.f = open(self.pcap_path, 'rb')
      self.reader = enumerate(dpkt.pcap.Reader(self.f))

      self.after_ptp_trigger = False
      self.init_for_next_frame()

    def __del__(self):
      self.f.close()

    def init_for_next_frame(self):
      self.packets_in_frame = None

    def decode(self):
      # find ptp trigger packet
      while not self.after_ptp_trigger:
        idx_packet, ts, pkg = self.next_udp_packet()
        if PtpTriggerPacket.is_PtpTriggerPacket(pkg):
          log_BLUE('[{:.6f}] idx_packet={}, ptp_trigger_packet transfer'.format(ts, idx_packet))
          idx_packet, ts, pkg = self.next_udp_packet()
          if PtpTriggerPacket.is_PtpTriggerPacket(pkg):
            log_BLUE('[{:.6f}] idx_packet={}, ptp_trigger_packet confirm'.format(ts, idx_packet))
            self.after_ptp_trigger = True
            continue
        print('[{:.6f}] idx_packet={}, before ptp_trigger_packet, skip'.format(ts, idx_packet))

      # decode after ptp trigger packet
      while self.after_ptp_trigger:
        self.next_frame_packets()
        if self.packets_in_frame[0].is_ptp_sync:
          # generate pointcloud frame
          self.generate_frame()
        else:
          # skip
          log_YELLOW('    not ptp sync')

        # new frame init
        self.init_for_next_frame()

    def next_frame_packets(self):
      print('=' * 100)
      while True:
        idx_packet, ts, pkg = self.next_udp_packet()
        if HandshakePacket.is_HandshakePacket(pkg):
          break
        else:
          print('[{:.6f}] idx_packet={}, not handshake packet(first packet in frame), skip'.format(ts, idx_packet))
      handshake_pkg = HandshakePacket(idx_packet, ts, pkg)
      assert self.packets_in_frame is None
      self.packets_in_frame = []
      self.packets_in_frame.append(handshake_pkg)

      cnt_length = 0
      while cnt_length < handshake_pkg.frame_data_length:
        idx_packet, ts, pkg = self.next_udp_packet()
        body_pkg_div = BodyPacket_divided(idx_packet, ts, pkg)
        cnt_length += len(body_pkg_div.data)
        self.packets_in_frame.append(body_pkg_div)
      assert cnt_length == handshake_pkg.frame_data_length

    def next_udp_packet(self):
      while True:
        try:
          idx_packet, (ts, pkg) = next(self.reader)
          eth = dpkt.ethernet.Ethernet(pkg)
          # check whether ip packet: to consider only ip packets
          if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            print('[{:.6f}] idx_packet={}, not ip packet, skip'.format(ts, idx_packet))
            continue
          # check whether udp packet: to consider only udp packets
          if eth.data.p == dpkt.ip.IP_PROTO_UDP:
            return idx_packet, ts, pkg
          else:
            print('[{:.6f}] idx_packet={}, not udp packet, skip'.format(ts, idx_packet))
            continue
        except Exception as e:
          log_YELLOW(repr(e))
          print('Read all packets done')
          exit()

    def generate_frame(self):
      handshake_pkg = self.packets_in_frame[0]
      body_pkg = BodyPacket(self.packets_in_frame[1:])

      # name the file according to the pts' unix_timestamp at 0 degree
      pcd_filename = '{:.9f}.{}'.format(handshake_pkg.timestamp_trigger, self.pcd_file_type)
      pcd_path = os.path.join(self.output_path, pcd_filename)

      # x y z doppler snr
      if self.pcd_file_type == 'npz':
        np.savez(
          pcd_path,
          x=body_pkg.pts['x'].values.astype('float32'),
          y=body_pkg.pts['y'].values.astype('float32'),
          z=body_pkg.pts['z'].values.astype('float32'),
          doppler=body_pkg.pts['doppler'].values.astype('float32'),
          snr=body_pkg.pts['snr'].values.astype('float32')
        )
      elif self.pcd_file_type == 'pcd':
        pcd = pd.DataFrame({
          'x': body_pkg.pts['x'].values.astype('float32'),
          'y': body_pkg.pts['y'].values.astype('float32'),
          'z': body_pkg.pts['z'].values.astype('float32'),
          'doppler': body_pkg.pts['doppler'].values.astype('float32'),
          'snr': body_pkg.pts['snr'].values.astype('float32'),
        })

        pcd.to_csv(pcd_path, sep=' ', index=False, header=False)
        with open(pcd_path, 'r') as f_pcd:
          lines = f_pcd.readlines()

        with open(pcd_path, 'w') as f_pcd:
          f_pcd.write('VERSION .7\n')
          f_pcd.write('FIELDS')
          for col in pcd.columns.values:
            f_pcd.write(' {}'.format(col))
          f_pcd.write('\n')
          f_pcd.write('SIZE 4 4 4 4 4\n')
          f_pcd.write('TYPE F F F F F\n')
          f_pcd.write('COUNT 1 1 1 1 1\n')
          f_pcd.write('WIDTH {}\n'.format(len(pcd)))
          f_pcd.write('HEIGHT 1\n')
          f_pcd.write('VIEWPOINT 0 0 0 1 0 0 0\n')
          f_pcd.write('POINTS {}\n'.format(len(pcd)))
          f_pcd.write('DATA ascii\n')
          f_pcd.writelines(lines)

      log_GREEN('    Generate {},save to {}'.format(pcd_filename, pcd_path))




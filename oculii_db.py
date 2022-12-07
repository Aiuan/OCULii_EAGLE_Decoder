import os
import time

import pandas as pd
import numpy as np

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


class HeaderBlock(object):
  def __init__(self, bytes_stream):
    assert len(bytes_stream) == HeaderBlock.length
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

  @staticmethod
  def is_HeaderBlock(bytes_stream):
      if len(bytes_stream) == HeaderBlock.length:
          magic = bytes_stream[:8]
          if magic == b'\x02\x01\x04\x03\x06\x05\x08\x07':
              return True
          else:
              return False
      else:
          return False

  length = 48

class DetectionBlock(object):
  def __init__(self, bytes_stream):
    assert len(bytes_stream) == DetectionBlock.length
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

  length = 8

class TrackerBlock(object):
  def __init__(self, bytes_stream):
    assert len(bytes_stream) == TrackerBlock.length
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

  length = 32

class FooterBlock(object):
  def __init__(self, bytes_stream):
    assert len(bytes_stream) == FooterBlock.length
    self.range_accuracy_idx_1 = read_uint16(bytes_stream, 8) * 1.0 / 10000  # m
    self.doppler_accuracy_idx_1 = read_uint16(bytes_stream, 10) * 1.0 / 10000  # m/s
    self.azimuth_accuracy_idx_1 = read_uint16(bytes_stream, 12) * 1.0 / 10000  # degree
    self.elevation_accuracy_idx_1 = read_uint16(bytes_stream, 14) * 1.0 / 10000  # degree

  length = 32

class OCULiiDecoderDataBin(object):
    def __init__(self, bin_path, output_path, pcd_file_type='pcd'):
        print('=' * 100)
        print('Initialization\n')

        assert bin_path.split('.')[-1] == 'bin'
        self.bin_path = bin_path
        print('Reading data from: {}\n'.format(self.bin_path))

        self.output_path = output_path
        if not os.path.exists(self.output_path):
            os.makedirs(self.output_path)
            print('Create output folder: {}'.format(self.output_path))

        self.pcd_file_type = pcd_file_type

        self.f = open(self.bin_path, 'rb')

        self.init_for_next()

    def __del__(self):
      self.f.close()

    def init_for_next(self):
        self.header_block = None
        self.detection_blocks = None
        self.tracker_blocks = None
        self.footer_block = None
        self.pts = None
        self.tracks = None

    def decode(self):
        while True:
            try:
                tmp = self.f.read(HeaderBlock.length)
                if HeaderBlock.is_HeaderBlock(tmp):
                    print('='*100)
                    # header block
                    self.header_block = HeaderBlock(tmp)
                    print('frame_number: {}'.format(self.header_block.frame_number))
                    # detection blocks
                    print('number_of_detection: {}'.format(self.header_block.number_of_detection))
                    self.detection_blocks = []
                    for i in range(self.header_block.number_of_detection):
                        self.detection_blocks.append(
                            DetectionBlock(self.f.read(DetectionBlock.length))
                        )
                    # track blocks
                    print('number_of_tracks: {}'.format(self.header_block.number_of_tracks))
                    self.tracker_blocks = []
                    for i in range(self.header_block.number_of_tracks):
                        self.tracker_blocks.append(
                            TrackerBlock(self.f.read(TrackerBlock.length))
                        )
                    # footer block
                    self.footer_block = FooterBlock(self.f.read(FooterBlock.length))

                    # calculate pts tracks
                    self.pts = self.calculate_pts()
                    self.tracks = self.calculate_tracks()

                    self.generate_frame()
                    self.init_for_next()

            except Exception as e:
                log_YELLOW(repr(e))
                print('Read all packets done')
                exit()

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

        range_accuracy = np.array([self.header_block.range_accuracy_idx_0, self.footer_block.range_accuracy_idx_1])
        doppler_accuracy = np.array(
            [self.header_block.doppler_accuracy_idx_0, self.footer_block.doppler_accuracy_idx_1])
        azimuth_accuracy = np.array(
            [self.header_block.azimuth_accuracy_idx_0, self.footer_block.azimuth_accuracy_idx_1])
        elevation_accuracy = np.array(
            [self.header_block.elevation_accuracy_idx_0, self.footer_block.elevation_accuracy_idx_1])

        pts['range'] = pts['range_index'].values * range_accuracy[pts['flag'].values]
        pts['doppler'] = pts['doppler_index'].values * doppler_accuracy[pts['flag'].values]
        pts['azimuth'] = pts['azimuth_index'].values * azimuth_accuracy[pts['flag'].values]
        pts['elevation'] = pts['elevation_index'].values * elevation_accuracy[pts['flag'].values]

        pts['x'] = pts['range'].values * np.cos(pts['elevation'].values / 180 * np.pi) * np.sin(
            pts['azimuth'].values / 180 * np.pi)
        pts['y'] = pts['range'].values * np.sin(pts['elevation'].values / 180 * np.pi)
        pts['z'] = pts['range'].values * np.cos(pts['elevation'].values / 180 * np.pi) * np.cos(
            pts['azimuth'].values / 180 * np.pi)

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

    def generate_frame(self):
      # name the file according to the pts' unix_timestamp at 0 degree
      pcd_filename = '{}.{}'.format(self.header_block.frame_number, self.pcd_file_type)
      pcd_path = os.path.join(self.output_path, pcd_filename)

      # x y z doppler snr
      if self.pcd_file_type == 'npz':
        np.savez(
          pcd_path,
          x=self.pts['x'].values.astype('float32'),
          y=self.pts['y'].values.astype('float32'),
          z=self.pts['z'].values.astype('float32'),
          doppler=self.pts['doppler'].values.astype('float32'),
          snr=self.pts['snr'].values.astype('float32')
        )
      elif self.pcd_file_type == 'pcd':
        pcd = pd.DataFrame({
          'x': self.pts['x'].values.astype('float32'),
          'y': self.pts['y'].values.astype('float32'),
          'z': self.pts['z'].values.astype('float32'),
          'doppler': self.pts['doppler'].values.astype('float32'),
          'snr': self.pts['snr'].values.astype('float32'),
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

      log_GREEN('Generate {},save to {}'.format(pcd_filename, pcd_path))
"""
    mstream - console based mumble (music) streamer
    Copyright (C) 2013  Jan Stancek <jan@stancek.eu>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
__author__ = "Jan Stancek <jan@stancek.eu>"

import os
import sys

import logging
import logging.handlers
import optparse
import platform
import random
import select
import signal
import socket
import struct
import subprocess
import thread
import threading
import time
import traceback

import ctypes
import curses
import ssl
import Queue

import Mumble_pb2

class Config:
    SCREEN_LOG_LEVEL = logging.INFO
    FILE_LOG_LEVEL = logging.INFO

    SAMPLE_RATE = 48000
    FRAME_SIZE = (SAMPLE_RATE / 100)
    FRAME_TIME = 1.0 / (SAMPLE_RATE / FRAME_SIZE)
    FRAMES_IN_PACKET = 4
    PACKETS_PER_SECOND = 100 / FRAMES_IN_PACKET
    SERVER_MAXBANDWIDTH = 64000 / 8
    ENCSIZE = 64
    SENT_BUFFER_FRAMES = FRAMES_IN_PACKET
    SENT_BUFFER_DURATION = FRAME_TIME * SENT_BUFFER_FRAMES
    VOLUME = 0.2
    # IP + UDP + Crypt + Data
    # (20 + 8 + 4 + (1 + 9) + FRAMES_IN_PACKET * (1 + enc_size_max))
    #   * (PACKETS_PER_SECOND) = SERVER_MAXBANDWIDTH
    # 42 + FRAMES_IN_PACKET * (1 + enc_size_max)
    #   = SERVER_MAXBANDWIDTH / PACKETS_PER_SECOND
    # FRAMES_IN_PACKET * (1 + enc_size_max))
    #   = SERVER_MAXBANDWIDTH / PACKETS_PER_SECOND - 42
    ENCSIZE_SERVERMAX = ((SERVER_MAXBANDWIDTH / PACKETS_PER_SECOND - 42) /
        FRAMES_IN_PACKET - 1)
    RAWDATA_TO_TIME = 1 / (2.0 * FRAME_SIZE / FRAME_TIME)
    PROGRESS_PERIOD = 30

MUMLE_MSG_DICT = {
    0:Mumble_pb2.Version,
    1:Mumble_pb2.UDPTunnel,
    2:Mumble_pb2.Authenticate,
    3:Mumble_pb2.Ping,
    4:Mumble_pb2.Reject,
    5:Mumble_pb2.ServerSync,
    6:Mumble_pb2.ChannelRemove,
    7:Mumble_pb2.ChannelState,
    8:Mumble_pb2.UserRemove,
    9:Mumble_pb2.UserState,
    10:Mumble_pb2.BanList,
    11:Mumble_pb2.TextMessage,
    12:Mumble_pb2.PermissionDenied,
    13:Mumble_pb2.ACL,
    14:Mumble_pb2.QueryUsers,
    15:Mumble_pb2.CryptSetup,
    16:Mumble_pb2.ContextActionModify,
    17:Mumble_pb2.ContextAction,
    18:Mumble_pb2.UserList,
    19:Mumble_pb2.VoiceTarget,
    20:Mumble_pb2.PermissionQuery,
    21:Mumble_pb2.CodecVersion,
    22:Mumble_pb2.UserStats,
    23:Mumble_pb2.RequestBlob,
    24:Mumble_pb2.ServerConfig,
    25:Mumble_pb2.SuggestConfig
    }

for k in MUMLE_MSG_DICT:
    MUMLE_MSG_DICT[k].msg_no = k

def clear_log_handlers(logger):
    for h in logger.handlers[:]:
        logger.removeHandler(h)

def setup_logging(log_storage):
    log_format = '%(asctime)20.25s %(levelname)5.5s' \
                 ':%(lineno)3s %(funcName)12.12s - %(message)s'

    logger = logging.getLogger('')
    clear_log_handlers(logger)

    formatter = logging.Formatter(log_format)

    my_handler = MyHandler(log_storage)
    my_handler.setFormatter(formatter)
    my_handler.setLevel(Config.SCREEN_LOG_LEVEL)
    logger.addHandler(my_handler)

    file_handler = logging.handlers.TimedRotatingFileHandler(
            'mstream.log', when='D', interval=1, backupCount=1)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    file_handler.setLevel(Config.FILE_LOG_LEVEL)
    logger.setLevel(logging.DEBUG)

def log_exception(exc, level=logging.CRITICAL):
    logging.log(level, 'type(exc), exc:')
    logging.log(level, str(type(exc)))
    logging.log(level, str(exc))

    exc_type, exc_value, exc_traceback = sys.exc_info()
    stack = traceback.format_exception(exc_type, exc_value, exc_traceback)

    logging.log(level, 'stack:')
    for line in stack:
        logging.log(level, line)

def send_fully(sock, msg):
    while len(msg) > 0:
        sent = sock.send(msg)
        if sent < 0:
            logging.error('sock error (send): %s', sent)
            return False
        msg = msg[sent:]
    return True

def read_fully(sock, size):
    msg = ''
    while len(msg) < size:
        received = sock.recv(size - len(msg))
        msg = msg + received
        if len(received) == 0:
            logging.error('sock error (read), connection closed')
            return None
    return msg

def get_dir_files(dirpath):
    filelist = []
    dirs_to_explore = [dirpath]

    while len(dirs_to_explore) > 0:
        current_dir = dirs_to_explore.pop()
        if os.path.exists(current_dir):
            try:
                dir_entries = os.listdir(current_dir)
                for entry in dir_entries:
                    entry = os.path.join(current_dir, entry)
                    if os.path.isdir(entry):
                        dirs_to_explore.append(entry)
                    elif os.path.isfile(entry):
                        filelist.append(entry)
            except OSError, e:
                log_exception(e)
    return filelist

def encode_varint(i):
    ret = ''

    if ((i & 0x8000000000000000) and (~i < 0x100000000)):
        # Signed number.
        i = ~i
        if (i <= 0x3):
            # Shortcase for -1 to -4
            ret = ret + chr(0xFC | i)
            return ret
        else:
            ret = ret + chr(0xF8)

    if i < 0x80:
        ret = chr(i)
    elif i < 0x4000:
        # Need top two bits clear
        ret = chr((i >> 8) | 0x80)
        ret = ret + chr(i & 0xFF)
    elif i < 0x200000:
        # Need top three bits clear
        ret = chr((i >> 16) | 0xC0)
        ret = ret + chr((i >> 8) & 0xFF)
        ret = ret + chr((i & 0xFF))
    elif i < 0x10000000:
        # Need top four bits clear
        ret = chr((i >> 24) | 0xE0)
        ret = ret + chr((i >> 16) & 0xFF)
        ret = ret + chr((i >> 8) & 0xFF)
        ret = ret + chr(i & 0xFF)
    elif i < 0x100000000:
        # It's a full 32-bit integer.
        ret = chr(0xF0)
        ret = ret + chr((i >> 24) & 0xFF)
        ret = ret + chr((i >> 16) & 0xFF)
        ret = ret + chr((i >> 8) & 0xFF)
        ret = ret + chr(i & 0xFF)
    else:
        # It's a 64-bit value.
        ret = chr(0xF4)
        ret = ret + chr((i >> 56) & 0xFF)
        ret = ret + chr((i >> 48) & 0xFF)
        ret = ret + chr((i >> 40) & 0xFF)
        ret = ret + chr((i >> 32) & 0xFF)
        ret = ret + chr((i >> 24) & 0xFF)
        ret = ret + chr((i >> 16) & 0xFF)
        ret = ret + chr((i >> 8) & 0xFF)
        ret = ret + chr(i & 0xFF)
    return ret


class LogStorage():
    def __init__(self, max_logs):
        self.content = []
        self.max_logs = max_logs
        self.changed = False

    def add_log(self, msg):
        # this should be thread-safe because MyHandler acquires lock
        self.content.append(msg)
        if len(self.content) > self.max_logs:
            self.content = self.content[-self.max_logs:]
        self.changed = True

    def check_changed(self):
        tmp = self.changed
        self.changed = False
        return tmp


class MyHandler(logging.Handler):
    def __init__(self, log_storage):
        super(MyHandler, self).__init__()
        self.log_storage = log_storage

    def emit(self, record):
        msg = self.format(record)
        self.log_storage.add_log(msg)


class Celt_Encoder:
    CELT_RESET_STATE = 8

    def __init__(self):
        self.celt_lib = ctypes.CDLL('./libcelt.so')

        INTP = ctypes.POINTER(ctypes.c_int)
        num = ctypes.c_int(0)
        addr = ctypes.addressof(num)
        err_ptr = ctypes.cast(addr, INTP)

        self.celt_lib.celt_mode_create.restype = ctypes.c_void_p
        self.mode = ctypes.c_void_p(
                self.celt_lib.celt_mode_create(
                    ctypes.c_int(Config.SAMPLE_RATE),
                    ctypes.c_int(Config.FRAME_SIZE),
                    err_ptr)
                )
        logging.debug('celt mode: %s err: %s', self.mode, num.value)

        self.celt_lib.celt_encoder_create.restype = ctypes.c_void_p
        self.encoder = ctypes.c_void_p(
            self.celt_lib.celt_encoder_create(self.mode, 1, err_ptr)
            )
        if self.encoder == None:
            raise Exception('failed to create celt encoder')
        logging.debug('celt encoder: %s, err: %s', self.encoder, num.value)

        ret = self.celt_lib.celt_encoder_ctl(self.encoder, 4, 1)
        logging.debug('celt prediction: %s', ret)


    def __del__(self):
        self.celt_lib.celt_encoder_destroy(self.encoder)
        self.celt_lib.celt_mode_destroy(self.mode)

    def reset_state(self):
        self.celt_lib.celt_encoder_ctl(self.encoder,
            self.celt_lib.CELT_RESET_STATE)

    def encode(self, data):
        if len(data) != 2 * Config.FRAME_SIZE:
            logging.error('expected %s bytes for celt encoder',
                2 * Config.FRAME_SIZE)
        out_buf = ctypes.create_string_buffer(Config.ENCSIZE)
        ret = self.celt_lib.celt_encode(self.encoder, data, None,
            ctypes.byref(out_buf), Config.ENCSIZE)
        out = out_buf.raw[:Config.ENCSIZE]
        return (ret, out)


class MumbleConnection(threading.Thread):
    PKT_FORMAT = '>HI'

    def __init__(self, host, channel, password):
        super(MumbleConnection, self).__init__()
        self.daemon = True
        self.running = True
        self.nick = 'mstream'
        self.host = host
        self.channel = channel
        self.password = password
        self.session = None
        self.channel_id = None

        sock = socket.socket(type=socket.SOCK_STREAM)
        self.sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1)
        self.sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

        self.sock_lock = thread.allocate_lock()
        self.cend = Celt_Encoder()
        self.packet_seq = 0
        self.connected = False
        self.in_channel = False
        self.user_channels = {}
        self.user_chan_lock = thread.allocate_lock()

    def safe_send_fully(self, data):
        ret = False
        try:
            self.sock_lock.acquire()
            ret = send_fully(self.sock, data)
        finally:
            self.sock_lock.release()
        return ret

    def safe_read_fully(self, size):
        data = None
        try:
            self.sock_lock.acquire()
            data = read_fully(self.sock, size)
        finally:
            self.sock_lock.release()
        return data

    def send_audio_packet(self, raw_frames_16bit):
        encoded_seq = encode_varint(self.packet_seq)
        udp_header = chr(0) + encoded_seq
        data = ''

        last_raw_frame = raw_frames_16bit[-1]
        for raw_frame in raw_frames_16bit:
            # bump seq number for each audio frame
            self.packet_seq = self.packet_seq + 1

            ret, enc_frame = self.cend.encode(raw_frame)
            if ret != Config.ENCSIZE:
                logging.error('unexpected encoded data length: %s', ret)

            audio_len = ret
            if raw_frame == last_raw_frame:
                audio_header = chr(audio_len)
            else:
                audio_header = chr(audio_len + 0x80)
            data = data + audio_header + enc_frame

        udp_data = udp_header + data
        length = len(udp_data)
        udp_packet = (struct.pack(MumbleConnection.PKT_FORMAT, 1, length)
            + udp_data)
        if not self.safe_send_fully(udp_packet):
            raise Exception('failed sending udp_packet')

    def send_audio_data(self, rawdata_16bit):
        # split to frames
        raw_frames = []
        while rawdata_16bit:
            frame_bytes = min(2 * Config.FRAME_SIZE, len(rawdata_16bit))
            frame_data = rawdata_16bit[:frame_bytes]

            # pad shorter frames
            while len(frame_data) < 2 * Config.FRAME_SIZE:
                frame_data = frame_data + chr(0)
            raw_frames.append(frame_data)
            rawdata_16bit = rawdata_16bit[frame_bytes:]

        # send frames grouped by number of FRAMES_IN_PACKET
        while raw_frames:
            frames_in_next_packet = min(Config.FRAMES_IN_PACKET,
                len(raw_frames))
            raw_frames_next_packet = raw_frames[:frames_in_next_packet]
            self.send_audio_packet(raw_frames_next_packet)
            raw_frames = raw_frames[frames_in_next_packet:]

    def pb_msg_to_mumble_packet(self, pb_msg):
        msgtype = pb_msg.msg_no
        msg = pb_msg.SerializeToString()
        length = len(msg)
        return struct.pack(MumbleConnection.PKT_FORMAT, msgtype, length) + msg

    def connect(self):
        self.sock.connect(self.host)

        pb_ver = Mumble_pb2.Version()
        pb_ver.release = '1.2.0'
        pb_ver.version = 66048
        pb_ver.os = platform.system()
        pb_ver.os_version = 'mstream-0.1'

        pb_auth = Mumble_pb2.Authenticate()
        pb_auth.username = self.nick
        if self.password:
            pb_auth.password = self.password
        pb_auth.celt_versions.append(-2147483637)

        ver_packet = self.pb_msg_to_mumble_packet(pb_ver)
        auth_packet = self.pb_msg_to_mumble_packet(pb_auth)

        logging.info('sending ver_packet')
        if not self.safe_send_fully(ver_packet):
            raise Exception('failed sending ver_packet')

        logging.info('sending auth_packet')
        if not self.safe_send_fully(auth_packet):
            raise Exception('failed sending auth_packet')

    def read_msg(self):
        hdr = self.safe_read_fully(6)
        if not hdr or len(hdr) != 6:
            logging.error('bad packet, terminating')
            raise Exception('bad packet: %s' % str(hdr))
        msg_type, length = struct.unpack(MumbleConnection.PKT_FORMAT, hdr)

        #msg_type_str = MUMLE_MSG_DICT[msg_type].__name__
        #logging.debug('msg received: %s', msg_type_str)

        msg = self.safe_read_fully(length)
        if not msg:
            raise Exception('failed reading msg of type %s' % msg_type)

        if msg_type == 1:
            return msg_type, msg

        pb_class = MUMLE_MSG_DICT[msg_type]
        pb_msg = pb_class()
        pb_msg.ParseFromString(msg)

        return msg_type, pb_msg

    def join_channel(self):
        if self.channel and self.session:
            pb_userstate = Mumble_pb2.UserState()
            pb_userstate.session = self.session
            pb_userstate.channel_id = self.channel_id

            userstate_packet = self.pb_msg_to_mumble_packet(pb_userstate)

            logging.info('sending userstate_packet (joining channel)')
            if not self.safe_send_fully(userstate_packet):
                raise Exception('failed sending userstate_packet')
        else:
            logging.info('no channel set, ignoring join_channel')

    def handle_msg(self, msg_type, pb_msg):
        #msg_type_str = MUMLE_MSG_DICT[msg_type].__name__
        #logging.debug('handling: %s', msg_type_str)

        # ServerSync
        if msg_type == 5:
            self.session = pb_msg.session
            logging.info('ServerSync - our session is: %s (connected)',
                self.session)
            self.connected = True

        # CodecVersion
        if msg_type == 21:
            codecs = str(pb_msg).split('\n')
            for codec in codecs:
                logging.info('CodecVersion - codecs: %s', codec)

        # ChannelState
        if msg_type == 7:
            if self.channel and pb_msg.name == self.channel:
                if not self.channel_id:
                    self.channel_id = pb_msg.channel_id
                    logging.info('ChannelState - channelid for %s is %s',
                        self.channel, self.channel_id)

        # UserState
        if msg_type == 9:
            try:
                self.user_chan_lock.acquire()
                if pb_msg.HasField('session') and pb_msg.HasField('channel_id'):
                    logging.debug('UserState - session: %s channeld_id:%s',
                        pb_msg.session, pb_msg.channel_id)
                    self.user_channels[pb_msg.session] = pb_msg.channel_id

                if self.channel_id != None:
                    for u in self.user_channels:
                        if self.user_channels[u] == self.channel_id:
                            logging.debug('UserState - in our channel: %s', u)
            finally:
                self.user_chan_lock.release()

        # UserRemove
        if msg_type == 8:
            try:
                self.user_chan_lock.acquire()
                if pb_msg.HasField('session'):
                    logging.debug('UserRemove - session: %s', pb_msg.session)
                    if pb_msg.session in self.user_channels:
                        del self.user_channels[pb_msg.session]
            finally:
                self.user_chan_lock.release()

    def get_user_channels(self):
        ret = {}
        try:
            self.user_chan_lock.acquire()
            ret = dict(self.user_channels)
        finally:
            self.user_chan_lock.release()
        return ret

    def send_ping(self):
        pb_ping = Mumble_pb2.Ping()
        pb_ping.timestamp = int(time.time())
        ping_packet = self.pb_msg_to_mumble_packet(pb_ping)
        if not self.safe_send_fully(ping_packet):
            logging.warning('failed to send ping packet')
        else:
            logging.debug('ping packet sent OK')

    def run(self):
        self.connect()
        sockfd = self.sock.fileno()
        lastping = time.time()

        if Config.ENCSIZE > Config.ENCSIZE_SERVERMAX:
            logging.info('capping ENCSIZE to %s', Config.ENCSIZE_SERVERMAX)
            Config.ENCSIZE = Config.ENCSIZE_SERVERMAX
        logging.info('ENCSIZE is %s', Config.ENCSIZE)

        try:
            while self.running:
                rlist, _, _ = select.select([sockfd], [], [sockfd], 1)
                if rlist:
                    pb_msg_type, pb_msg = self.read_msg()
                    self.handle_msg(pb_msg_type, pb_msg)

                if self.channel and self.session and not self.in_channel:
                    self.join_channel()
                    self.in_channel = True

                now = time.time()
                if now - lastping > 10:
                    self.send_ping()
                    lastping = now
            self.running = False
        except Exception, e:
            log_exception(e)

    def stop(self):
        logging.info('stopping MumbleConnection')
        self.running = False


class MumbleStreamer(threading.Thread):
    REQ_PAUSE = 1
    REQ_NEXT = 2
    REQ_PREV = 3
    REQ_RESTART = 4
    REQ_VOLUME_UP = 5
    REQ_VOLUME_DOWN = 6
    REQ_JUMP_FORWARD = 7
    REQ_RANDOM = 8

    def __init__(self, mconn, playlist_random, playlist_repeat, playlist_dir):
        super(MumbleStreamer, self).__init__()
        self.daemon = True
        self.running = True
        self.mconn = mconn
        self.soxfd = None
        self.sox_sub = None
        self.rawdata = Queue.Queue()
        self.buffered_until = None
        self.paused = 1
        self.progress_time = time.time()
        self.raw_data_progress = 0
        self.last_sox_start = 0
        self.sox_progress = 0
        self.sox_current_file = ''
        self.playlist = []
        self.playlist_dir = playlist_dir
        self.playlist_iter = -1
        self.playlist_repeat = playlist_repeat
        self.playlist_random = playlist_random
        self.req_queue = Queue.Queue()
        self.listeners_last_check = time.time()

        self._rebuild_playlist()

    def _rebuild_playlist(self):
        all_files = get_dir_files(self.playlist_dir)
        playlist = []
        for one_file in all_files:
            one_file_low = one_file.lower()
            if (one_file_low.endswith('.mp3')
                or one_file_low.endswith('.ogg')
                or one_file_low.endswith('.wav')):
                playlist.append(one_file)
        for one_file in playlist:
            logging.info('now in playlist: %s', one_file)

        if self.playlist_iter > len(playlist):
            self.playlist_iter = -1

        if self.playlist_random:
            random.shuffle(playlist)
        else:
            playlist = sorted(playlist)
        playlist.append(None)

        self.playlist = playlist

    def _get_next_playlist_item(self):
        ret = None
        if self.playlist_iter + 1 < len(self.playlist):
            self.playlist_iter = self.playlist_iter + 1
            ret = self.playlist[self.playlist_iter]
        return ret

    def _toggle_pause(self, byadmin=False):
        if self.paused:
            logging.info('resuming stream: %s', self.sox_current_file)
            self.paused = 0
        else:
            logging.info('pausing stream: %s', self.sox_current_file)
            if byadmin:
                self.paused = 2
            else:
                self.paused = 1
        self.progress_time = time.time()
        self.buffered_until = None

    def get_status_str(self):
        if self.paused == 1:
            status = '<paused> '
        elif self.paused == 2:
            status = '<paused by admin> '
        else:
            status = '<playing> '
        status = status + '%s %.2f sec' % (
            self.sox_current_file, self.sox_progress)
        return status

    def _playlist_prev(self, n=1):
        logging.info('playlist_prev')
        self.playlist_iter = self.playlist_iter - 1 - n
        if self.playlist_iter < -1:
            self.playlist_iter = -1

    def _playlist_next(self):
        logging.info('playlist_next')

    def _playlist_random(self):
        logging.info('playlist_random')
        self.playlist_iter = random.randint(-1, len(self.playlist) - 1)

    def _jump_forward(self):
        jump_by = Config.FRAMES_IN_PACKET * Config.PACKETS_PER_SECOND * 10
        logging.info('jump forward by: %s', jump_by)
        while not self.rawdata.empty():
            self.rawdata.get()
        self._refill_buffer(jump_by)
        while not self.rawdata.empty():
            self.rawdata.get()
        self.sox_progress = self.sox_progress + jump_by * Config.FRAME_TIME

    def _volume_change(self, direction):
        Config.VOLUME = Config.VOLUME + 0.1*direction
        logging.info('volume: %s', Config.VOLUME)

    def _start_sox(self, musicfile):
        sox_params = ['/usr/bin/sox', musicfile, '--bits', '16',
            '--encoding', 'signed-integer', '-t', 'raw', '-',
            'channels', '1', 'rate', '48k', 'vol', str(Config.VOLUME)]
        self.sox_current_file = os.path.basename(musicfile)
        logging.info('starting sox for: %s', self.sox_current_file)
        self.sox_sub = subprocess.Popen(sox_params, stdout=subprocess.PIPE,
                                        cwd=os.getcwd())
        self.soxfd = self.sox_sub.stdout
        self._refill_buffer(Config.SENT_BUFFER_FRAMES * 16)
        self.sox_progress = 0

    def _stop_sox(self, drain_buffer=False):
        logging.info('stopping sox')
        if self.sox_sub:
            self.sox_sub.kill()
            self.sox_sub.wait()
            self.sox_sub = None
        if self.soxfd:
            self.soxfd.close()
            self.soxfd = None
        self.sox_current_file = ''
        # drain buffer
        if drain_buffer:
            self.sox_progress = 0
            self.buffered_until = None
            while not self.rawdata.empty():
                self.rawdata.get()

    def _run_next_in_playlist(self, force):
        next_in_playlist = self._get_next_playlist_item()
        if not next_in_playlist:
            if self.playlist_repeat:
                self.playlist_iter = -1
                next_in_playlist = self._get_next_playlist_item()
            else:
                logging.info('playlist is empty')
                if self.paused == 0:
                    self._toggle_pause(False)
        if next_in_playlist:
            self._start_sox(next_in_playlist)
            if force and self.paused:
                self._toggle_pause(False)
        else:
            logging.info('could not find anything to play')

    def _check_sox(self, force=False):
        now = time.time()
        if now - self.last_sox_start > 2 or force:
            self.last_sox_start = now
            if not self.sox_sub and not self.soxfd:
                logging.info('sox is dead, looking for next item in playlist')
                self._run_next_in_playlist(force)

    def _refill_buffer(self, frame_count = Config.SENT_BUFFER_FRAMES * 2):
        if self.rawdata.qsize() < Config.SENT_BUFFER_FRAMES * 64 and self.soxfd:
            for i in range(0, frame_count):
                raw_data = self.soxfd.read(2 * Config.FRAME_SIZE)
                if raw_data:
                    raw_data_len = len(raw_data)
                    if raw_data_len < 2 * Config.FRAME_SIZE:
                        logging.debug('len of raw_data is %s, padding to %s',
                            len(raw_data), 2 * Config.FRAME_SIZE)
                        raw_data = (raw_data +
                            '\0' * (2 * Config.FRAME_SIZE - raw_data_len))
                    self.rawdata.put(raw_data)
                else:
                    logging.info('reached end of rawdata (sox fd)')
                    self._stop_sox()
                    break

    def _stream_buffer(self):
        now = time.time()
        if not self.buffered_until:
            self.buffered_until = now

        if self.buffered_until < now:
            logging.debug('we are late %s', self.buffered_until)

        if self.rawdata.empty():
            return

        if self.buffered_until - now < Config.SENT_BUFFER_DURATION:
            raw_data_list = []
            i = 0
            raw_data_size = 0
            while i < Config.FRAMES_IN_PACKET and not self.rawdata.empty():
                raw_frame = self.rawdata.get()
                raw_data_size = raw_data_size + len(raw_frame)
                raw_data_list.append(raw_frame)
                i = i + 1
            if raw_data_list:
                logging.debug('sending audio (%s frames), buff_sent [t]: %s',
                    i, self.buffered_until - now)
                self.mconn.send_audio_packet(raw_data_list)
                self.buffered_until = (self.buffered_until +
                        (raw_data_size * Config.RAWDATA_TO_TIME))
                now = time.time()
                self.raw_data_progress = self.raw_data_progress + 1
                self.sox_progress = self.sox_progress + i * Config.FRAME_TIME
            else:
                logging.debug('raw_data_list is empty')
        if now - self.progress_time > Config.PROGRESS_PERIOD:
            logging.info('streamed %s frames in %s sec',
                self.raw_data_progress, now - self.progress_time)
            self.progress_time = now
            self.raw_data_progress = 0

    def add_req(self, req):
        self.req_queue.put(req)

    def _check_for_listeners(self):
        now = time.time()
        if now - self.listeners_last_check > 10:
            self.listeners_last_check = now
            listeners = self.mconn.get_user_channels()
            someone_listening = False
            for u in listeners:
                if (u != self.mconn.session
                    and listeners[u] == self.mconn.channel_id):
                    someone_listening = True
                    break

            if self.paused == 1 and someone_listening:
                logging.info('we have a listener, resuming')
                self._toggle_pause(False)
            if self.paused == 0 and not someone_listening:
                logging.info('we do not have any listenerer, pausing')
                self._toggle_pause(False)

    def run(self):
        try:
            while self.running and self.mconn.is_alive():

                while not self.req_queue.empty():
                    req = self.req_queue.get()
                    if req == MumbleStreamer.REQ_PAUSE:
                        self._toggle_pause(True)
                    if req == MumbleStreamer.REQ_PREV:
                        self._playlist_prev(1)
                        self._stop_sox(True)
                        self._check_sox(force=True)
                    if req == MumbleStreamer.REQ_NEXT:
                        self._playlist_next()
                        self._stop_sox(True)
                        self._check_sox(force=True)
                    if req == MumbleStreamer.REQ_RESTART:
                        self._playlist_prev(0)
                        self._stop_sox(True)
                        self._check_sox(force=True)
                    if req == MumbleStreamer.REQ_RANDOM:
                        self._playlist_random()
                        self._stop_sox(True)
                        self._check_sox(force=True)
                    if req == MumbleStreamer.REQ_VOLUME_UP:
                        self._volume_change(1)
                    if req == MumbleStreamer.REQ_VOLUME_DOWN:
                        self._volume_change(-1)
                    if req == MumbleStreamer.REQ_JUMP_FORWARD:
                        self._jump_forward()

                self._check_for_listeners()

                if self.paused == 0:
                    self._check_sox(force=False)
                if self.paused == 0:
                    self._refill_buffer()
                    self._stream_buffer()
                    time.sleep(Config.FRAME_TIME)
                else:
                    logging.debug('paused, sleeping')
                    time.sleep(1)
        except Exception, e:
            log_exception(e)

    def stop(self):
        logging.info('stopping MumbleStreamer')
        self._stop_sox()
        self.running = False


class CursesScreen:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        maxy, maxx = stdscr.getmaxyx()

        log_lines, log_cols = (maxy - 2, maxx)
        self.logwnd = self.stdscr.subpad(log_lines, log_cols, 0, 0)

        status_lines, status_cols = (1, maxx)
        self.statuswnd = self.stdscr.subpad(status_lines,
            status_cols, log_lines, 0)

    def resize_windows(self):
        maxy, maxx = self.stdscr.getmaxyx()
        logging.debug('check_resize_windows %s %s', maxy, maxx)

        self.stdscr.clear()

        log_lines, log_cols = (maxy - 2, maxx)
        self.logwnd.resize(log_lines, log_cols)
        self.logwnd.clear()
        self.logwnd.noutrefresh()

        status_lines, status_cols = (1, maxx)
        self.statuswnd.mvderwin(log_lines, 0)
        self.statuswnd.resize(status_lines, status_cols)
        logging.debug('check_resize_windows %s', str(self.statuswnd.getparyx()))
        logging.debug('check_resize_windows %s', str(self.statuswnd.getmaxyx()))
        self.statuswnd.clear()
        self.statuswnd.noutrefresh()
        self.stdscr.refresh()

    def draw(self, log_storage, statusline):
        maxy, maxx = self.logwnd.getmaxyx()
        content_height = maxy - 1
        log_storage.max_logs = content_height
        lines_to_display = min(content_height, len(log_storage.content))

        self.stdscr.clear()
        if log_storage.check_changed:
            self.logwnd.clear()
            for i in range(0, lines_to_display):
                self.logwnd.addstr(i, 0, log_storage.content[i][:maxx])
                #self.window.leaveok(0)
                self.logwnd.noutrefresh()

        self.statuswnd.clear()
        self.statuswnd.addstr(0, 0, statusline)
        self.statuswnd.noutrefresh()

        maxy, maxx = self.stdscr.getmaxyx()
        self.stdscr.move(maxy - 1, 0)
        self.stdscr.refresh()


def main_curses(stdscr, options):
    curses.cbreak()
    stdscr.keypad(1)
    stdscr.nodelay(True)

    mconn = None
    mstreamer = None

    log_storage = LogStorage(25)
    screen = CursesScreen(stdscr)
    setup_logging(log_storage)

    def stop_app(sig, frame):
        logging.info('got signal %s', sig)
        if mconn:
            mconn.stop()
        if mstreamer:
            mstreamer.stop()

    logging.info('App is starting')
    host = (options.server, options.port)

    mconn = MumbleConnection(host = host, channel = options.channel,
        password = options.password)
    mconn.start()

    mstreamer = MumbleStreamer(mconn, playlist_random=options.random,
                playlist_repeat=options.repeat, playlist_dir=options.dir)
    mstreamer.start()

    signal.signal(signal.SIGINT, stop_app)
    signal.signal(signal.SIGTERM, stop_app)

    while (mconn.is_alive() and mstreamer.is_alive()
        and mconn.running and mstreamer.running):
        s = stdscr.getch()

        if s != -1:
            logging.debug('read from stdin: %s', s)
        if s == ord('q') or s == ord('Q'):
            break
        if s == ord(' '):
            mstreamer.add_req(MumbleStreamer.REQ_PAUSE)
        if s == ord('n') or s == ord('N'):
            mstreamer.add_req(MumbleStreamer.REQ_NEXT)
        if s == ord('p') or s == ord('P'):
            mstreamer.add_req(MumbleStreamer.REQ_PREV)
        if s == ord('a') or s == ord('A'):
            mstreamer.add_req(MumbleStreamer.REQ_RESTART)
        if s == ord('r') or s == ord('R'):
            mstreamer.add_req(MumbleStreamer.REQ_RANDOM)
        if s == ord('+'):
            mstreamer.add_req(MumbleStreamer.REQ_VOLUME_UP)
        if s == ord('-'):
            mstreamer.add_req(MumbleStreamer.REQ_VOLUME_DOWN)
        if s == ord('f') or s == ord('F'):
            mstreamer.add_req(MumbleStreamer.REQ_JUMP_FORWARD)

        if s == curses.KEY_RESIZE:
            screen.resize_windows()

        screen.draw(log_storage, mstreamer.get_status_str())
        if s == -1:
            time.sleep(0.25)

    if mconn.running:
        mconn.stop()

    if mstreamer.running:
        mstreamer.stop()

    i = 0
    while i < 20 and  mconn.is_alive() and mstreamer.is_alive():
        time.sleep(0.1)
        i = i + 1
    logging.info('App is exiting')

def main():
    p = optparse.OptionParser(description='Mumble streamer 0.1',
        prog='mstream.py', version='%prog 0.1',
        usage='\t%prog -c "channelname"')
    p.add_option('-c', '--channel', help='Channel to join', default="Root")
    p.add_option('-s', '--server', help='Server to connect to')
    p.add_option('-r', '--repeat', help='repeat playlist',
        action='store_true')
    p.add_option('-a', '--random', help='random order of items in playlist',
        action='store_true', default=False)
    p.add_option('-p', '--port', help='Server port',
        action='store', type='int', default=64738)
    p.add_option('-d', '--dir', help='Directory to scan',
        action='store', default='.')
    p.add_option('--password', help='Server password')

    (options, args) = p.parse_args()
    curses.wrapper(main_curses, options)

if __name__ == '__main__':
    main()

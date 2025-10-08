import socket
import threading
import traceback
import time
from multiprocessing import Process
from enum import Enum
import queue
import logging
import math
import argparse
import re
import os
import select
from collections import deque
from defended_socket import DefendedSocket

params = {
    'padding_parameter': 250,
    'Client': {
        'fast': {
            'size': 750,
            'rate': 0.02,
            'active_timeout': 8,
            'inactive_timeout': 5,
        },
        'slow': {
            'size': 100,
            'rate': 0.1,
            'active_timeout': 10,
            'inactive_timeout': 10,
        },
        'extended': {
            'size': 750,
            'rate': 0.02,
            'active_timeout': 60,
            'inactive_timeout': 5,
        },
    },
    'Server': {
        'fast': {
            'size': 1000,
            'rate': 0.02,
            'active_timeout': 13,
            'inactive_timeout': 5,
        },
        'slow': {
            'size': 100,
            'rate': 0.1,
            'active_timeout': 2,
            'inactive_timeout': 5,
        },
        'extended': {
            'size': 750,
            'rate': 0.02,
            'active_timeout': 60,
            'inactive_timeout': 5,
        },
    }
}

MAX_RECV_SIZE = 4096
BYTES_MAX_2 = 65535

SPECIAL_MSGS = {
    'HEADER_SPECIAL': b'\x00\x00',
    'CODE_SHUTDOWN': b'\x00',
}

SERVER_ADDR = None
SERVER_PORT = None

class PlainSocketManager:
    def __init__(self, proxy_type, ch_recv_queue):
        self.proxy_type = proxy_type
        if self.proxy_type == 'Client':
            self.slots = deque(list(range(1, 255)))
            self.slot_leases = {}
        else:
            self.slots = None
            self.slot_leases = None
        self.mapping = TwoWayDict()
        self.lease_time = 30 * 60 # 30 minutes
        self.l = logging.getLogger('PlainSocketManager')
        self.half_closed = set()
        self.ch_recv_queue = ch_recv_queue
    
    def isHalfClosed(self, snum):
        return snum in self.half_closed
    
    def halfClose(self, snum):
        self.half_closed.add(snum)

    def getSlotFromSocket(self, s):
        try:
            snum = self.mapping[s]
            return snum
        except KeyError:
            self.l.error(f"getSlotFromSocket: KeyError, s={s}")
            return None
        
    def getSocketFromSnum(self, snum):
        try:
            s = self.mapping[snum]
            return s
        except KeyError:
            self.l.error(f"getSocketFromSnum: KeyError, snum={snum}")
            return None
        
    def release(self, snum):
        self.l.info(f"Releasing Slot: {snum}")
        if self.slots is not None: self.slots.append(snum)
        if snum in self.mapping: del self.mapping[snum]
        if self.slot_leases is not None: del self.slot_leases[snum]
        if snum in self.half_closed: self.half_closed.remove(snum)

    def check_leases(self):
        self.l.info(f'Checking Leases')
        t = time.time()
        keys = list(self.slot_leases.keys())
        for snum in keys:
            expiry = self.slot_leases[snum]
            if t > expiry:
                self.l.info(f"Lease Expired: {snum}")
                self.release(snum)
                self.special_close_communicate(snum)

    def special_close_communicate(self, snum):
        msg = SPECIAL_MSGS['HEADER_SPECIAL'] + snum.to_bytes(1, byteorder='big') + SPECIAL_MSGS['CODE_SHUTDOWN']
        self.l.info(f"Special Close Communicate: snum={snum}, {msg}")
        self.ch_recv_queue.put_nowait(msg)
        return
    
    def check_snum_exists(self, snum):
        return snum in self.mapping
    
    def get_new_slot(self, s):
        if self.proxy_type == 'Server':
            self.l.warning('get_new_slot: Called for Server')
            return
        self.check_leases()
        try:
            snum = self.slots.popleft()
        except IndexError:
            self.l.error("No Slots Available")
            return None
        self.slot_leases[snum] = time.time() + self.lease_time
        self.mapping[snum] = s
        self.l.info(f"New Slot: {snum}")
        return snum
    
    def assign_socket_to_slot(self, snum, s):
        if self.proxy_type == 'Client':
            self.l.warning('assign_socket_to_slot: Called for Client')
            return
        self.mapping[snum] = s
        self.l.info(f"Assigned Socket to Slot: {snum}")
        return
     
class State(Enum):
    IDLE = 1
    FAST = 2
    SLOW = 3
    EXTENDED = 4

    def __int__(self):
        return self.value
    
    def state_change_msg(self):
        state = self.value.to_bytes(1, byteorder='big')
        to = b'\x00'
        msg = to + state
        print('sending state_change_message:', msg)
        return msg

class ProxyType(Enum):
    CLIENT = 1
    SERVER = 2

class TwoWayDict(dict):
    def __setitem__(self, key, value):
        # Remove any previous connections with these values
        if key in self:
            del self[key]
        if value in self:
            del self[value]
        dict.__setitem__(self, key, value)
        dict.__setitem__(self, value, key)

    def __delitem__(self, key):
        dict.__delitem__(self, self[key])
        dict.__delitem__(self, key)

    def __len__(self):
        """Returns the number of connections"""
        return dict.__len__(self) // 2

class Timeout:
    def __init__(self, timeout):
        self.timeout = timeout
        self.last_time = time.time()
    
    def check(self):
        if time.time() - self.last_time > self.timeout:
            return True
        return False
    
    def reset(self):
        self.last_time = time.time()

class Padding:
    def __init__(self):
        self.header_size = 2
        self.encoding_buffer = b''
        self.decoding_buffer = b''
        self.max_length = MAX_RECV_SIZE + self.header_size
        self.encoding_len = 0
        self.max_encoding_len = 1000

    def encode(self, data):
        chunk_len = len(data)
        header = chunk_len.to_bytes(self.header_size, byteorder='big')
        if chunk_len == 0:
            return header
        elif chunk_len > BYTES_MAX_2:
            raise ValueError("Chunk Length Exceeded", chunk_len)
        else:
            return header + data
    
    def feedEncodingData(self, data):
        encoded_data = self.encode(data)
        l = len(encoded_data)
        self.encoding_buffer += encoded_data
        self.encoding_len += l
        if self.encoding_len > self.max_encoding_len:
            logging.warning(f'Encoding_Buffer_Size: {self.encoding_len}')
            self.max_encoding_len = self.encoding_len
        return
    
    def getEncodedData(self, min_length=None):
        encoding_buffer_len = len(self.encoding_buffer)
        if min_length is None:
            data = self.encoding_buffer[:self.max_length]
            self.encoding_buffer = self.encoding_buffer[self.max_length:]
        else:
            if encoding_buffer_len < min_length:
                filling_len = min_length - encoding_buffer_len
                filling_len += filling_len % self.header_size
                self.encoding_buffer += b'\x00' * filling_len
            data = self.encoding_buffer[:min_length]
            self.encoding_buffer = self.encoding_buffer[min_length:]
        self.encoding_len = len(self.encoding_buffer)
        return data
    
    def decode(self, encoded_data):
        self.decoding_buffer += encoded_data
        ret_val = []
        while True:
            if len(self.decoding_buffer) < self.header_size: break
            chunk_len = int.from_bytes(self.decoding_buffer[:self.header_size], byteorder='big')
            if chunk_len > BYTES_MAX_2:
                raise ValueError("Chunk Length Error", chunk_len)
            elif chunk_len == 0:
                self.decoding_buffer = self.decoding_buffer[self.header_size:]
            elif (chunk_len + self.header_size) <= len(self.decoding_buffer):
                ret_val.append(self.decoding_buffer[self.header_size:self.header_size + chunk_len])
                self.decoding_buffer = self.decoding_buffer[chunk_len + self.header_size:]
            else:
                break
        return ret_val

class ProxyConnectionHandler:
    outgoing_state_threshold_llim = 2200
    outgoing_state_threshold_ulim = 3500
    def __init__(self, recv_queue, send_queue, params, proxy_type):
        self.recv_queue = recv_queue
        self.send_queue = send_queue
        self.defended_socket = DefendedSocket(proxy_type, addr=SERVER_ADDR, port=SERVER_PORT)
        self.state = None
        self.set_state(State.IDLE)
        self.params = params
        self.proxy_type = proxy_type
        self.padding = Padding()
        self.run = True
        self.validate_params()

    def validate_params(self):
        assert self.params['padding_parameter'] > 0 and self.params['padding_parameter'] < 10000
        assert self.params['Client']['fast']['size'] > 0 and self.params['Client']['fast']['size'] < 10000
        assert self.params['Client']['fast']['rate'] > 0 and self.params['Client']['fast']['rate'] < 1
        assert self.params['Client']['slow']['size'] > 0 and self.params['Client']['slow']['size'] < 10000
        assert self.params['Client']['slow']['rate'] > 0 and self.params['Client']['slow']['rate'] < 5
        assert self.params['Client']['extended']['size'] > 0 and self.params['Client']['extended']['size'] < 10000
        assert self.params['Client']['extended']['rate'] > 0 and self.params['Client']['extended']['rate'] < 5
        assert self.params['Server']['fast']['size'] > 0 and self.params['Server']['fast']['size'] < 10000
        assert self.params['Server']['fast']['rate'] > 0 and self.params['Server']['fast']['rate'] < 1
        assert self.params['Server']['slow']['size'] > 0 and self.params['Server']['slow']['size'] < 10000
        assert self.params['Server']['slow']['rate'] > 0 and self.params['Server']['slow']['rate'] < 5
        assert self.params['Server']['extended']['size'] > 0 and self.params['Server']['extended']['size'] < 10000
        assert self.params['Server']['extended']['rate'] > 0 and self.params['Server']['extended']['rate'] < 5
        
        # Timeouts
        assert self.params['Client']['fast']['active_timeout'] > 0
        assert self.params['Client']['slow']['active_timeout'] > 0
        assert self.params['Client']['slow']['inactive_timeout'] > 0
        assert self.params['Client']['extended']['active_timeout'] > 0
        assert self.params['Client']['extended']['inactive_timeout'] > 0
        assert self.params['Server']['fast']['active_timeout'] > 0
        assert self.params['Server']['slow']['active_timeout'] > 0
        assert self.params['Server']['slow']['inactive_timeout'] > 0
        assert self.params['Server']['extended']['active_timeout'] > 0
        assert self.params['Server']['extended']['inactive_timeout'] > 0

        return
    
    @staticmethod
    def findTimeToNextInterval(val, interval_width=0.5):
        return interval_width - (val % interval_width)
    
    def set_state(self, new_state, msg=False):
        # return
        if self.state == new_state:
            return
        if self.state is None:
            self.state = State.IDLE
            self.state_st = 0
            self.state_pkt_sent = 0
        t = time.time()
        m = f"State Changed from {self.state} to {new_state}. Stats: pkt_sent={self.state_pkt_sent}, time={round(t - self.state_st, 3)}"
        self.l.info(m)
        if msg:
            message = new_state.state_change_msg()
            self.padding.feedEncodingData(message)
        print(m)
        if new_state == State.IDLE:
            self.state_active_timeout = Timeout(float('inf'))
            self.state_inactive_timeout = Timeout(float('inf'))
        elif new_state == State.FAST:
            self.state_active_timeout = Timeout(self.params[self.proxy_type]['fast']['active_timeout'])
            self.state_inactive_timeout = Timeout(self.params[self.proxy_type]['fast']['inactive_timeout'])
        elif new_state == State.SLOW:
            self.state_active_timeout = Timeout(self.params[self.proxy_type]['slow']['active_timeout'])
            self.state_inactive_timeout = Timeout(self.params[self.proxy_type]['slow']['inactive_timeout'])
        elif new_state == State.EXTENDED:
            self.state_active_timeout = Timeout(self.params[self.proxy_type]['extended']['active_timeout'])
            self.state_inactive_timeout = Timeout(self.params[self.proxy_type]['extended']['inactive_timeout'])
        else:
            raise ValueError("Invalid State")
        
        self.state = new_state
        self.state_st = t
        self.state_pkt_sent = 0
        return
    
    def plain2defended(self):
        self.l.info("Starting plain2defended")
        while self.run:
            if (time.time() - self.state_st) > 60: self.set_state(State.IDLE, msg=True)
            try:
                state = self.state
                if state == State.IDLE:
                    self.sendr_idle()
                elif state == State.FAST:
                    self.sendr_fast()
                    time.sleep(self.params[self.proxy_type]['fast']['rate'])
                elif state == State.SLOW:
                    self.sendr_slow()
                    time.sleep(self.params[self.proxy_type]['slow']['rate'])
                elif state == State.EXTENDED:
                    self.sendr_extended()
                    time.sleep(self.params[self.proxy_type]['extended']['rate'])
            except Exception:
                print(traceback.format_exc())
                self.run = False
                break
        return
        
    def start(self):
        self.l.info("Starting ConnectionHandler")
        d2p = threading.Thread(target=self.defended2plain)
        d2p.start()
        self.plain2defended()
        d2p.join()
        self.l.info("ConnectionHandler closed")


class ServerProxyConnectionHandler(ProxyConnectionHandler):
    def __init__(self, recv_queue, send_queue, params):
        self.l = logging.getLogger('ServerProxyCH')
        super().__init__(recv_queue=recv_queue, send_queue=send_queue, params=params, proxy_type='Server')
        self.l.info("Initialized ConnectionHandler")

    def sendr_slow(self):
        send_size = self.params[self.proxy_type]['slow']['size']
        while (self.padding.encoding_len < send_size) and not self.recv_queue.empty():
            data = self.recv_queue.get_nowait()
            data_len = len(data)
            if data_len == 0:
                self.set_state(State.IDLE, msg=True)
                break
                # raise ValueError("Data Length is 0")
            self.padding.feedEncodingData(data)

        if self.state_active_timeout.check():
            self.l.info("Incoming Inactive: State Active Timeout")
            self.set_state(State.FAST, msg=True)
        encoded_data = self.padding.getEncodedData(send_size)
        self.defended_socket.send(encoded_data)
        self.state_pkt_sent += 1
        return
    
    def sendr_fast(self):
        send_size = self.params[self.proxy_type]['fast']['size']
        while (self.padding.encoding_len < send_size) and not self.recv_queue.empty():
            data = self.recv_queue.get_nowait()
            data_len = len(data)
            if data_len == 0:
                raise ValueError("Data Length is 0")
            self.padding.feedEncodingData(data)
            if data_len >= 100:
                self.state_inactive_timeout.reset()
        if self.state_active_timeout.check():
            if self.state_inactive_timeout.check():
                self.l.info("Incoming Active: State Active Timeout and State Not Active")
                self.set_state(State.IDLE, msg=True)
            else:
                self.l.info("Incoming Active: State Active Timeout but State Active")
                self.set_state(State.EXTENDED, msg=True)
        encoded_data = self.padding.getEncodedData(send_size)
        self.defended_socket.send(encoded_data)
        self.state_pkt_sent += 1
        return
    
    def sendr_extended(self):
        send_size = self.params[self.proxy_type]['extended']['size']
        padding_parameter = self.params['padding_parameter']
        while (self.padding.encoding_len < send_size) and not self.recv_queue.empty():
            data = self.recv_queue.get_nowait()
            data_len = len(data)
            if data_len == 0:
                raise ValueError("Data Length is 0")
            self.padding.feedEncodingData(data)
            if data_len >= 100:
                self.state_inactive_timeout.reset()
        
        done = False
        if self.state_inactive_timeout.check() and ((self.state_pkt_sent % padding_parameter) == 0):
            self.l.info("Incoming Extended: State Inactive Timeout")
            done = True
        if self.state_active_timeout.check():
            self.l.info("Incoming Extended: State Active Timeout")
            done = True
        if done:
            self.set_state(State.IDLE, msg=True)

        encoded_data = self.padding.getEncodedData(send_size)
        self.defended_socket.send(encoded_data)
        self.state_pkt_sent += 1
        return
    
    def sendr_idle(self):
        try:
            data = self.recv_queue.get(block=True, timeout=0.1)
            # Padding
            self.padding.feedEncodingData(data)
            data = self.padding.getEncodedData()
            self.defended_socket.send(data)
        except queue.Empty:
            pass
        return
    
    def defended2plain(self):
        # Decodes data from defended socket to plain socket
        self.l.info("Starting defended2plain")
        while self.run:
            try:
                data = self.defended_socket.recv(MAX_RECV_SIZE)
            except Exception:
                print(traceback.format_exc())
                self.run = False
                break
            if len(data) == 0:
                # Connection Closed
                self.l.error("Connection Closed")
                break
            # self.l.debug(f"d2p: recv {len(data)} bytes")
            decoded_data = self.padding.decode(data) # Padding
            for data in decoded_data:
                if data[0] == 0:
                    # Message for Connection Handler
                    print('Server Recv:', data)
                    if data[1] == 0:
                        self.send_queue.put_nowait(data)
                    elif data[1] == 1:
                        # Client is IDLE: Set as IDLE
                        self.set_state(State.IDLE)
                    elif data[1] == 2:
                        # Client is FAST. Set as SLOW Initially
                        self.set_state(State.SLOW)
                    elif data[1] == 3:
                        # Client is in SLOW. Don't do anything
                        pass
                    elif data[1] == 4:
                        # Client is in state EXTENDED. Set as EXTENDED
                        self.set_state(State.EXTENDED)
                    else:
                        raise ValueError("Invalid Message", data[1])
                else:
                    # self.l.debug(f"Sending {len(data)} bytes to {self.proxy_type}Proxy")
                    self.send_queue.put_nowait(data)

                        
class ClientProxyConnectionHandler(ProxyConnectionHandler):
    def __init__(self, recv_queue, send_queue, params):
        self.l = logging.getLogger('ClientProxyCH')
        super().__init__(recv_queue=recv_queue, send_queue=send_queue, params=params, proxy_type='Client')
        self.l.info("Initialized ConnectionHandler")

    def sendr_fast(self):
        send_size = self.params[self.proxy_type]['fast']['size']
        while (self.padding.encoding_len < send_size) and not self.recv_queue.empty():
            data = self.recv_queue.get_nowait()
            data_len = len(data)
            if data_len == 0:
                raise ValueError("Data Length is 0")
            self.padding.feedEncodingData(data)
            if data_len >= 100:
                self.state_inactive_timeout.reset()
        # if self.state_inactive_timeout.check():
        #     self.l.info("Outgoing Active: State Inactive Timeout")
        #     self.set_state(State.INACTIVE, msg=True)
        if self.state_active_timeout.check():
            self.l.info("Outgoing Active: State Active Timeout")
            self.set_state(State.SLOW, msg=True)
        encoded_data = self.padding.getEncodedData(send_size)
        self.defended_socket.send(encoded_data)
        self.state_pkt_sent += 1
        return
    
    def sendr_slow(self):
        send_size = self.params[self.proxy_type]['slow']['size']
        while (self.padding.encoding_len < send_size) and not self.recv_queue.empty():
            data = self.recv_queue.get_nowait()
            data_len = len(data)
            if data_len == 0:
                raise ValueError("Data Length is 0")
            self.padding.feedEncodingData(data)
        if self.state_active_timeout.check():
            self.l.info("Outgoing Inactive: State Active Timeout")
            self.set_state(State.IDLE, msg=True)
        encoded_data = self.padding.getEncodedData(send_size)
        self.defended_socket.send(encoded_data)
        self.state_pkt_sent += 1
        return
    
    def sendr_extended(self):
        send_size = self.params[self.proxy_type]['extended']['size']
        while (self.padding.encoding_len < send_size) and not self.recv_queue.empty():
            data = self.recv_queue.get_nowait()
            data_len = len(data)
            if data_len == 0:
                raise ValueError("Data Length is 0")
            self.padding.feedEncodingData(data)
        
        done = False
        if self.state_active_timeout.check():
            self.l.info("Incoming Extended: State Active Timeout")
            done = True
        if done:
            self.set_state(State.IDLE, msg=True)

        encoded_data = self.padding.getEncodedData(send_size)
        self.defended_socket.send(encoded_data)
        self.state_pkt_sent += 1
        return
    
    def sendr_idle(self):
        try:
            data = self.recv_queue.get(block=True, timeout=0.1)
            data_len = len(data)
            
            if (data_len >= self.outgoing_state_threshold_llim) and (data_len <= self.outgoing_state_threshold_ulim):
                print('Outgoing Started')
                self.l.info("Outgoing Start Indicator")
                self.set_state(State.FAST, msg=True)

            # Padding
            self.padding.feedEncodingData(data)
            encoded_data = self.padding.getEncodedData()
            self.defended_socket.send(encoded_data)
        except queue.Empty:
            pass
        return
    
    def defended2plain(self):
        # Decodes data from defended socket to plain socket
        self.l.info("Starting defended2plain")
        while self.run:
            try:
                data = self.defended_socket.recv(MAX_RECV_SIZE)
            except Exception:
                print(traceback.format_exc())
                self.run = False
                break
            if len(data) == 0:
                # Connection Closed
                self.l.error("Connection Closed")
                break
            # self.l.debug(f"d2p: recv {len(data)} bytes")
            decoded_data = self.padding.decode(data) # Padding
            for data in decoded_data:
                if data[0] == 0:
                    print(data)
                    # Message for Connection Handler
                    if data[1] == 0:
                        self.send_queue.put_nowait(data)
                    elif data[1] == 1:
                        # Server is IDLE: Set as IDLE
                        self.set_state(State.IDLE)
                    elif data[1] == 2:
                        # Server is FAST. Don't do anything
                        pass
                    elif data[1] == 3:
                        # Server is SLOW. Don't to anything
                        # self.set_state(State.INACTIVE)
                        pass
                    elif data[1] == 4:
                        # Server is Extended. Set extended
                        self.set_state(State.EXTENDED)
                    else:
                        raise ValueError("Invalid Message", data[1])
                else:
                    # self.l.debug(f"Sending {len(data)} bytes to {self.proxy_type}Proxy")
                    self.send_queue.put_nowait(data)

class Proxy:
    def __init__(self, listen_addr, listen_port, forward_addr, forward_port, proxy_type):
        self.proxy_type = proxy_type
        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self.forward_addr = forward_addr
        self.forward_port = forward_port
        self.run = True
        self.half_closed = set()
        self.l = logging.getLogger(f'{proxy_type}Proxy')
        self.pipe_r, self.pipe_w = os.pipe()
        self.input_sockets= [self.pipe_r]
        self.ch_send_queue = queue.Queue()
        self.ch_recv_queue = queue.Queue()
        self.plain_socket_manager = PlainSocketManager(proxy_type=self.proxy_type, ch_recv_queue=self.ch_recv_queue)

        # Only for Client
        self.server_socket = None

        # Only for Server

    def update_input_sockets(self, s):
        self.input_sockets.append(s)
        os.write(self.pipe_w, b'\x00')
        return

    def handle_special(self, data):
        # Special Case
        snum = data[1]
        code = data[2]
        if self.plain_socket_manager.check_snum_exists(snum) == False:
            self.l.warning("handle_special: Invalid Slot Number")
            return
        s = self.plain_socket_manager.getSocketFromSnum(snum)
        if s is None:
            self.l.error("handle_special: Invalid Socket")
            return
        
        if code == 0:
            try:
                s.shutdown(2)
                s.close()
            except OSError:
                self.l.warning("handle_special: OSError. Socket Already Closed")
            self.plain_socket_manager.release(snum)
        else:
            self.l.error("Invalid Code", data)
        return
    
    def defended_get(self):
        data = self.ch_send_queue.get(block=True, timeout=1)
        snum = data[0]

        # Debugging
        data_len = len(data)
        data_str = '' if data_len > 5 else str(data) 
        self.l.info(f"defended: recv {len(data)} bytes, snum={snum} {data_str}")

        return snum, data[1:]
    
    def create_new_connection(self, snum):
        self.l.info(f"create_new_connection: Called. snum={snum}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.forward_addr, self.forward_port))
        self.plain_socket_manager.assign_socket_to_slot(snum, s)
        self.update_input_sockets(s)
        return
    
    def handle_defended_shutdown(self, snum):
        s = self.plain_socket_manager.getSocketFromSnum(snum)
        if s is None:
            self.l.error("handle_defended_shutdown: Invalid Socket")
            return
        try:
            s.shutdown(1)
        except OSError:
            self.l.warning("OSError. Socket Already Closed. Releasing it")
            if not self.plain_socket_manager.isHalfClosed(snum):
                self.l.info("Sending Forwarded Shutdown Message")
                self.ch_recv_queue.put_nowait(snum.to_bytes(1, byteorder='big') + b'')
            self.plain_socket_manager.release(snum)
            try:
                s.close()
            except Exception:
                print(traceback.format_exc())
                pass
            return
            # self.unexpected_shutdown(s)
        if self.plain_socket_manager.isHalfClosed(snum):
            self.plain_socket_manager.release(snum)
            s.close()
        else:
            self.plain_socket_manager.halfClose(snum)
            self.l.debug(f"Sending shutdown message. snum={snum}")

    def handle_plain_shutdown(self, snum):
        s = self.plain_socket_manager.getSocketFromSnum(snum)
        if s is None:
            self.l.error("handle_plain_shutdown: Invalid Socket")
            return
        self.input_sockets.remove(s)
        if self.plain_socket_manager.isHalfClosed(snum):
            self.plain_socket_manager.release(snum)
            try:
                s.close()
            except Exception:
                print(traceback.format_exc())
                pass
        else:
            self.plain_socket_manager.halfClose(snum)

    def handle_defended(self):
        self.l.info("Starting handle_defended")
        try:
            while self.run:
                try:
                    snum, data = self.defended_get()
                except queue.Empty:
                    continue
                if snum == 0:
                    self.handle_special(data)
                    continue
                if not self.plain_socket_manager.check_snum_exists(snum):
                    if self.proxy_type == 'Client':
                        self.l.error(f"Invalid Slot Number. snum={snum}, data={data}")
                        continue
                        # raise ValueError("Invalid Slot Number")
                    else:
                        self.create_new_connection(snum)
                if len(data) == 0:
                    self.handle_defended_shutdown(snum)
                else:
                    s = self.plain_socket_manager.getSocketFromSnum(snum)
                    if s is None:
                        self.l.error("handle_defended: Invalid Socket")
                        continue
                    try:
                        s.send(data)
                        # print('plain_send:', len(data))
                        # self.l.debug(f"Send {len(data)} bytes to {self.proxy_type}. snum={snum}")
                    except (BrokenPipeError, ConnectionResetError, OSError) as e:
                        self.l.warning(f"handle_defended: Unexpected Shutdown. snum={snum}. e={e}")
                        self.unexpected_shutdown(s)

        except KeyboardInterrupt:
            m = "handle_defended: Keyboard Interrupt"
            print(m)
            self.l.info(m)
            self.shutdown()
            return
        
    def handle_new_incoming_connection(self, s):
        self.l.info("handle_new_incoming_connection: Called")
        client_socket, client_address = s.accept()
        snum = self.plain_socket_manager.get_new_slot(client_socket)
        if snum is None:
            self.l.error("New Slot Failed. Exiting...")
            self.run = False
        self.input_sockets.append(client_socket)
        self.l.info(f"Accepted connection from {client_address}. snum={snum}")

    def plain_recv(self, s):
        try:
            data = s.recv(MAX_RECV_SIZE)
            # print('plain_recv:', len(data))
            snum = self.plain_socket_manager.getSlotFromSocket(s)
            if snum is None: raise ConnectionResetError("Invalid Slot Number")
            # self.l.debug(f"Received {len(data)} bytes from {self.proxy_type}. snum={snum}")
            return snum, data
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            self.l.error(f"plain_recv: Unexpected Shutdown, e={e}")
            self.unexpected_shutdown(s)
            return None, None
        
    def handle_plain(self):
        try:
            while self.run:
                readable, _, _ = select.select(self.input_sockets, [], [], 30)
                for s in readable:
                    if s is self.pipe_r:
                        # Manual Rerun
                        os.read(self.pipe_r, 1)
                        self.l.debug('handle_plain: Pipe Read')
                        continue
                    if s is self.server_socket:
                        self.l.debug("Server Socket Readable")
                        if self.proxy_type == 'Client': self.handle_new_incoming_connection(s)
                    else:
                        snum, data = self.plain_recv(s)
                        if snum is None: continue
                        
                        if len(data) == 0:
                            self.handle_plain_shutdown(snum)
                        data = snum.to_bytes(1, byteorder='big') + data
                        self.ch_recv_queue.put_nowait(data)
                        self.l.debug(f"Send {len(data)} bytes to ClientCH. snum={snum}")
        except KeyboardInterrupt:
            m = "handle_plain: Keyboard Interrupt"
            print(m)
            self.l.info(m)
            self.shutdown()
            return
        
    def unexpected_shutdown(self, s):
        self.l.info("unexpected_shutdown: Called")
        if s in self.input_sockets: self.input_sockets.remove(s)
        try:
            s.close()
        except Exception:
            print(traceback.format_exc())
            pass
        snum = self.plain_socket_manager.getSlotFromSocket(s)
        if snum is None:
            self.l.error("unexptected_shutdown: Invalid Slot Number")
            return
        self.plain_socket_manager.release(snum)
        self.plain_socket_manager.special_close_communicate(snum)
        return
        
    def shutdown(self):
        self.run = False
        if self.pipe_w is not None:
            os.write(self.pipe_w, b'\x00')
        return
    
    def start(self):
        self.prestart()
        connection_handler = self.ConnectionHandler(recv_queue=self.ch_recv_queue, send_queue=self.ch_send_queue, params=params)
        defended_thread = threading.Thread(target=self.handle_defended)
        plain_thread = threading.Thread(target=self.handle_plain)
        defended_thread.start()
        plain_thread.start()
        try:
            connection_handler.start()
        except Exception:
            print(traceback.format_exc())
        self.l.info(f"{self.proxy_type}Proxy Closing...")
        self.shutdown()
        defended_thread.join()
        plain_thread.join()
        self.l.info(f"{self.proxy_type}Proxy Closed")

    
class ClientProxy(Proxy):
    def __init__(self, listen_addr, listen_port, forward_addr, forward_port):
        super().__init__(listen_addr, listen_port, forward_addr, forward_port, 'Client')
        self.ConnectionHandler = ClientProxyConnectionHandler
   
    def prestart(self):
        # Create a Listening Server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.listen_addr, self.listen_port))
        server_socket.listen(5)
        m = f"ClientProxy Started. Listening on {self.listen_addr}:{self.listen_port}"
        self.l.info(m)
        print(m)
        self.server_socket = server_socket
        self.input_sockets.append(server_socket)
        

class ServerProxy(Proxy):
    def __init__(self, listen_addr, listen_port, forward_addr, forward_port):
        super().__init__(listen_addr=listen_addr, listen_port=listen_port, forward_addr=forward_addr, forward_port=forward_port, proxy_type='Server')
        self.ConnectionHandler = ServerProxyConnectionHandler

    def prestart(self):
        pass
    
def mode_parser(mode):
    mode = mode.lower()
    if mode == "client" or mode=='c':
        return 'Client'
    elif mode == "server" or mode=='s':
        return 'Server'
    else:
        raise ValueError("Invalid mode")
    
def ip_parser(ip):
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return ip
    else:
        raise ValueError("Invalid IP address")

    
def main():
    parser = argparse.ArgumentParser(description='Proxy')
    parser.add_argument('-m', '--proxy-type', type=mode_parser, required=True)
    parser.add_argument('-l', '--listen-port', type=int, default=0)
    parser.add_argument('--listen-ip', type=ip_parser, default='127.0.0.1')
    parser.add_argument('--forward-ip', type=ip_parser, default='127.0.0.1')
    parser.add_argument('-f', '--forward-port', type=int, default=0)
    args = parser.parse_args()

    logging_level = logging.INFO if args.proxy_type == 'Client' else logging.DEBUG
    logging.basicConfig(level=logging_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', filename=f'ProxyLog_{args.proxy_type}.log', filemode='w')
    global SERVER_ADDR, SERVER_PORT
    if args.proxy_type == 'Client':
        listen_port = args.listen_port if args.listen_port != 0 else 8001
        forward_port = args.forward_port if args.forward_port != 0 else 8002
        SERVER_ADDR = args.forward_ip
        SERVER_PORT = forward_port
        print(args.proxy_type, listen_port, args.forward_ip, forward_port, flush=True)
        proxy = ClientProxy(listen_addr=args.listen_ip, listen_port=listen_port, forward_addr=args.forward_ip, forward_port=forward_port)
    elif args.proxy_type == 'Server':
        listen_port = args.listen_port if args.listen_port != 0 else 8002
        forward_port = args.forward_port if args.forward_port != 0 else 8003
        SERVER_ADDR = args.listen_ip
        SERVER_PORT = listen_port
        print(args.proxy_type, listen_port, args.forward_ip, forward_port)
        proxy = ServerProxy(listen_addr=args.listen_ip, listen_port=listen_port, forward_addr=args.forward_ip, forward_port=forward_port)
    else:
        raise ValueError("Invalid Proxy Type")
    proxy.start()


if __name__ == "__main__":
    main()

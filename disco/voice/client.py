from __future__ import print_function

import gevent
import socket
import struct
import heapq
import time

try:
    import nacl.secret
except ImportError:
    print('WARNING: nacl is not installed, voice support is disabled')

from holster.enum import Enum
from holster.emitter import Emitter

from disco.gateway.encoding.json import JSONEncoder
from disco.gateway.events import UserSpeaking, VoiceReceived
from disco.util.websocket import Websocket
from disco.util.logging import LoggingClass
from disco.voice.packets import VoiceOPCode
from disco.voice.opus import OpusDecoder
from disco.gateway.packets import OPCode

VoiceState = Enum(
    DISCONNECTED=0,
    AWAITING_ENDPOINT=1,
    AUTHENTICATING=2,
    CONNECTING=3,
    CONNECTED=4,
    VOICE_CONNECTING=5,
    VOICE_CONNECTED=6,
)


class VoiceException(Exception):
    def __init__(self, msg, client):
        self.voice_client = client
        super(VoiceException, self).__init__(msg)


class UDPVoiceClient(LoggingClass):
    # Struct format of the packet metadata
    _FORMAT = '>HHII'
    # Packets should start with b'\x80\x78' (32888 as a big endian ushort)
    _CHECK = 32888
    # Some packets will start with b'\x90\x78' (36984)
    _CHECK2 = 36984

    def __init__(self, vc):
        super(UDPVoiceClient, self).__init__()
        self.vc = vc

        # The underlying UDP socket
        self.conn = None

        # Connection information
        self.ip = None
        self.port = None

        self.run_task = None
        self.connected = False

        # Buffer used for encoding/sending frames
        self._buffer = bytearray(24)
        self._buffer[0] = 0x80
        self._buffer[1] = 0x78

        self._decoders = {}

    def send_frame(self, frame, sequence=None, timestamp=None):
        # Convert the frame to a bytearray
        frame = bytearray(frame)

        # Pack the rtc header into our buffer
        struct.pack_into('>H', self._buffer, 2, sequence or self.vc.sequence)
        struct.pack_into('>I', self._buffer, 4, timestamp or self.vc.timestamp)
        struct.pack_into('>i', self._buffer, 8, self.vc.ssrc)

        # Now encrypt the payload with the nonce as a header
        raw = self.vc.secret_box.encrypt(bytes(frame), bytes(self._buffer)).ciphertext

        # Send the header (sans nonce padding) plus the payload
        self.send(self._buffer[:12] + raw)

        # Increment our sequence counter
        self.vc.sequence += 1
        if self.vc.sequence >= 65535:
            self.vc.sequence = 0

    def run(self):
        while True:
            data, addr = self.conn.recvfrom(4096)

            # Check the packet size
            if len(data) < 13:
                raise ValueError('packet is too small: {}'.format(data))

            # Unpack header
            check, seq, ts, ssrc = struct.unpack_from(self._FORMAT, data)
            header = data[:12]
            buff = data[12:]

            # Check the packet is valid
            if check != self._CHECK and check != self._CHECK2:
                fmt = 'packet has invalid check bytes: {}'
                raise ValueError(fmt.format(data))

            # Decrypt data
            nonce = bytearray(24)
            nonce[:12] = header
            buff = self.vc.secret_box.decrypt(bytes(buff), bytes(nonce))

            if buff[0] == 0xBE and buff[1] == 0xDE:  # RFC5285 Section 4.2: One-Byte Header
                # Please note: This has been added to future-proof the code however I have been
                # unable to find any voice clients that are using the one-byte headers. As such,
                # this code is untested but should work.
                rtp_header_extension_length = buff[2] << 8 | buff[3]
                index = 4
                for i in range(rtp_header_extension_length):
                    byte = buff[index]
                    index += 1
                    if byte == 0:
                        continue

                    l = (byte & 0b1111) + 1
                    index += l

                while buff[index] == 0:
                    index += 1

                buff = buff[index:]
            elif check == self._CHECK2:
                # Packets starting with b'\x90' need the first 8 bytes ignored BecauseDiscord(tm)
                buff = buff[8:]

            if ssrc not in self._decoders:
                self._decoders[ssrc] = OpusDecoder(48000, 2)

            # Lookup the SSRC and then get the user
            user_id = 0
            member = None

            if ssrc in self.vc.ssrc_lookup:
                user_id = int(self.vc.ssrc_lookup[ssrc])

                member = self.vc.channel.guild.get_member(user_id)
            else:
                self.log.warning('User speaking was unknown! Dropping packet.')
                return

            buff = self._decoders[ssrc].decode(buff)

            obj = VoiceReceived()
            obj.member = member
            obj.channel = self.vc.channel
            obj.voice_data = buff
            obj.timestamp = ts
            obj.sequence = seq

            self.vc.client.gw.events.emit('VoiceReceived', obj)

            for cb in self.vc.pcm_listeners:
                cb(obj)

    def send(self, data):
        self.conn.sendto(data, (self.ip, self.port))

    def disconnect(self):
        self.run_task.kill()

    def connect(self, host, port, timeout=10, addrinfo=None):
        self.ip = socket.gethostbyname(host)
        self.port = port

        self.conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        if addrinfo:
            ip, port = addrinfo
        else:
            # Send discovery packet
            packet = bytearray(70)
            struct.pack_into('>I', packet, 0, self.vc.ssrc)
            self.send(packet)

            # Wait for a response
            try:
                data, addr = gevent.spawn(lambda: self.conn.recvfrom(70)).get(timeout=timeout)
            except gevent.Timeout:
                return (None, None)

            # Read IP and port
            ip = str(data[4:]).split('\x00', 1)[0]
            port = struct.unpack('<H', data[-2:])[0]

        # Spawn read thread so we don't max buffers
        self.connected = True
        self.run_task = gevent.spawn(self.run)

        return (ip, port)


class VoiceClient(LoggingClass):
    def __init__(self, channel, encoder=None):
        super(VoiceClient, self).__init__()

        if not channel.is_voice:
            raise ValueError('Cannot spawn a VoiceClient for a non-voice channel')

        self.channel = channel
        self.client = self.channel.client
        self.encoder = encoder or JSONEncoder

        # Bind to some WS packets
        self.packets = Emitter(spawn_each=True)
        self.packets.on(VoiceOPCode.READY, self.on_voice_ready)
        self.packets.on(VoiceOPCode.SESSION_DESCRIPTION, self.on_voice_sdp)
        self.packets.on(VoiceOPCode.SPEAKING, self.on_voice_speaking)

        # State + state change emitter
        self.state = VoiceState.DISCONNECTED
        self.state_emitter = Emitter(spawn_each=True)

        # Connection metadata
        self.token = None
        self.endpoint = None
        self.ssrc = None
        self.port = None
        self.secret_box = None
        self.udp = None

        # Voice data state
        self.sequence = 0
        self.timestamp = 0

        self.update_listener = None
        self.ssrc_lookup = {}

        self.pcm_listeners = []
        self.speaking_listeners = []

        # Websocket connection
        self.ws = None
        self.heartbeat_task = None

    def __repr__(self):
        return u'<VoiceClient {}>'.format(self.channel)

    def set_state(self, state):
        self.log.debug('[%s] state %s -> %s', self, self.state, state)
        prev_state = self.state
        self.state = state
        self.state_emitter.emit(state, prev_state)

    def heartbeat(self, interval):
        while True:
            self.send(VoiceOPCode.HEARTBEAT, time.time() * 1000)
            gevent.sleep(interval / 1000)

    def set_speaking(self, value):
        self.send(VoiceOPCode.SPEAKING, {
            'speaking': value,
            'delay': 0,
        })

    def send(self, op, data):
        self.log.debug('[%s] sending OP %s (data = %s)', self, op, data)
        self.ws.send(self.encoder.encode({
            'op': op.value,
            'd': data,
        }), self.encoder.OPCODE)

    def pipe_voice_into_file(self, member, file_object, buffer_size=0.2):
        # Convert buffer_size from seconds to packets.
        buffer_size = int(round((buffer_size * 1000) / 20))

        SAMPLE_RATE = 48000
        SAMPLE_SIZE = 2

        user_id = member.id

        state = {'last_packet': 0, 'voice_buffer': [], 'last_speaking': 0}

        def listener(vp):
            if user_id == (None if vp.member is None else vp.member.id):
                state['last_packet'] = vp.timestamp
                heapq.heappush(state['voice_buffer'], (vp.timestamp, vp))

                if len(state['voice_buffer']) > buffer_size:
                    packet = heapq.heappop(state['voice_buffer'])[1]

                    if state['last_packet'] == 0:
                        delta = 0
                    else:
                        delta = (packet.timestamp - state['last_packet']) + 9600

                    print(delta, state['last_packet'])

                    if delta >= 0:  # Ignore skipped packets
                        data = bytearray([0] * delta * 4)
                        print(packet.voice_data)
                        data += packet.voice_data

                        file_object.write(data)

                    state['last_packet'] = packet.timestamp

        def speaking_listener(uid, speaking):
            if uid == user_id:
                if speaking:
                    if state['last_speaking'] != 0:
                        delta = time.time() - state['last_speaking']
                        padding = bytearray([0] * int(delta * SAMPLE_RATE) * SAMPLE_SIZE)
                        file_object.write(padding)

                        state['last_speaking'] = 0
                else:
                    state['last_speaking'] = time.time()

        self.pcm_listeners.append(listener)
        self.speaking_listeners.append(speaking_listener)

    def on_voice_speaking(self, data):
        self.ssrc_lookup[data['ssrc']] = data['user_id']

        obj = UserSpeaking()
        obj.member = self.channel.guild.get_member(int(data['user_id']))
        obj.speaking = data['speaking']
        obj.channel = self.channel

        for cb in self.speaking_listeners:
            cb(int(data['user_id']), data['speaking'])

        self.client.gw.events.emit('UserSpeaking', obj)

    def on_voice_ready(self, data):
        self.log.info('[%s] Recived Voice READY payload, attempting to negotiate voice connection w/ remote', self)
        self.set_state(VoiceState.CONNECTING)
        self.ssrc = data['ssrc']
        self.port = data['port']

        self.heartbeat_task = gevent.spawn(self.heartbeat, data['heartbeat_interval'])

        self.log.debug('[%s] Attempting IP discovery over UDP to %s:%s', self, self.endpoint, self.port)
        self.udp = UDPVoiceClient(self)
        ip, port = self.udp.connect(self.endpoint, self.port)

        if not ip:
            self.log.error('Failed to discover our IP, perhaps a NAT or firewall is fucking us')
            self.disconnect()
            return

        self.log.debug('[%s] IP discovery completed (ip = %s, port = %s), sending SELECT_PROTOCOL', self, ip, port)
        self.send(VoiceOPCode.SELECT_PROTOCOL, {
            'protocol': 'udp',
            'data': {
                'port': port,
                'address': ip,
                'mode': 'xsalsa20_poly1305',
            },
        })

    def on_voice_sdp(self, sdp):
        self.log.info('[%s] Recieved session description, connection completed', self)
        # Create a secret box for encryption/decryption
        self.secret_box = nacl.secret.SecretBox(bytes(bytearray(sdp['secret_key'])))

        # Toggle speaking state so clients learn of our SSRC
        self.set_speaking(True)
        self.set_speaking(False)
        gevent.sleep(0.25)

        self.set_state(VoiceState.CONNECTED)

    def on_voice_server_update(self, data):
        if self.channel.guild_id != data.guild_id or not data.token:
            return

        if self.token and self.token != data.token:
            return

        self.log.info('[%s] Recieved VOICE_SERVER_UPDATE (state = %s / endpoint = %s)', self, self.state, data.endpoint)

        self.token = data.token
        self.set_state(VoiceState.AUTHENTICATING)

        self.endpoint = data.endpoint.split(':', 1)[0]
        self.ws = Websocket('wss://' + self.endpoint)
        self.ws.emitter.on('on_open', self.on_open)
        self.ws.emitter.on('on_error', self.on_error)
        self.ws.emitter.on('on_close', self.on_close)
        self.ws.emitter.on('on_message', self.on_message)
        self.ws.run_forever()

    def on_message(self, msg):
        try:
            data = self.encoder.decode(msg)
            self.packets.emit(VoiceOPCode[data['op']], data['d'])
        except Exception:
            self.log.exception('Failed to parse voice gateway message: ')

    def on_error(self, err):
        self.log.error('[%s] Voice websocket error: %s', self, err)

    def on_open(self):
        self.send(VoiceOPCode.IDENTIFY, {
            'server_id': self.channel.guild_id,
            'user_id': self.client.state.me.id,
            'session_id': self.client.gw.session_id,
            'token': self.token,
        })

    def on_close(self, code, error):
        self.log.warning('[%s] Voice websocket disconnected (%s, %s)', self, code, error)

        if self.state == VoiceState.CONNECTED:
            self.log.info('Attempting voice reconnection')
            self.connect()

    def connect(self, timeout=5, mute=False, deaf=False):
        self.log.debug('[%s] Attempting connection', self)
        self.set_state(VoiceState.AWAITING_ENDPOINT)

        self.update_listener = self.client.events.on('VoiceServerUpdate', self.on_voice_server_update)

        self.client.gw.send(OPCode.VOICE_STATE_UPDATE, {
            'self_mute': mute,
            'self_deaf': deaf,
            'guild_id': int(self.channel.guild_id),
            'channel_id': int(self.channel.id),
        })

        if not self.state_emitter.once(VoiceState.CONNECTED, timeout=timeout):
            raise VoiceException('Failed to connect to voice', self)

    def disconnect(self):
        self.log.debug('[%s] disconnect called', self)
        self.set_state(VoiceState.DISCONNECTED)

        if self.heartbeat_task:
            self.heartbeat_task.kill()
            self.heartbeat_task = None

        if self.ws and self.ws.sock.connected:
            self.ws.close()

        if self.udp and self.udp.connected:
            self.udp.disconnect()

        self.client.gw.send(OPCode.VOICE_STATE_UPDATE, {
            'self_mute': False,
            'self_deaf': False,
            'guild_id': int(self.channel.guild_id),
            'channel_id': None,
        })

    def send_frame(self, *args, **kwargs):
        self.udp.send_frame(*args, **kwargs)

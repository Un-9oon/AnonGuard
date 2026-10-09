#!/usr/bin/python3 -I
"""Linux IPv4 transparent TCP and local DNS-over-TLS adapter to loopback AnonGuard SOCKS.

Requires the separately installed native firewall. No direct destination fallback.
"""
import asyncio
import ipaddress
import secrets
import socket
import ssl
import struct

MAX_DNS = 4096
DNS_CONCURRENCY = 32
TCP_CONCURRENCY = 128
SOCKS_PORT = 9050
TCP_PORT = 9040
DNS_PORT = 1053
DNS_RESOLVER = '1.1.1.1'
DNS_TLS_NAME = 'cloudflare-dns.com'
# One opaque local label per adapter process; separate from browser NOAUTH contexts.
CONTEXT = secrets.token_bytes(32)


def original_destination(sock):
    # Linux SO_ORIGINAL_DST: native sockaddr family, network-order port/address.
    data = sock.getsockopt(socket.SOL_IP, 80, 16)
    if len(data) != 16 or struct.unpack_from('=H', data)[0] != socket.AF_INET:
        raise ValueError('Unsupported original destination metadata')
    host = socket.inet_ntoa(data[4:8])
    port = struct.unpack_from('!H', data, 2)[0]
    if not ipaddress.IPv4Address(host).is_global or port == 0:
        raise ValueError('Transparent destination must be public IPv4')
    return host, port


async def close(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 2)
    except (OSError, asyncio.TimeoutError):
        pass


async def socks_connect(host, port, proxy_port=SOCKS_PORT):
    address = ipaddress.IPv4Address(host)
    if not address.is_global or not 1 <= port <= 65535:
        raise ValueError('SOCKS target must be public IPv4')
    reader, writer = await asyncio.open_connection('127.0.0.1', proxy_port)
    try:
        writer.write(b'\x05\x01\x02')
        await writer.drain()
        if await reader.readexactly(2) != b'\x05\x02':
            raise ValueError('Local SOCKS context method rejected')
        writer.write(b'\x01' + bytes([len(CONTEXT)]) + CONTEXT + b'\x01\x01')
        await writer.drain()
        if await reader.readexactly(2) != b'\x01\x00':
            raise ValueError('Local SOCKS context rejected')
        writer.write(b'\x05\x01\x00\x01' + address.packed + struct.pack('!H', port))
        await writer.drain()
        header = await reader.readexactly(4)
        if header[:3] != b'\x05\x00\x00':
            raise ValueError('Local SOCKS connection rejected')
        if header[3] == 1:
            await reader.readexactly(6)
        elif header[3] == 4:
            await reader.readexactly(18)
        elif header[3] == 3:
            length = (await reader.readexactly(1))[0]
            if length == 0:
                raise ValueError('Invalid SOCKS bound address')
            await reader.readexactly(length + 2)
        else:
            raise ValueError('Invalid SOCKS bound address type')
        return reader, writer
    except BaseException:
        await close(writer)
        raise


def dns_question(query):
    if not 12 <= len(query) <= MAX_DNS:
        raise ValueError('DNS size outside bounds')
    _, flags, qd, an, ns, ar = struct.unpack('!6H', query[:12])
    if flags & 0xF800 or qd != 1 or an or ns or ar > 1:
        raise ValueError('Unsupported DNS query header')
    offset = 12
    name_size = 0
    while True:
        if offset >= len(query):
            raise ValueError('Incomplete DNS question')
        length = query[offset]
        offset += 1
        name_size += length + 1
        if length > 63 or name_size > 255 or offset + length > len(query):
            raise ValueError('Invalid DNS question name')
        offset += length
        if length == 0:
            break
    if offset + 4 > len(query):
        raise ValueError('Missing DNS question type/class')
    offset += 4
    question = query[12:offset]
    udp_limit = 512
    if ar:
        # Only a single uncompressed OPT record is supported; no TSIG/other RR.
        if len(query) < offset + 11 or query[offset] != 0:
            raise ValueError('Invalid EDNS record')
        rr_type, payload, _, length = struct.unpack('!HHIH', query[offset + 1:offset + 11])
        if rr_type != 41 or len(query) != offset + 11 + length:
            raise ValueError('Unsupported DNS additional record')
        udp_limit = max(512, min(payload, 1232))
    elif len(query) != offset:
        raise ValueError('Trailing DNS bytes')
    return question, udp_limit


def dns_error(query, question, code=2, truncated=False):
    flags = struct.unpack('!H', query[2:4])[0]
    flags = 0x8000 | (flags & 0x0100) | 0x0080 | code | (0x0200 if truncated else 0)
    return query[:2] + struct.pack('!5H', flags, 1, 0, 0, 0) + question


def validate_response(query, response):
    question, _ = dns_question(query)
    if not 12 <= len(response) <= MAX_DNS:
        raise ValueError('DNS response size outside bounds')
    flags = struct.unpack('!H', response[2:4])[0]
    if response[:2] != query[:2] or not flags & 0x8000 or flags & 0x7800:
        raise ValueError('DNS response ID/opcode mismatch')
    if struct.unpack('!H', response[4:6])[0] != 1 or response[12:12 + len(question)] != question:
        raise ValueError('DNS response question mismatch')


async def dns_lookup(query):
    dns_question(query)
    reader, writer = await socks_connect(DNS_RESOLVER, 853)
    try:
        # Validate the resolver certificate end-to-end, including through an exit.
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        await writer.start_tls(context, server_hostname=DNS_TLS_NAME, ssl_handshake_timeout=10)
        writer.write(struct.pack('!H', len(query)) + query)
        await writer.drain()
        length = struct.unpack('!H', await reader.readexactly(2))[0]
        if not 12 <= length <= MAX_DNS:
            raise ValueError('DNS response size outside bounds')
        response = await reader.readexactly(length)
        validate_response(query, response)
        return response
    finally:
        await close(writer)


async def answer_dns(query, udp=False):
    question, limit = dns_question(query)
    try:
        response = await asyncio.wait_for(dns_lookup(query), 20)
        if udp and len(response) > limit:
            return dns_error(query, question, code=0, truncated=True)
        return response
    except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError):
        return dns_error(query, question)


class LocalDNS(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.tasks = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        if len(self.tasks) >= DNS_CONCURRENCY:
            return
        try:
            dns_question(data)
        except ValueError:
            return
        async def respond():
            response = await answer_dns(data, udp=True)
            if self.transport is not None:
                self.transport.sendto(response, peer)
        task = asyncio.create_task(respond())
        self.tasks.add(task)
        def completed(done):
            self.tasks.discard(done)
            if not done.cancelled():
                done.exception()  # Consume socket/transport shutdown failures.
        task.add_done_callback(completed)

    def connection_lost(self, _error):
        self.transport = None
        for task in tuple(self.tasks):
            task.cancel()


async def copy(source, destination):
    while True:
        block = await asyncio.wait_for(source.read(16384), 60)
        if not block:
            if destination.can_write_eof():
                destination.write_eof()
                await destination.drain()
            return
        destination.write(block)
        await destination.drain()


class Adapter:
    def __init__(self):
        self.tcp = asyncio.Semaphore(TCP_CONCURRENCY)
        self.dns = asyncio.Semaphore(DNS_CONCURRENCY)

    async def transparent(self, reader, writer):
        if self.tcp.locked():
            await close(writer)
            return
        upstream = None
        tasks = []
        try:
            async with self.tcp:
                host, port = original_destination(writer.get_extra_info('socket'))
                remote, upstream = await asyncio.wait_for(socks_connect(host, port), 15)
                tasks = [asyncio.create_task(copy(reader, upstream)),
                         asyncio.create_task(copy(remote, writer))]
                # Preserve TCP half-close; an error/lifetime deadline closes both sides.
                await asyncio.wait_for(asyncio.gather(*tasks), 300)
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if upstream is not None:
                await close(upstream)
            await close(writer)

    async def dns_tcp(self, reader, writer):
        if self.dns.locked():
            await close(writer)
            return
        try:
            async with self.dns:
                # One query per TCP session; clients can establish a fresh session.
                size = struct.unpack('!H', await asyncio.wait_for(reader.readexactly(2), 5))[0]
                if not 12 <= size <= MAX_DNS:
                    return
                query = await asyncio.wait_for(reader.readexactly(size), 5)
                response = await answer_dns(query)
                writer.write(struct.pack('!H', len(response)) + response)
                await asyncio.wait_for(writer.drain(), 5)
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        finally:
            await close(writer)


async def main():
    adapter = Adapter()
    tcp = await asyncio.start_server(adapter.transparent, '127.0.0.1', TCP_PORT, backlog=64)
    dns = None
    transport = None
    try:
        dns = await asyncio.start_server(adapter.dns_tcp, '127.0.0.1', DNS_PORT, backlog=32)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            LocalDNS, local_addr=('127.0.0.1', DNS_PORT))
        async with tcp, dns:
            await asyncio.gather(tcp.serve_forever(), dns.serve_forever())
    finally:
        tcp.close()
        if dns is not None:
            dns.close()
        if transport is not None:
            transport.close()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

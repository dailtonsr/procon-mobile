#!/usr/bin/env python3
"""
PRoCon Mobile — WebSocket ↔ PRoCon Layer Proxy
Deploy: Railway.app

Conecta ao PRoCon Layer (não direto ao RCON do BF4)
Login: username + password do Layer
"""

import asyncio
import hashlib
import json
import os
import struct
import traceback
import websockets
from websockets.server import serve

PORT = int(os.environ.get('PORT', 8080))

# ── FROSTBITE PACKET PROTOCOL ──────────────────────────────
HEADER = 12
_seq = 0

def mk_packet(words):
    global _seq
    _seq = (_seq + 1) & 0x3FFFFFFF
    body = b''
    for w in words:
        b = w.encode('utf-8') if isinstance(w, str) else w
        body += struct.pack('<I', len(b)) + b + b'\x00'
    hdr = struct.pack('<III', _seq, HEADER + len(body), len(words))
    return hdr + body, _seq

def parse_packets(buf):
    packets, rest = [], buf
    while len(rest) >= HEADER:
        seq, total, wcount = struct.unpack('<III', rest[:HEADER])
        if len(rest) < total:
            break
        words, off = [], HEADER
        for _ in range(wcount):
            if off + 4 > total: break
            wlen = struct.unpack('<I', rest[off:off+4])[0]
            off += 4
            words.append(rest[off:off+wlen].decode('utf-8','replace'))
            off += wlen + 1
        packets.append({
            'seq': seq & 0x3FFFFFFF,
            'resp': bool(seq & 0x80000000),
            'words': words
        })
        rest = rest[total:]
    return packets, rest

# ── WS HANDLER ─────────────────────────────────────────────
async def handler(ws):
    print(f"[+] Client: {ws.remote_address}")
    reader = writer = None
    buf = b''
    pending = {}

    async def rcon(*words):
        pkt, seq = mk_packet(list(words))
        fut = asyncio.get_event_loop().create_future()
        pending[seq] = fut
        writer.write(pkt)
        await writer.drain()
        try:
            return await asyncio.wait_for(fut, timeout=8.0)
        except asyncio.TimeoutError:
            pending.pop(seq, None)
            return ['error', 'timeout']

    async def recv_loop():
        nonlocal buf
        while True:
            try:
                chunk = await reader.read(8192)
                if not chunk:
                    break
                buf += chunk
                pkts, buf = parse_packets(buf)
                for p in pkts:
                    if p['resp'] and p['seq'] in pending:
                        pending.pop(p['seq']).set_result(p['words'])
                    else:
                        await on_event(p['words'])
            except Exception as e:
                print(f"[recv] {e}")
                break
        for f in pending.values():
            if not f.done():
                f.set_exception(Exception('disconnected'))

    async def on_event(words):
        if not words: return
        cmd = words[0]
        if cmd == 'player.onChat':
            await ws.send(json.dumps({
                'type': 'chat',
                'player': words[1] if len(words) > 1 else '?',
                'text':   words[2] if len(words) > 2 else '',
                'subset': words[3] if len(words) > 3 else 'All',
                'isAdmin': False
            }))
        elif cmd in ('player.onJoin', 'player.onLeave', 'player.onSpawn'):
            await refresh_players()

    async def refresh_players():
        r = await rcon('admin.listPlayers', 'all')
        players = parse_playerlist(r)
        await ws.send(json.dumps({'type': 'players', 'players': players}))

    async def refresh_info():
        r = await rcon('serverInfo')
        if r and r[0] == 'OK' and len(r) > 5:
            scores = {}
            try:
                scores = {
                    'team1': int(r[8]) if len(r) > 8 else 0,
                    'team2': int(r[9]) if len(r) > 9 else 0
                }
            except: pass
            await ws.send(json.dumps({
                'type': 'serverInfo',
                'serverName': r[1] if len(r) > 1 else '',
                'mapName':    r[4] if len(r) > 4 else '',
                'modeName':   r[5] if len(r) > 5 else '',
                'scores': scores,
            }))

    async def refresh_maplist():
        r = await rcon('mapList.list', '0')
        maps = []
        if r and r[0] == 'OK' and len(r) > 2:
            try:
                n = int(r[2]); idx = 3
                for _ in range(n):
                    if idx + 1 < len(r):
                        maps.append({'map': r[idx], 'mode': r[idx+1]})
                    idx += 3
            except: pass
        ci = await rcon('mapList.getMapIndices')
        cur = int(ci[1]) if ci and len(ci) > 1 else 0
        await ws.send(json.dumps({'type': 'mapList', 'maps': maps, 'currentIdx': cur}))

    def parse_playerlist(words):
        out = []
        if not words or words[0] != 'OK': return out
        try:
            fc = int(words[1])
            fields = words[2:2+fc]
            pc = int(words[2+fc])
            off = 3 + fc
            for i in range(pc):
                p = {fields[j]: words[off+i*fc+j]
                     for j in range(fc) if off+i*fc+j < len(words)}
                out.append({
                    'name':   p.get('name', ''),
                    'team':   int(p.get('teamId', '0')),
                    'squad':  int(p.get('squadId', '0')),
                    'kills':  int(p.get('kills', '0')),
                    'deaths': int(p.get('deaths', '0')),
                    'score':  int(p.get('score', '0')),
                    'ping':   int(p.get('ping', '0')),
                    'rank':   int(p.get('rank', '0')),
                })
        except Exception as e:
            print(f"[parse] {e}")
        return out

    # ── MAIN LOOP ───────────────────────────────────────────
    try:
        async for raw in ws:
            msg = json.loads(raw)

            # CONNECT — login via PRoCon Layer
            if msg['type'] == 'connect':
                host     = msg['host']
                port     = int(msg['port'])
                username = msg.get('username', 'admin')
                password = msg.get('pass', '')

                print(f"[→] Connecting to {host}:{port} as {username}")

                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=10)
                    print(f"[✓] TCP connected to {host}:{port}")
                except Exception as e:
                    await ws.send(json.dumps({
                        'type': 'error',
                        'message': f'Cannot connect to {host}:{port} — {e}'
                    }))
                    continue

                asyncio.ensure_future(recv_loop())

                # PRoCon Layer login: login.hashed → MD5(salt + MD5(password))
                r1 = await rcon('login.hashed')
                if not r1 or r1[0] != 'OK' or len(r1) < 2:
                    await ws.send(json.dumps({
                        'type': 'error',
                        'message': 'Handshake failed — server did not respond'
                    }))
                    continue

                salt = r1[1]
                print(f"[→] Salt received: {salt}")

                # PRoCon Layer: hash = MD5(salt + MD5(password))
                # Primeiro MD5 da senha
                pass_md5 = hashlib.md5(password.encode('utf-8')).hexdigest().upper()
                # Segundo MD5: salt (hex) + pass_md5
                try:
                    final_hash = hashlib.md5(
                        bytes.fromhex(salt) + pass_md5.encode('utf-8')
                    ).hexdigest().upper()
                except Exception:
                    # Fallback: salt como string
                    final_hash = hashlib.md5(
                        (salt + pass_md5).encode('utf-8')
                    ).hexdigest().upper()

                r2 = await rcon('login.hashed', final_hash)
                print(f"[→] Login response: {r2}")

                if not r2 or r2[0] != 'OK':
                    # Tenta método alternativo: MD5(salt + password) direto
                    try:
                        alt_hash = hashlib.md5(
                            bytes.fromhex(salt) + password.encode('utf-8')
                        ).hexdigest().upper()
                        r2b = await rcon('login.hashed', alt_hash)
                        print(f"[→] Alt login response: {r2b}")
                        if r2b and r2b[0] == 'OK':
                            r2 = r2b
                        else:
                            await ws.send(json.dumps({
                                'type': 'error',
                                'message': f'Wrong username or password'
                            }))
                            continue
                    except Exception as e:
                        await ws.send(json.dumps({
                            'type': 'error',
                            'message': f'Login failed: {e}'
                        }))
                        continue

                await rcon('admin.eventsEnabled', 'true')

                ri = await rcon('serverInfo')
                sname = ri[1] if ri and len(ri) > 1 else host

                await ws.send(json.dumps({
                    'type': 'connected',
                    'serverName': sname
                }))
                print(f"[✓] Authenticated as {username} — {sname}")

                await refresh_players()
                await refresh_info()
                await refresh_maplist()

            # COMMAND
            elif msg['type'] == 'cmd':
                if not writer:
                    await ws.send(json.dumps({
                        'type': 'error', 'message': 'Not connected'
                    }))
                    continue
                cmd  = msg.get('cmd', '')
                args = msg.get('args', [])
                r = await rcon(cmd, *args)
                await ws.send(json.dumps({
                    'type': 'cmdResult',
                    'result': ' '.join(r) if r else 'no response',
                    'ok': bool(r and r[0] == 'OK')
                }))

    except websockets.exceptions.ConnectionClosed:
        print(f"[-] Client disconnected")
    except Exception as e:
        print(f"[!] Error: {e}")
        traceback.print_exc()
    finally:
        if writer:
            try: writer.close()
            except: pass

# ── MAIN ───────────────────────────────────────────────────
async def main():
    print(f"PRoCon Proxy — porta {PORT}")
    async with serve(handler, '0.0.0.0', PORT):
        await asyncio.Future()

if __name__ == '__main__':
    asyncio.run(main())

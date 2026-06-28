#!/usr/bin/env python3
import asyncio, hashlib, json, os, struct, traceback, websockets
from websockets.server import serve
PORT = int(os.environ.get('PORT', 8080))
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
        if len(rest) < total: break
        words, off = [], HEADER
        for _ in range(wcount):
            if off + 4 > total: break
            wlen = struct.unpack('<I', rest[off:off+4])[0]; off += 4
            words.append(rest[off:off+wlen].decode('utf-8','replace')); off += wlen + 1
        packets.append({'seq': seq & 0x3FFFFFFF, 'resp': bool(seq & 0x80000000), 'words': words})
        rest = rest[total:]
    return packets, rest

async def read_first(reader, timeout=5.0):
    try:
        chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        if not chunk: return None
        pkts, _ = parse_packets(chunk)
        if pkts:
            print(f"[first] {pkts[0]['words']}")
            return pkts[0]
    except asyncio.TimeoutError:
        print(f"[first] timeout — server silent")
    return None

async def handler(ws):
    print(f"[+] {ws.remote_address}")
    reader = writer = None
    buf = b''
    pending = {}

    async def send_cmd(*words, timeout=20.0):
        pkt, seq = mk_packet(list(words))
        fut = asyncio.get_event_loop().create_future()
        pending[seq] = fut
        writer.write(pkt); await writer.drain()
        try: return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            pending.pop(seq, None); print(f"[timeout] {words[0]}"); return None

    async def recv_loop():
        nonlocal buf
        while True:
            try:
                chunk = await reader.read(8192)
                if not chunk: break
                buf += chunk
                pkts, buf = parse_packets(buf)
                for p in pkts:
                    if p['resp'] and p['seq'] in pending:
                        pending.pop(p['seq']).set_result(p['words'])
                    else:
                        await on_event(p['words'])
            except Exception as e: print(f"[recv] {e}"); break
        for f in pending.values():
            if not f.done(): f.set_exception(Exception('disconnected'))

    async def on_event(words):
        if not words: return
        if words[0] == 'player.onChat':
            await ws.send(json.dumps({'type':'chat','player':words[1] if len(words)>1 else '?',
                'text':words[2] if len(words)>2 else '','subset':words[3] if len(words)>3 else 'All','isAdmin':False}))
        elif words[0] in ('player.onJoin','player.onLeave'):
            r = await send_cmd('admin.listPlayers','all')
            if r: await ws.send(json.dumps({'type':'players','players':parse_pl(r)}))

    def parse_pl(words):
        out = []
        if not words or words[0]!='OK': return out
        try:
            fc=int(words[1]); fields=words[2:2+fc]; pc=int(words[2+fc]); off=3+fc
            for i in range(pc):
                p={fields[j]:words[off+i*fc+j] for j in range(fc) if off+i*fc+j<len(words)}
                out.append({'name':p.get('name',''),'team':int(p.get('teamId','0')),
                    'squad':int(p.get('squadId','0')),'kills':int(p.get('kills','0')),
                    'deaths':int(p.get('deaths','0')),'score':int(p.get('score','0')),
                    'ping':int(p.get('ping','0')),'rank':int(p.get('rank','0'))})
        except Exception as e: print(f"[parse] {e}")
        return out

    try:
        async for raw in ws:
            msg = json.loads(raw)
            if msg['type'] == 'connect':
                host=msg['host']; port=int(msg['port']); password=msg.get('pass','')
                print(f"[→] {host}:{port}")
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=15)
                    print(f"[✓] TCP connected")
                except Exception as e:
                    await ws.send(json.dumps({'type':'error','message':f'Cannot connect: {e}'})); continue

                # Escuta primeiro pacote do servidor
                first = await read_first(reader, timeout=5.0)
                salt = None

                if first and first['words']:
                    words = first['words']
                    print(f"[first words] {words}")
                    if words[0] == 'login.hashed' and len(words) >= 2:
                        # Servidor enviou salt diretamente
                        salt = words[1]
                        print(f"[✓] Server sent salt: {salt}")
                        asyncio.ensure_future(recv_loop())
                    else:
                        asyncio.ensure_future(recv_loop())
                        r1 = await send_cmd('login.hashed', timeout=20.0)
                        print(f"[login.hashed] {r1}")
                        if r1 and r1[0]=='OK' and len(r1)>=2:
                            salt = r1[1]
                else:
                    # Servidor não mandou nada — cliente fala primeiro
                    asyncio.ensure_future(recv_loop())
                    r1 = await send_cmd('login.hashed', timeout=20.0)
                    print(f"[login.hashed after silence] {r1}")
                    if r1 and r1[0]=='OK' and len(r1)>=2:
                        salt = r1[1]

                if not salt:
                    await ws.send(json.dumps({'type':'error','message':'Could not get salt from server'})); continue

                hashed = hashlib.md5(bytes.fromhex(salt)+password.encode('utf-8')).hexdigest().upper()
                r2 = await send_cmd('login.hashed', hashed, timeout=15.0)
                print(f"[login result] {r2}")

                if not r2 or r2[0]!='OK':
                    await ws.send(json.dumps({'type':'error','message':'Wrong password'})); continue

                await send_cmd('admin.eventsEnabled','true')
                ri = await send_cmd('serverInfo')
                sname = ri[1] if ri and len(ri)>1 else host
                await ws.send(json.dumps({'type':'connected','serverName':sname}))
                print(f"[✓] Auth OK — {sname}")

                r=await send_cmd('admin.listPlayers','all')
                if r: await ws.send(json.dumps({'type':'players','players':parse_pl(r)}))

                r=await send_cmd('serverInfo')
                if r and r[0]=='OK' and len(r)>5:
                    scores={}
                    try: scores={'team1':int(r[8]) if len(r)>8 else 0,'team2':int(r[9]) if len(r)>9 else 0}
                    except: pass
                    await ws.send(json.dumps({'type':'serverInfo','serverName':r[1] if len(r)>1 else '',
                        'mapName':r[4] if len(r)>4 else '','modeName':r[5] if len(r)>5 else '','scores':scores}))

                r=await send_cmd('mapList.list','0')
                maps=[]
                if r and r[0]=='OK' and len(r)>2:
                    try:
                        n=int(r[2]); idx=3
                        for _ in range(n):
                            if idx+1<len(r): maps.append({'map':r[idx],'mode':r[idx+1]})
                            idx+=3
                    except: pass
                ci=await send_cmd('mapList.getMapIndices')
                cur=int(ci[1]) if ci and len(ci)>1 else 0
                await ws.send(json.dumps({'type':'mapList','maps':maps,'currentIdx':cur}))

            elif msg['type']=='cmd':
                if not writer:
                    await ws.send(json.dumps({'type':'error','message':'Not connected'})); continue
                r=await send_cmd(msg.get('cmd',''),*msg.get('args',[]))
                await ws.send(json.dumps({'type':'cmdResult',
                    'result':' '.join(r) if r else 'no response','ok':bool(r and r[0]=='OK')}))

    except websockets.exceptions.ConnectionClosed: print(f"[-] Disconnected")
    except Exception as e: print(f"[!] {e}"); traceback.print_exc()
    finally:
        if writer:
            try: writer.close()
            except: pass

async def main():
    print(f"PRoCon Proxy — porta {PORT}")
    async with serve(handler, '0.0.0.0', PORT):
        await asyncio.Future()

if __name__ == '__main__':
    asyncio.run(main())

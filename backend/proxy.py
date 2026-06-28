#!/usr/bin/env python3
import asyncio, hashlib, json, os, struct, traceback, websockets
from websockets.server import serve
PORT = int(os.environ.get("PORT", 8080))
HEADER = 12

def mk_packet(seq, words):
    body = b""
    for w in words:
        b = w.encode("utf-8") if isinstance(w, str) else w
        body += struct.pack("<I", len(b)) + b + b"\x00"
    hdr = struct.pack("<III", seq & 0x3FFFFFFF, HEADER + len(body), len(words))
    return hdr + body

def parse_packets(buf):
    packets, rest = [], buf
    while len(rest) >= HEADER:
        seq, total, wcount = struct.unpack("<III", rest[:HEADER])
        if len(rest) < total: break
        words, off = [], HEADER
        for _ in range(wcount):
            if off + 4 > total: break
            wlen = struct.unpack("<I", rest[off:off+4])[0]; off += 4
            words.append(rest[off:off+wlen].decode("utf-8","replace")); off += wlen + 1
        packets.append({"seq": seq & 0x3FFFFFFF, "resp": bool(seq & 0x40000000), "words": words})
        rest = rest[total:]
    return packets, rest

def compute_hash(salt_hex, password):
    salt_bytes = bytes.fromhex(salt_hex)
    final = hashlib.md5(salt_bytes + password.encode("utf-8")).hexdigest().upper()
    print(f"[hash] {final[:8]}...")
    return final

async def handler(ws):
    print(f"[+] {ws.remote_address}")
    reader = writer = None
    buf = b""
    pending = {}
    seq_counter = [0]
    connected = [False]
    host = port = password = username = None

    async def send_cmd(*words, timeout=15.0):
        if not writer:
            return None
        seq_counter[0] = (seq_counter[0] + 1) & 0x3FFFFFFF
        seq = seq_counter[0]
        pkt = mk_packet(seq, list(words))
        fut = asyncio.get_event_loop().create_future()
        pending[seq] = fut
        try:
            writer.write(pkt); await writer.drain()
            print(f"[>>] {words[0]}")
            result = await asyncio.wait_for(fut, timeout=timeout)
            print(f"[<<] {result[:3] if result else result}")
            return result
        except asyncio.TimeoutError:
            pending.pop(seq, None)
            print(f"[timeout] {words[0]}")
            return None
        except Exception as e:
            pending.pop(seq, None)
            print(f"[send_cmd error] {e}")
            return None

    async def recv_loop():
        nonlocal buf
        while True:
            try:
                chunk = await reader.read(8192)
                if not chunk: break
                buf += chunk
                pkts, buf = parse_packets(buf)
                for p in pkts:
                    if p["resp"] and p["seq"] in pending:
                        f = pending.pop(p["seq"])
                        if not f.done(): f.set_result(p["words"])
                    else:
                        await on_event(p["words"])
            except Exception as e:
                print(f"[recv] {e}"); break
        print("[recv_loop] encerrado")
        for f in pending.values():
            if not f.done(): f.set_exception(Exception("disconnected"))
        pending.clear()

    async def on_event(words):
        if not words: return
        if words[0] == "player.onChat":
            try:
                await ws.send(json.dumps({"type":"chat",
                    "player": words[1] if len(words)>1 else "?",
                    "text":   words[2] if len(words)>2 else "",
                    "subset": words[3] if len(words)>3 else "All",
                    "isAdmin": False}))
            except: pass
        elif words[0] in ("player.onJoin","player.onLeave","player.onTeamChange"):
            r = await send_cmd("admin.listPlayers","all")
            if r:
                try: await ws.send(json.dumps({"type":"players","players":parse_pl(r)}))
                except: pass
        elif words[0] == "server.onLevelLoaded":
            try:
                await ws.send(json.dumps({"type":"event","event":"levelLoaded",
                    "map": words[1] if len(words)>1 else "",
                    "mode": words[2] if len(words)>2 else ""}))
            except: pass

    def parse_pl(words):
        out = []
        if not words or words[0] != "OK": return out
        try:
            fc = int(words[1]); fields = words[2:2+fc]
            pc = int(words[2+fc]); off = 3+fc
            for i in range(pc):
                p = {fields[j]: words[off+i*fc+j] for j in range(fc) if off+i*fc+j < len(words)}
                out.append({"name":p.get("name",""),"guid":p.get("guid",""),
                    "team":int(p.get("teamId","0")),"squad":int(p.get("squadId","0")),
                    "kills":int(p.get("kills","0")),"deaths":int(p.get("deaths","0")),
                    "score":int(p.get("score","0")),"ping":int(p.get("ping","0")),
                    "rank":int(p.get("rank","0")),"type":p.get("type","0")})
        except Exception as e: print(f"[parse_pl] {e}")
        return out

    async def do_auth():
        nonlocal reader, writer, buf
        seq_counter[0] = 0
        buf = b""
        pending.clear()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=15)
            print("[OK] TCP")
        except Exception as e:
            return False, f"TCP falhou: {e}"

        asyncio.ensure_future(recv_loop())

        r0 = await send_cmd("version", timeout=10.0)
        if not r0 or r0[0] != "OK": return False, f"version falhou: {r0}"
        r1 = await send_cmd("procon.login.username", username, timeout=10.0)
        if not r1 or r1[0] != "OK": return False, f"username falhou: {r1}"
        r2 = await send_cmd("login.hashed", timeout=10.0)
        if not r2 or r2[0] != "OK" or len(r2) < 2: return False, f"salt falhou: {r2}"
        salt = r2[1]; print(f"[salt] {salt}")
        hashed = compute_hash(salt, password)
        r3 = await send_cmd("login.hashed", hashed, timeout=15.0)
        if not r3 or r3[0] != "OK": return False, "Senha incorreta"
        print("[AUTH OK]")
        return True, None

    async def load_initial_data():
        await send_cmd("admin.eventsEnabled","true")
        ri = await send_cmd("serverInfo")
        sname = ri[1] if ri and len(ri)>1 else host
        try: await ws.send(json.dumps({"type":"connected","serverName":sname}))
        except: pass

        r = await send_cmd("admin.listPlayers","all")
        if r:
            try: await ws.send(json.dumps({"type":"players","players":parse_pl(r)}))
            except: pass

        r = await send_cmd("serverInfo")
        if r and r[0]=="OK":
            scores={}
            try: scores={"team1":int(r[8]) if len(r)>8 else 0,"team2":int(r[9]) if len(r)>9 else 0}
            except: pass
            try: await ws.send(json.dumps({"type":"serverInfo",
                "serverName":r[1] if len(r)>1 else "",
                "mapName":r[4] if len(r)>4 else "",
                "modeName":r[5] if len(r)>5 else "",
                "maxPlayers":int(r[7]) if len(r)>7 else 32,
                "scores":scores}))
            except: pass

        r = await send_cmd("mapList.list","0")
        maps = []
        if r and r[0]=="OK" and len(r)>2:
            try:
                n=int(r[2]); idx=3
                for _ in range(n):
                    if idx+1<len(r): maps.append({"map":r[idx],"mode":r[idx+1]})
                    idx+=3
            except: pass
        ci = await send_cmd("mapList.getMapIndices")
        cur = int(ci[1]) if ci and len(ci)>1 else 0
        try: await ws.send(json.dumps({"type":"mapList","maps":maps,"currentIdx":cur}))
        except: pass

        rb = await send_cmd("banList.list","0")
        bans = []
        if rb and rb[0]=="OK":
            try:
                i=1
                while i+4<len(rb):
                    bans.append({"idType":rb[i],"id":rb[i+1],"banType":rb[i+2],"time":rb[i+3],"reason":rb[i+5] if i+5<len(rb) else ""})
                    i+=6
            except: pass
        try: await ws.send(json.dumps({"type":"banList","bans":bans}))
        except: pass

        rr = await send_cmd("reservedSlotsList.list")
        slots = [rr[i] for i in range(1,len(rr)) if rr[i]] if rr and rr[0]=="OK" else []
        try: await ws.send(json.dumps({"type":"reservedSlots","slots":slots}))
        except: pass

        # Plugins via PRoCon Layer
        rp = await send_cmd("procon.plugin.list")
        plugins = []
        if rp and rp[0]=="OK":
            try:
                print(f"[plugins raw] {rp[:10]}")
                # formato: OK <count> <name> <enabled> <version> ...
                pc2 = int(rp[1])
                for i in range(pc2):
                    base = 2 + i*3
                    if base+2 < len(rp):
                        plugins.append({
                            "name": rp[base],
                            "enabled": rp[base+1].lower() == "true",
                            "version": rp[base+2]
                        })
            except Exception as e:
                print(f"[plugins parse] {e}")
        else:
            print(f"[plugins] resposta: {rp}")
        try: await ws.send(json.dumps({"type":"plugins","plugins":plugins}))
        except: pass

    try:
        async for raw in ws:
            msg = json.loads(raw)

            if msg["type"] == "connect":
                host     = msg["host"]
                port     = int(msg["port"])
                password = msg.get("pass","")
                username = msg.get("username","admin")
                print(f"[->] {host}:{port}")

                ok, err = await do_auth()
                if not ok:
                    try: await ws.send(json.dumps({"type":"error","message":err}))
                    except: pass
                    continue

                connected[0] = True
                await load_initial_data()

            elif msg["type"] == "cmd":
                if not writer:
                    try: await ws.send(json.dumps({"type":"error","message":"Não conectado"}))
                    except: pass
                    continue
                r = await send_cmd(msg.get("cmd",""), *msg.get("args",[]))
                try: await ws.send(json.dumps({"type":"cmdResult",
                    "result":" ".join(r) if r else "sem resposta",
                    "ok":bool(r and r[0]=="OK")}))
                except: pass

            elif msg["type"] == "refresh":
                if not writer: continue
                what = msg.get("what","players")
                if what == "players":
                    r = await send_cmd("admin.listPlayers","all")
                    if r:
                        try: await ws.send(json.dumps({"type":"players","players":parse_pl(r)}))
                        except: pass
                elif what == "serverInfo":
                    r = await send_cmd("serverInfo")
                    if r and r[0]=="OK":
                        scores={}
                        try: scores={"team1":int(r[8]) if len(r)>8 else 0,"team2":int(r[9]) if len(r)>9 else 0}
                        except: pass
                        try: await ws.send(json.dumps({"type":"serverInfo",
                            "serverName":r[1] if len(r)>1 else "",
                            "mapName":r[4] if len(r)>4 else "",
                            "modeName":r[5] if len(r)>5 else "",
                            "maxPlayers":int(r[7]) if len(r)>7 else 32,
                            "scores":scores}))
                        except: pass
                elif what == "bans":
                    rb = await send_cmd("banList.list","0")
                    bans = []
                    if rb and rb[0]=="OK":
                        try:
                            i=1
                            while i+4<len(rb):
                                bans.append({"idType":rb[i],"id":rb[i+1],"banType":rb[i+2],"time":rb[i+3],"reason":rb[i+5] if i+5<len(rb) else ""})
                                i+=6
                        except: pass
                    try: await ws.send(json.dumps({"type":"banList","bans":bans}))
                    except: pass
                elif what == "reserved":
                    rr = await send_cmd("reservedSlotsList.list")
                    slots = [rr[i] for i in range(1,len(rr)) if rr[i]] if rr and rr[0]=="OK" else []
                    try: await ws.send(json.dumps({"type":"reservedSlots","slots":slots}))
                    except: pass
                elif what == "plugins":
                    rp = await send_cmd("procon.plugin.list")
                    plugins = []
                    if rp and rp[0]=="OK":
                        try:
                            pc2 = int(rp[1])
                            for i in range(pc2):
                                base = 2+i*3
                                if base+2 < len(rp):
                                    plugins.append({"name":rp[base],"enabled":rp[base+1].lower()=="true","version":rp[base+2]})
                        except Exception as e:
                            print(f"[plugins refresh parse] {e}")
                    print(f"[plugins refresh] {len(plugins)} plugins, raw={rp[:5] if rp else None}")
                    try: await ws.send(json.dumps({"type":"plugins","plugins":plugins}))
                    except: pass

            elif msg["type"] == "ping":
                # heartbeat do cliente — responde com pong
                try: await ws.send(json.dumps({"type":"pong"}))
                except: pass

    except websockets.exceptions.ConnectionClosed:
        print("[-] WS fechado")
    except Exception as e:
        print(f"[!] {e}"); traceback.print_exc()
    finally:
        connected[0] = False
        if writer:
            try: writer.close()
            except: pass

async def main():
    print(f"PRoCon Proxy v2.2 — porta {PORT}")
    async with serve(handler, "0.0.0.0", PORT):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())

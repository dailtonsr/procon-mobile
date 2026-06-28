#!/usr/bin/env python3
"""
PRoCon Mobile — WebSocket <-> PRoCon Layer Proxy v2.0
Fluxo de auth correto (capturado via Wireshark):
  1. version
  2. procon.login.username <username>
  3. login.hashed                       <- pede o salt
  4. login.hashed <MD5(salt+pass)>      <- autentica
"""

import asyncio, hashlib, json, os, struct, traceback, websockets
from websockets.server import serve

PORT = int(os.environ.get("PORT", 8080))
HEADER = 12
_seq = 0

def mk_packet(words):
    global _seq
    _seq = (_seq + 1) & 0x3FFFFFFF
    body = b""
    for w in words:
        b = w.encode("utf-8") if isinstance(w, str) else w
        body += struct.pack("<I", len(b)) + b + b"\x00"
    hdr = struct.pack("<III", _seq, HEADER + len(body), len(words))
    return hdr + body, _seq

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
    print(f"[hash] final={final[:8]}...")
    return final

async def handler(ws):
    print(f"[+] WS {ws.remote_address}")
    reader = writer = None
    buf = b""
    pending = {}

    async def send_cmd(*words, timeout=20.0):
        pkt, seq = mk_packet(list(words))
        fut = asyncio.get_event_loop().create_future()
        pending[seq] = fut
        writer.write(pkt); await writer.drain()
        print(f"[>>] {words[0]} {words[1] if len(words)>1 else ''}")
        try:
            result = await asyncio.wait_for(fut, timeout=timeout)
            print(f"[<<] {result[:3] if result else result}")
            return result
        except asyncio.TimeoutError:
            pending.pop(seq, None)
            print(f"[timeout] {words[0]}")
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
                        pending.pop(p["seq"]).set_result(p["words"])
                    else:
                        await on_event(p["words"])
            except Exception as e:
                print(f"[recv] {e}"); break
        for f in pending.values():
            if not f.done(): f.set_exception(Exception("disconnected"))

    async def on_event(words):
        if not words: return
        if words[0] == "player.onChat":
            await ws.send(json.dumps({"type":"chat",
                "player": words[1] if len(words)>1 else "?",
                "text":   words[2] if len(words)>2 else "",
                "subset": words[3] if len(words)>3 else "All",
                "isAdmin": False}))
        elif words[0] in ("player.onJoin","player.onLeave","player.onTeamChange","player.onSquadChange"):
            r = await send_cmd("admin.listPlayers","all")
            if r: await ws.send(json.dumps({"type":"players","players":parse_pl(r)}))
        elif words[0] == "player.onKill":
            await ws.send(json.dumps({"type":"event",
                "event": "kill",
                "killer": words[1] if len(words)>1 else "",
                "victim": words[2] if len(words)>2 else "",
                "weapon": words[3] if len(words)>3 else "",
                "headshot": words[4] if len(words)>4 else "false"}))
        elif words[0] == "server.onRoundOver":
            await ws.send(json.dumps({"type":"event","event":"roundOver","winner": words[1] if len(words)>1 else ""}))
        elif words[0] == "server.onLevelLoaded":
            await ws.send(json.dumps({"type":"event","event":"levelLoaded",
                "map": words[1] if len(words)>1 else "",
                "mode": words[2] if len(words)>2 else ""}))

    def parse_pl(words):
        """
        Parse admin.listPlayers response.
        Formato: OK <fieldCount> <field1> ... <fieldN> <playerCount> <val1> ... <valN> ...
        Campos possíveis: name, guid, teamId, squadId, kills, deaths, score, rank, ping, type
        """
        out = []
        if not words or words[0] != "OK": return out
        try:
            fc = int(words[1])
            fields = words[2:2+fc]
            pc = int(words[2+fc])
            off = 3+fc
            for i in range(pc):
                p = {fields[j]: words[off+i*fc+j] for j in range(fc) if off+i*fc+j < len(words)}
                out.append({
                    "name":   p.get("name",""),
                    "guid":   p.get("guid",""),
                    "team":   int(p.get("teamId","0")),
                    "squad":  int(p.get("squadId","0")),
                    "kills":  int(p.get("kills","0")),
                    "deaths": int(p.get("deaths","0")),
                    "score":  int(p.get("score","0")),
                    "ping":   int(p.get("ping","0")),
                    "rank":   int(p.get("rank","0")),
                    "type":   p.get("type","0"),
                })
        except Exception as e:
            print(f"[parse_pl] {e}")
        return out

    def parse_pl_extended(words):
        """
        Parse admin.listPlayers com dados estendidos incluindo IP.
        O servidor retorna campos extras quando disponíveis.
        """
        return parse_pl(words)

    async def fetch_player_info(name):
        """Busca dados extras de um jogador: GUID, IP via punkBuster.pb_sv_plist"""
        info = {"name": name, "guid": "", "ip": "", "ea_guid": ""}
        # Tenta pegar via admin.listPlayers que já inclui guid
        r = await send_cmd("admin.listPlayers", "player", name, timeout=5.0)
        if r and r[0] == "OK":
            players = parse_pl(r)
            if players:
                info["guid"] = players[0].get("guid","")
        return info

    try:
        async for raw in ws:
            msg = json.loads(raw)

            # ── CONNECT ──────────────────────────────────────
            if msg["type"] == "connect":
                host     = msg["host"]
                port     = int(msg["port"])
                password = msg.get("pass","")
                username = msg.get("username","admin")
                print(f"[->] {host}:{port} user={username}")

                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=15)
                    print("[OK] TCP ok")
                except Exception as e:
                    await ws.send(json.dumps({"type":"error","message":f"TCP falhou: {e}"}))
                    continue

                asyncio.ensure_future(recv_loop())

                r0 = await send_cmd("version", timeout=10.0)
                if not r0 or r0[0] != "OK":
                    await ws.send(json.dumps({"type":"error","message":f"version falhou: {r0}"}))
                    continue

                r1 = await send_cmd("procon.login.username", username, timeout=10.0)
                if not r1 or r1[0] != "OK":
                    await ws.send(json.dumps({"type":"error","message":f"username falhou: {r1}"}))
                    continue

                r2 = await send_cmd("login.hashed", timeout=10.0)
                if not r2 or r2[0] != "OK" or len(r2) < 2:
                    await ws.send(json.dumps({"type":"error","message":f"salt falhou: {r2}"}))
                    continue

                salt = r2[1]
                hashed = compute_hash(salt, password)
                r3 = await send_cmd("login.hashed", hashed, timeout=15.0)
                if not r3 or r3[0] != "OK":
                    await ws.send(json.dumps({"type":"error","message":"Senha incorreta"}))
                    continue

                print("[AUTH OK]")
                await send_cmd("admin.eventsEnabled","true")

                ri = await send_cmd("serverInfo")
                sname = ri[1] if ri and len(ri)>1 else host
                await ws.send(json.dumps({"type":"connected","serverName":sname}))

                # Players
                r = await send_cmd("admin.listPlayers","all")
                if r: await ws.send(json.dumps({"type":"players","players":parse_pl(r)}))

                # serverInfo completo
                r = await send_cmd("serverInfo")
                if r and r[0]=="OK" and len(r)>5:
                    scores = {}
                    try: scores={"team1":int(r[8]) if len(r)>8 else 0,"team2":int(r[9]) if len(r)>9 else 0}
                    except: pass
                    await ws.send(json.dumps({"type":"serverInfo",
                        "serverName":r[1] if len(r)>1 else "",
                        "mapName":r[4] if len(r)>4 else "",
                        "modeName":r[5] if len(r)>5 else "",
                        "playerCount":int(r[6]) if len(r)>6 else 0,
                        "maxPlayers":int(r[7]) if len(r)>7 else 0,
                        "scores":scores,
                        "roundsPlayed":int(r[10]) if len(r)>10 else 0,
                        "roundsTotal":int(r[11]) if len(r)>11 else 0,
                        "uptime":int(r[14]) if len(r)>14 else 0,
                        }))

                # Mapa
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
                await ws.send(json.dumps({"type":"mapList","maps":maps,"currentIdx":cur}))

                # Ban list
                rb = await send_cmd("banList.list","0")
                bans = []
                if rb and rb[0]=="OK":
                    try:
                        i = 1
                        while i+4 < len(rb):
                            bans.append({
                                "idType": rb[i],
                                "id":     rb[i+1],
                                "banType":rb[i+2],
                                "time":   rb[i+3],
                                "reason": rb[i+5] if i+5 < len(rb) else ""
                            })
                            i += 6
                    except: pass
                await ws.send(json.dumps({"type":"banList","bans":bans}))

                # Reserved slots
                rr = await send_cmd("reservedSlotsList.list")
                slots = []
                if rr and rr[0]=="OK":
                    slots = [rr[i] for i in range(1,len(rr)) if rr[i]]
                await ws.send(json.dumps({"type":"reservedSlots","slots":slots}))

                # Plugins
                rp = await send_cmd("procon.plugin.list")
                plugins = []
                if rp and rp[0]=="OK":
                    try:
                        pc2 = int(rp[1])
                        for i in range(pc2):
                            base = 2 + i*3
                            if base+2 < len(rp):
                                plugins.append({
                                    "name":    rp[base],
                                    "enabled": rp[base+1].lower()=="true",
                                    "version": rp[base+2]
                                })
                    except: pass
                await ws.send(json.dumps({"type":"plugins","plugins":plugins}))

            # ── CMD ───────────────────────────────────────────
            elif msg["type"] == "cmd":
                if not writer:
                    await ws.send(json.dumps({"type":"error","message":"Não conectado"}))
                    continue
                r = await send_cmd(msg.get("cmd",""), *msg.get("args",[]))
                await ws.send(json.dumps({"type":"cmdResult",
                    "result":" ".join(r) if r else "sem resposta",
                    "ok":bool(r and r[0]=="OK")}))

            # ── PLAYER INFO ───────────────────────────────────
            elif msg["type"] == "playerInfo":
                if not writer:
                    await ws.send(json.dumps({"type":"error","message":"Não conectado"}))
                    continue
                name = msg.get("name","")
                info = await fetch_player_info(name)
                await ws.send(json.dumps({"type":"playerInfo","info":info}))

            # ── REFRESH ───────────────────────────────────────
            elif msg["type"] == "refresh":
                if not writer: continue
                what = msg.get("what","players")
                if what == "players":
                    r = await send_cmd("admin.listPlayers","all")
                    if r: await ws.send(json.dumps({"type":"players","players":parse_pl(r)}))
                elif what == "bans":
                    rb = await send_cmd("banList.list","0")
                    bans = []
                    if rb and rb[0]=="OK":
                        try:
                            i = 1
                            while i+4 < len(rb):
                                bans.append({"idType":rb[i],"id":rb[i+1],"banType":rb[i+2],"time":rb[i+3],"reason":rb[i+5] if i+5<len(rb) else ""})
                                i += 6
                        except: pass
                    await ws.send(json.dumps({"type":"banList","bans":bans}))
                elif what == "plugins":
                    rp = await send_cmd("procon.plugin.list")
                    plugins = []
                    if rp and rp[0]=="OK":
                        try:
                            pc2 = int(rp[1])
                            for i in range(pc2):
                                base = 2+i*3
                                if base+2<len(rp):
                                    plugins.append({"name":rp[base],"enabled":rp[base+1].lower()=="true","version":rp[base+2]})
                        except: pass
                    await ws.send(json.dumps({"type":"plugins","plugins":plugins}))
                elif what == "reserved":
                    rr = await send_cmd("reservedSlotsList.list")
                    slots = []
                    if rr and rr[0]=="OK":
                        slots = [rr[i] for i in range(1,len(rr)) if rr[i]]
                    await ws.send(json.dumps({"type":"reservedSlots","slots":slots}))
                elif what == "serverInfo":
                    r = await send_cmd("serverInfo")
                    if r and r[0]=="OK":
                        scores = {}
                        try: scores={"team1":int(r[8]) if len(r)>8 else 0,"team2":int(r[9]) if len(r)>9 else 0}
                        except: pass
                        await ws.send(json.dumps({"type":"serverInfo",
                            "serverName":r[1] if len(r)>1 else "",
                            "mapName":r[4] if len(r)>4 else "",
                            "modeName":r[5] if len(r)>5 else "",
                            "playerCount":int(r[6]) if len(r)>6 else 0,
                            "maxPlayers":int(r[7]) if len(r)>7 else 0,
                            "scores":scores}))

    except websockets.exceptions.ConnectionClosed:
        print("[-] WS fechado")
    except Exception as e:
        print(f"[!] {e}"); traceback.print_exc()
    finally:
        if writer:
            try: writer.close()
            except: pass

async def main():
    print(f"PRoCon Proxy v2.0 — porta {PORT}")
    async with serve(handler, "0.0.0.0", PORT):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())

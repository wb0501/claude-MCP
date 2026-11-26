#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agent LLM uplink byte audit (Python 3.9+, standard library only).

Usage (exactly one positional argument):
    python3 analyze_bytes.py /path/to/task
    python3 analyze_bytes.py /path/to/all_tasks

Input: a task directory containing raw_traffic.pcapng, a directory whose
immediate child directories each contain a pcapng, or one .pcapng file.
Output: exactly one CSV named llm_bytes_summary.csv in the supplied directory
(or beside the .pcapng). No raw prompts, tokens, tool responses, or credentials
are exported.

Measures traffic OBSERVED at the client <-> configured gateways (192.168.3.125:8317 and 172.17.192.1:8317). It does
not imply identical requests reach the upstream inference backend.

All-capture frame bytes include every protocol and retransmission, using the
original frame length (not just captured payload). Direction is relative to
the capturing host, from Linux cooked v1/v2 packet type: 4 = up, 0..3 = down.
Other packet types/link formats remain unknown rather than guessing direction.
All-capture directional percentages use all_capture_frame_bytes as denominator,
including unknown-direction bytes. Existing up/down fields remain gateway-only.
"""
import argparse
import collections
import csv
import hashlib
import ipaddress
import json
import struct
import sys
from pathlib import Path

GATEWAY_IPS = {'192.168.3.125', '172.17.192.1'}
GATEWAY_PORT = 8317
OUT_NAME = 'llm_bytes_summary.csv'

CATEGORIES = ('system', 'tool_schema', 'user', 'assistant', 'tool_result', 'other_content', 'json_overhead')
REPLAY_CATEGORIES = ('system', 'tool_schema', 'user', 'assistant', 'tool_result', 'other_content')


def discover(path):
    if not path.exists():
        raise ValueError(f'路径不存在: {path}')
    if path.is_file():
        if path.suffix.lower() != '.pcapng':
            raise ValueError('文件路径必须指向 .pcapng 抓包')
        return [(path.parent.name, path)], path.parent / OUT_NAME, False
    direct = choose_pcap(path)
    if direct:
        return [(path.name, direct)], path / OUT_NAME, False
    tasks = [(p.name, c) for p in sorted(path.iterdir()) if p.is_dir()
             for c in [choose_pcap(p)] if c is not None]
    if not tasks:
        raise ValueError('未找到抓包：当前目录没有 .pcapng，直接子目录也没有 .pcapng')
    return tasks, path / OUT_NAME, True


def choose_pcap(folder):
    wanted = folder / 'raw_traffic.pcapng'
    if wanted.is_file():
        return wanted
    choices = sorted(p for p in folder.glob('*.pcapng') if p.is_file())
    if len(choices) == 1:
        return choices[0]
    if len(choices) > 1:
        raise ValueError(f'目录包含多个 pcapng，无法确定使用哪一个: {folder}')
    return None


def iter_pcapng(path):
    """Yield (linktype, packet_bytes, original_frame_length) from EPB/PB blocks.
    PCAPNG is streamed rather than loaded entirely into RAM.
    """
    end = '<'; interfaces = []
    with path.open('rb') as f:
        while True:
            h = f.read(8)
            if not h:
                break
            if len(h) != 8:
                raise ValueError('截断的 PCAPNG 块头')
            if h[:4] == b'\x0a\x0d\x0d\x0a':
                magic = f.read(4)
                if magic == b'\x4d\x3c\x2b\x1a': end = '<'
                elif magic == b'\x1a\x2b\x3c\x4d': end = '>'
                else: raise ValueError('PCAPNG Section 字节序无效')
                size = struct.unpack(end+'I', h[4:8])[0]
                if size < 28: raise ValueError('PCAPNG Section 长度无效')
                f.seek(size-12, 1)  # first eight bytes + 4 magic already consumed
                interfaces = []
                continue
            typ, size = struct.unpack(end+'II', h)
            if size < 12 or size > 256 * 1024 * 1024:
                raise ValueError(f'PCAPNG 块长度异常: {size}')
            body = f.read(size-8)
            if len(body) != size-8: raise ValueError('截断的 PCAPNG 块体')
            if struct.unpack(end+'I',body[-4:])[0] != size:
                raise ValueError('PCAPNG 块结束长度校验失败')
            body = body[:-4]
            if typ == 1:
                if len(body) >= 8:
                    interfaces.append(struct.unpack(end+'H',body[:2])[0])
            elif typ == 6 and len(body)>=20:
                iid,hi,lo,caplen,origlen = struct.unpack(end+'IIIII',body[:20])
                if iid < len(interfaces) and caplen <= len(body)-20:
                    yield interfaces[iid],body[20:20+caplen],origlen
            elif typ == 2 and len(body)>=20:
                iid,drop,hi,lo,caplen,origlen = struct.unpack(end+'HHIIII',body[:20])
                if iid < len(interfaces) and caplen <= len(body)-20:
                    yield interfaces[iid],body[20:20+caplen],origlen


def tcp_packet(linktype, frame):
    if linktype == 1:  # Ethernet incl VLAN
        if len(frame)<14:return None
        pos=12; typ=int.from_bytes(frame[pos:pos+2],'big');pos+=2
        while typ in (0x8100,0x88a8,0x9100):
            if len(frame)<pos+4:return None
            typ=int.from_bytes(frame[pos+2:pos+4],'big');pos+=4
        ip=frame[pos:]
    elif linktype == 113:  # Linux cooked v1
        if len(frame)<16:return None
        typ=int.from_bytes(frame[14:16],'big');ip=frame[16:]
    elif linktype == 276:  # Linux cooked v2
        if len(frame)<20:return None
        typ=int.from_bytes(frame[:2],'big');ip=frame[20:]
    elif linktype == 101:  # raw IP
        ip=frame;typ=0x0800 if ip and ip[0]>>4==4 else 0x86dd
    elif linktype == 0:  # BSD loopback DLT_NULL
        if len(frame)<4:return None
        family=int.from_bytes(frame[:4],'little')
        typ={2:0x0800,24:0x86dd,28:0x86dd,30:0x86dd}.get(family)
        ip=frame[4:]
    else:return None
    if typ==0x0800:
        if len(ip)<20 or ip[0]>>4!=4 or ip[9]!=6:return None
        ihl=(ip[0]&15)*4
        if ihl<20 or len(ip)<ihl:return None
        frag=int.from_bytes(ip[6:8],'big')
        if frag & 0x1fff:return None
        src=str(ipaddress.IPv4Address(ip[12:16]));dst=str(ipaddress.IPv4Address(ip[16:20]));tcp=ip[ihl:]
    elif typ==0x86dd:
        if len(ip)<40 or ip[0]>>4!=6:return None
        src=str(ipaddress.IPv6Address(ip[8:24]));dst=str(ipaddress.IPv6Address(ip[24:40]))
        nxt=ip[6];pos=40
        for _ in range(8):
            if nxt==6:break
            if nxt in (0,43,60) and len(ip)>=pos+2:
                step=(ip[pos+1]+1)*8; nxt=ip[pos];pos+=step
            elif nxt==44 and len(ip)>=pos+8:
                if int.from_bytes(ip[pos+2:pos+4],'big') & 0xfff8:return None
                nxt=ip[pos];pos+=8
            else:return None
        if nxt!=6:return None
        tcp=ip[pos:]
    else:return None
    if len(tcp)<20:return None
    sport,dport,seq=struct.unpack('!HHI',tcp[:8]);off=(tcp[12]>>4)*4
    if off<20 or len(tcp)<off:return None
    return src,sport,dst,dport,seq,tcp[13],tcp[off:]


def gateway_capture(path):
    stat=collections.Counter()
    sessions=[];active={}
    # Each new TCP SYN starts a distinct connection (unless retransmitted).
    for link,frame,frame_len in iter_pcapng(path):
        stat['all_capture_packets']+=1
        stat['all_capture_frame_bytes']+=frame_len
        packet_type = None
        if link == 113 and len(frame) >= 16:
            packet_type = int.from_bytes(frame[:2], 'big')
        elif link == 276 and len(frame) >= 20:
            packet_type = frame[10]
        if packet_type == 4:
            capture_direction = 'up'
        elif packet_type in (0, 1, 2, 3):
            capture_direction = 'down'
        else:
            capture_direction = 'unknown_direction'
        stat[f'all_capture_{capture_direction}_packets']+=1
        stat[f'all_capture_{capture_direction}_frame_bytes']+=frame_len
        pkt=tcp_packet(link,frame)
        if pkt is None:continue
        src,sport,dst,dport,seq,flags,payload=pkt
        if dst in GATEWAY_IPS and dport==GATEWAY_PORT:
            direction='up';peer=(dst,src,sport)
        elif src in GATEWAY_IPS and sport==GATEWAY_PORT:
            direction='down';peer=(src,dst,dport)
        else:continue
        stat[f'{direction}_packets']+=1
        stat[f'{direction}_frame_bytes']+=frame_len
        stat[f'{direction}_tcp_payload_captured_bytes']+=len(payload)
        if (flags & 2) and not (flags & 16):
            last=active.get(peer)
            if last is None or last.get('syn_seq')!=seq:
                active[peer]={'up':[],'down':[],'syn_seq':seq}
                sessions.append(active[peer])
        if peer not in active:
            active[peer]={'up':[],'down':[],'syn_seq':None}
            sessions.append(active[peer])
        if payload:
            active[peer][direction].append((seq,payload))
        if flags & (1|4):
            # Keep previous session object, but next distinct SYN can start a new one.
            pass
    return sessions,stat


def contiguous_chunks(segs):
    if not segs:return [],0,0
    # Sequence arithmetic supports ordinary captures (<2GB per individual TCP stream).
    segs.sort(key=lambda p:p[0]);chunks=[];current=bytearray();expected=None;unique=0;gaps=0
    for seq,data in segs:
        if expected is None:expected=seq
        if seq>expected:
            if current:chunks.append(bytes(current))
            current=bytearray();expected=seq;gaps+=1
        overlap=max(0,expected-seq)
        if overlap<len(data):
            add=data[overlap:];current.extend(add);unique+=len(add)
            expected+=len(add)
    if current:chunks.append(bytes(current))
    return chunks,unique,gaps


def parse_chunked(data,pos):
    parts=[]
    while True:
        stop=data.find(b'\r\n',pos)
        if stop<0:return None
        try:size=int(data[pos:stop].split(b';',1)[0],16)
        except ValueError:return None
        pos=stop+2
        if size==0:
            if data[pos:pos+2]==b'\r\n':return b''.join(parts),pos+2
            end=data.find(b'\r\n\r\n',pos)
            return (b''.join(parts),end+4) if end>=0 else None
        if pos+size+2>len(data) or data[pos+size:pos+size+2]!=b'\r\n':return None
        parts.append(data[pos:pos+size]);pos+=size+2


def scan_http_uplink(data):
    """Return request objects and any WS-data suffix. No search in arbitrary payload."""
    pos=0;requests=[];ws_suffix=None
    while pos<len(data):
        marker=data.find(b'\r\n\r\n',pos)
        if marker<0:break
        header=data[pos:marker]
        if b' HTTP/1.' not in header.split(b'\r\n',1)[0]:break
        lines=header.decode('latin1','replace').split('\r\n')
        first=lines[0];headers={}
        for l in lines[1:]:
            if ':' in l:
                a,b=l.split(':',1);headers[a.lower().strip()]=b.strip()
        body_start=marker+4
        if headers.get('upgrade','').lower()=='websocket':
            requests.append((first,headers,b'',body_start-pos,'upgrade'))
            ws_suffix=data[body_start:]
            break
        if 'chunked' in headers.get('transfer-encoding','').lower():
            parsed=parse_chunked(data,body_start)
            if parsed is None:break
            body,next_pos=parsed
        elif 'content-length' in headers:
            try:count=int(headers['content-length'])
            except ValueError:break
            if count<0 or body_start+count>len(data):break
            body=data[body_start:body_start+count];next_pos=body_start+count
        else:
            if first.startswith(('GET ','HEAD ','OPTIONS ','DELETE ')):
                body=b'';next_pos=body_start
            else:break
        requests.append((first,headers,body,next_pos-pos,'http'))
        pos=next_pos
    return requests,ws_suffix,pos


def websocket_messages(data):
    """Decode masked/unmasked WebSocket frames, incl fragmentation, never decompress.
    Yields (opcode, payload, encoded_frame_bytes, compressed).
    """
    i=0;part=[];part_size=0;part_compressed=False;part_opcode=None
    while i+2<=len(data):
        begin=i;b0=data[i];b1=data[i+1];i+=2
        fin=bool(b0&0x80);comp=bool(b0&0x40);opcode=b0&15;masked=bool(b1&0x80)
        length=b1&0x7f
        if length==126:
            if i+2>len(data):break
            length=int.from_bytes(data[i:i+2],'big');i+=2
        elif length==127:
            if i+8>len(data):break
            length=int.from_bytes(data[i:i+8],'big');i+=8
        if length>128*1024*1024:break
        key=b''
        if masked:
            if i+4>len(data):break
            key=data[i:i+4];i+=4
        if i+length>len(data):break
        payload=data[i:i+length];i+=length
        if masked:payload=bytes(x ^ key[j&3] for j,x in enumerate(payload))
        size=i-begin
        if opcode in (0x8,0x9,0xa):
            yield opcode,payload,size,comp
            continue
        if opcode in (0x1,0x2):
            part=[payload];part_size=size;part_compressed=comp;part_opcode=opcode
        elif opcode==0 and part_opcode is not None:
            part.append(payload);part_size+=size
        else:
            break
        if fin and part_opcode is not None:
            yield part_opcode,b''.join(part),part_size,part_compressed
            part=[];part_size=0;part_opcode=None


# Build exact-byte JSON value spans and map them to semantic classes. Field keys,
# punctuation and other request metadata intentionally belong to json_overhead.
class JsonSpan:
    def __init__(self,b):self.b=b;self.i=0
    def skip(self):
        while self.i<len(self.b) and self.b[self.i] in b' \r\n\t':self.i+=1
    def parse_val(self):
        self.skip();b=self.b;start=self.i
        if start>=len(b):raise ValueError('truncated JSON')
        c=b[self.i]
        if c==34:
            self.i+=1
            while self.i<len(b):
                cc=b[self.i];self.i+=1
                if cc==34:break
                if cc==92:self.i+=1
            else:raise ValueError('unterminated JSON string')
            return (start,self.i,None)
        if c in (123,91):
            arr=c==91;self.i+=1;self.skip();kids=[] if arr else {}
            closing=93 if arr else 125
            while self.i<len(b) and b[self.i]!=closing:
                if arr: kids.append(self.parse_val())
                else:
                    begin=self.i
                    k=self.parse_val()
                    key=json.loads(b[k[0]:k[1]])
                    self.skip()
                    if self.i>=len(b) or b[self.i]!=58:raise ValueError('bad JSON object')
                    self.i+=1;kids[key]=self.parse_val()
                self.skip()
                if self.i<len(b) and b[self.i]==44:self.i+=1;self.skip()
                else:break
            if self.i>=len(b) or b[self.i]!=closing:raise ValueError('bad JSON close')
            self.i+=1;return (start,self.i,kids)
        while self.i<len(b) and b[self.i] not in b' ,\r\n\t}]':self.i+=1
        if self.i==start:raise ValueError('bad JSON atom')
        return (start,self.i,None)
    def parse(self):
        node=self.parse_val();self.skip()
        if self.i!=len(self.b):raise ValueError('trailing JSON')
        return node


def child(n,key):return n[2].get(key) if n and isinstance(n[2],dict) else None

def bytes_len(n):return n[1]-n[0] if n else 0

def fp(obj):
    # fingerprints are for repetition labels, not a proof of token/cache equality
    return hashlib.sha256(json.dumps(obj,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf8')).digest()


def is_tool_result(obj):
    return isinstance(obj,dict) and (obj.get('type') in ('tool_result','function_call_output','custom_tool_call_output','computer_call_output') or obj.get('role') in ('tool','function'))


def mark(ctx,kind,n,obj=None):
    if n is None:return
    s=bytes_len(n)
    if s==0:return
    ctx['part'][kind]+=s
    if kind=='json_overhead':return
    if obj is None:
        obj=ctx['blob'][n[0]:n[1]]
    identity=(kind,fp(obj) if not isinstance(obj,bytes) else hashlib.sha256(obj).digest())
    if identity in ctx['seen']:
        ctx['repeated'][kind]+=s
    else:
        ctx['new'][kind]+=s
        ctx['seen'].add(identity)


def add_content(ctx,obj,n):
    """Classify item/message bytes without overlaps."""
    if not isinstance(obj,dict):
        mark(ctx,'other_content',n,obj);return
    if is_tool_result(obj):
        mark(ctx,'tool_result',n,obj);return
    role=obj.get('role')
    typ=obj.get('type')
    if role in ('system','developer') or typ in ('system','developer'):
        kind='system'
    elif role=='assistant' or typ in ('function_call','custom_tool_call','message') and role not in ('user','tool'):
        kind='assistant'
    elif role=='user' or typ in ('input_text','input_image','input_audio'):
        kind='user'
    else:kind='other_content'
    content=obj.get('content')
    cn=child(n,'content')
    # Anthropic may put tool_result blocks in a user message: split them out.
    if isinstance(content,list) and cn and isinstance(cn[2],list) and len(content)==len(cn[2]):
        results=[(v,sp) for v,sp in zip(content,cn[2]) if is_tool_result(v)]
        if results:
            for v,sp in results:mark(ctx,'tool_result',sp,v)
            remainder=bytes_len(n)-sum(bytes_len(sp) for v,sp in results)
            ctx['part'][kind]+=remainder
            stripped={k:([v for v in content if not is_tool_result(v)] if k=='content' else v) for k,v in obj.items()}
            identity=(kind,fp(stripped))
            if identity in ctx['seen']:ctx['repeated'][kind]+=remainder
            else:ctx['new'][kind]+=remainder;ctx['seen'].add(identity)
            return
    mark(ctx,kind,n,obj)


def classify_json(ctx,blob):
    try:
        obj=json.loads(blob)
        if not isinstance(obj,dict):return False
        root=JsonSpan(blob).parse()
    except (ValueError,TypeError,UnicodeDecodeError,json.JSONDecodeError):return False
    ctx['blob']=blob
    before_assigned=sum(ctx['part'].values())
    # Treat fields common to Anthropic Messages, OpenAI Responses, and chat/completions.
    for fld in ('system','instructions','developer'):
        mark(ctx,'system',child(root,fld))
    for fld in ('tools','functions'):
        mark(ctx,'tool_schema',child(root,fld))
    for fld in ('messages','input'):
        value=obj.get(fld);node=child(root,fld)
        if isinstance(value,list) and node and isinstance(node[2],list):
            for item,sp in zip(value,node[2]):add_content(ctx,item,sp)
        elif fld=='input' and isinstance(value,(str,dict)) and node:
            if isinstance(value,str):mark(ctx,'user',node,value)
            else:add_content(ctx,value,node)
    mark(ctx,'user',child(root,'prompt'))
    # Event-wrapped model input (less common). Recurse one level only where relevant.
    response=obj.get('response'); rn=child(root,'response')
    if isinstance(response,dict) and rn:
        for fld in ('instructions','system'):
            mark(ctx,'system',child(rn,fld))
        mark(ctx,'tool_schema',child(rn,'tools'))
        for fld in ('input','messages'):
            value=response.get(fld);node=child(rn,fld)
            if isinstance(value,list) and node and isinstance(node[2],list):
                for item,sp in zip(value,node[2]):add_content(ctx,item,sp)
            elif isinstance(value,(str,dict)) and node:
                if isinstance(value,str):mark(ctx,'user',node,value)
                else:add_content(ctx,value,node)
    assigned=sum(ctx['part'].values())-before_assigned
    if assigned>len(blob):raise ValueError('JSON byte accounting overlap')
    ctx['part']['json_overhead']+=len(blob)-assigned
    return True


def empty_result(name,file):
    row=collections.Counter()
    row['row_type']='task';row['task']=name;row['pcap_file']=file.name
    row['protocol']='unknown';row['status']='no_gateway_traffic'
    return row


def audit_one(name,path):
    row=empty_result(name,path)
    sessions,net=gateway_capture(path)
    row.update(net)
    if not (net['up_packets']+net['down_packets']):return row
    row['status']='unparsed_gateway_payload'
    ctx={'part':collections.Counter(),'repeated':collections.Counter(),'new':collections.Counter(),'seen':set(),'blob':b''}
    protocols=set();unique_up=0;unique_down=0;gap_count=0
    for sess in sessions:
        up_chunks,u,g1=contiguous_chunks(sess['up'])
        down_chunks,d,g2=contiguous_chunks(sess['down'])
        unique_up+=u;unique_down+=d;gap_count+=g1+g2
        for data in up_chunks:
            if not data:continue
            if data.startswith((b'GET ',b'POST ',b'HEAD ',b'OPTIONS ',b'PUT ',b'PATCH ',b'DELETE ')):
                requests,ws_tail,consumed=scan_http_uplink(data)
                if requests:protocols.add('HTTP/1.1')
                for first,headers,body,framing,kind in requests:
                    if kind=='upgrade':
                        row['ws_upgrades']+=1;protocols.add('WebSocket');continue
                    if not first.startswith(('POST ','PUT ','PATCH ')):continue
                    pathpart=first.split(' ',2)[1] if len(first.split(' ',2))>=2 else ''
                    if not any(k in pathpart.lower() for k in ('/messages','/responses','/chat/completions','/completions')):
                        continue
                    row['http_model_requests']+=1
                    row['http_body_bytes']+=len(body)
                    row['http_framing_bytes']+=framing-len(body)
                    if classify_json(ctx,body):
                        row['parsed_json_messages']+=1
                        row['parsed_json_bytes']+=len(body)
                    else:
                        row['unclassified_app_bytes']+=len(body)
                if ws_tail is not None:
                    for op,payload,encoded,compressed in websocket_messages(ws_tail):
                        row['ws_frame_bytes']+=encoded
                        if op in (1,2):
                            row['ws_data_messages']+=1;row['ws_app_payload_bytes']+=len(payload)
                            if not compressed and op==1 and classify_json(ctx,payload):
                                row['parsed_json_messages']+=1
                                row['parsed_json_bytes']+=len(payload)
                            else:row['unclassified_app_bytes']+=len(payload)
            elif len(data)>2 and data[0]==0x16 and data[1]==0x03:
                protocols.add('TLS/encrypted')
            elif data.startswith(b'PRI * HTTP/2.0'):
                protocols.add('HTTP/2 unsupported')
            else:
                protocols.add('other/unknown')
    row['tcp_unique_up_bytes']=unique_up
    row['tcp_unique_down_bytes']=unique_down
    row['tcp_stream_gap_count']=gap_count
    row['protocol']='+'.join(sorted(protocols)) if protocols else 'unknown'
    for k in CATEGORIES:
        row[k+'_bytes']=ctx['part'][k]
    for k in REPLAY_CATEGORIES:
        row['new_'+k+'_bytes']=ctx['new'][k]
        row['repeated_'+k+'_bytes']=ctx['repeated'][k]
    row['classified_json_bytes']=sum(ctx['part'][k] for k in CATEGORIES if k!='json_overhead')
    row['new_content_bytes']=sum(ctx['new'].values())
    row['repeated_content_bytes']=sum(ctx['repeated'].values())
    row['app_payload_bytes']=row['http_body_bytes']+row['ws_app_payload_bytes']
    row['gateway_requests_or_ws_messages']=row['http_model_requests']+row['ws_data_messages']
    if row['parsed_json_bytes']:
        row['status']='parsed' if not row['unclassified_app_bytes'] and not gap_count else 'partial_parsed'
    elif 'TLS/encrypted' in protocols:row['status']='encrypted_no_request_body'
    elif row['ws_data_messages'] or row['http_model_requests']:row['status']='unclassified_model_payload'
    return row


ADDITIVE = (
    'all_capture_packets','all_capture_frame_bytes',
    'all_capture_up_packets','all_capture_down_packets','all_capture_unknown_direction_packets',
    'all_capture_up_frame_bytes','all_capture_down_frame_bytes','all_capture_unknown_direction_frame_bytes',
    'up_packets','down_packets','up_frame_bytes','down_frame_bytes',
    'up_tcp_payload_captured_bytes','down_tcp_payload_captured_bytes',
    'tcp_unique_up_bytes','tcp_unique_down_bytes','tcp_stream_gap_count',
    'http_model_requests','http_body_bytes','http_framing_bytes','ws_upgrades',
    'ws_data_messages','ws_frame_bytes','ws_app_payload_bytes','app_payload_bytes',
    'gateway_requests_or_ws_messages','parsed_json_messages','parsed_json_bytes',
    'unclassified_app_bytes','classified_json_bytes','new_content_bytes','repeated_content_bytes',
) + tuple(k+'_bytes' for k in CATEGORIES) + tuple('new_'+k+'_bytes' for k in REPLAY_CATEGORIES) + tuple('repeated_'+k+'_bytes' for k in REPLAY_CATEGORIES)

PERCENT_DENOMS = {
    # data categories are disjoint slices of successfully parsed JSON values
    **{k+'_pct_of_parsed_json':'parsed_json_bytes' for k in CATEGORIES},
    'new_content_pct_of_parsed_json':'parsed_json_bytes',
    'repeated_content_pct_of_parsed_json':'parsed_json_bytes',
    'unclassified_pct_of_app_payload':'app_payload_bytes',
    'parsed_pct_of_app_payload':'app_payload_bytes',
}


def enrich(row):
    for k in ADDITIVE:
        row.setdefault(k,0)
    for direction in ('up', 'down', 'unknown_direction'):
        row[f'{direction}_pct_of_all_capture_frame_bytes']=pct(
            row[f'all_capture_{direction}_frame_bytes'],row['all_capture_frame_bytes'])
    for k in CATEGORIES:
        row[k+'_pct_of_parsed_json']=pct(row[k+'_bytes'],row['parsed_json_bytes'])
    row['new_content_pct_of_parsed_json']=pct(row['new_content_bytes'],row['parsed_json_bytes'])
    row['repeated_content_pct_of_parsed_json']=pct(row['repeated_content_bytes'],row['parsed_json_bytes'])
    row['unclassified_pct_of_app_payload']=pct(row['unclassified_app_bytes'],row['app_payload_bytes'])
    row['parsed_pct_of_app_payload']=pct(row['parsed_json_bytes'],row['app_payload_bytes'])
    row['repeated_pct_of_classified_content']=pct(row['repeated_content_bytes'],row['classified_json_bytes'])
    row['app_payload_pct_of_unique_up_tcp']=pct(row['app_payload_bytes'],row['tcp_unique_up_bytes'])
    row['up_pct_of_gateway_frame_bytes']=pct(row['up_frame_bytes'],row['up_frame_bytes']+row['down_frame_bytes'])
    if row['new_content_bytes']:
        row['context_replay_factor']=round((row['new_content_bytes']+row['repeated_content_bytes'])/row['new_content_bytes'],4)
    else:row['context_replay_factor']=''
    return row


def pct(num,den):return round(100*float(num)/float(den),2) if den else ''


def csv_write(rows,path):
    columns=['row_type','task','pcap_file','protocol','status','error'] + list(ADDITIVE) + [
        k+'_pct_of_parsed_json' for k in CATEGORIES] + [
        'new_content_pct_of_parsed_json','repeated_content_pct_of_parsed_json',
        'repeated_pct_of_classified_content','unclassified_pct_of_app_payload',
        'parsed_pct_of_app_payload','app_payload_pct_of_unique_up_tcp',
        'up_pct_of_gateway_frame_bytes',
        'up_pct_of_all_capture_frame_bytes','down_pct_of_all_capture_frame_bytes',
        'unknown_direction_pct_of_all_capture_frame_bytes','context_replay_factor']
    with path.open('w',newline='',encoding='utf-8-sig') as f:
        writer=csv.DictWriter(f,fieldnames=columns,extrasaction='ignore');writer.writeheader()
        writer.writerows(rows)


def main():
    parser=argparse.ArgumentParser(description='单任务或一级子目录多任务全部捕获流量方向与 LLM Gateway 传输字节统计；仅输出一个 CSV。')
    parser.add_argument('path',help='单任务目录、任务集合父目录或 pcapng 文件')
    args=parser.parse_args()
    try:tasks,out,collective=discover(Path(args.path).expanduser().resolve())
    except (ValueError,OSError) as e:parser.error(str(e))
    rows=[]
    for name,p in tasks:
        try:
            row=audit_one(name,p)
        except (OSError,ValueError,struct.error) as e:
            row=empty_result(name,p);row['status']='error';row['error']=str(e)[:200]
        rows.append(enrich(row))
    if collective:
        total=collections.Counter()
        for r in rows:
            if r['status']=='error':continue
            for k in ADDITIVE:total[k]+=r[k]
        total['row_type']='TOTAL';total['task']='ALL_TASKS';total['pcap_file']=''
        total['protocol']='mixed';total['status']=f'{sum(r["status"]!="error" for r in rows)}/{len(rows)} tasks counted'
        rows.append(enrich(total))
    csv_write(rows,out)
    print(f'完成：{len(tasks)} 个任务，结果文件：{out}')
    print('注意：无法解析/加密的请求不会被猜测分类；占比统计的分母见 CSV 列名。')

if __name__=='__main__':main()

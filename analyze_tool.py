#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""All Claude tool execution-boundary measurement, offline PCAPNG + Claude timeline.

Usage: python3 analyze_tool.py /path/to/results
Python 3.9+, standard library only. Recursively scans .pcapng; writes exactly
one analyze_tool.csv in the specified directory; no network operations.

Times:
  first_delta_utc, last_delta_utc, tool_block_stop_utc:
      timestamps of the packet containing the LAST byte of the corresponding SSE event;
  mcp_request_send_utc:
      timestamp of packet containing FIRST byte of the HTTP MCP tools/call request
      (only if correlated by tool use ID in the request metadata).
These are capture timestamps, NOT model generation or Agent SDK hook timestamps.
  dispatch_log_utc: optional Claude timeline 'tool_dispatch_observed'; NOT actual MCP send.

Classification is a CONSERVATIVE research hypothesis, NOT proof of early execution.
Potential preparation != permission to execute on partial/incomplete arguments.
Native stream processing is unverified unless explicitly documented per tool.
"""

import argparse
import bisect
import collections
import csv
import datetime
import ipaddress
import json
import re
import struct
import sys
from pathlib import Path

GATEWAY_IPS = {'192.168.3.125', '172.17.192.1'}
GATEWAY_PORT = 8317
OUTPUT = 'analyze_tool.csv'
# Only tool APIs with independently VERIFIED streaming contracts belong here.
# Names alone do not establish native streaming support.
VERIFIED_NATIVE_STREAMING_TOOLS = set()
# Add plaintext MCP ports here only when needed; local HTTP is discovered by address.
MCP_HTTP_PORTS = {3000, 3001, 8000, 8080, 8081}
MAX_HTTP_REQUEST_BODY = 64 * 1024 * 1024
SSE_RE = re.compile(rb'(?:(?:event:|data:|id:)[^\n]*\r?\n)+(?:\r?\n)')
HTTP_REQ_RE = re.compile(rb'(?:POST|PUT|PATCH)\s+/[^\r\n]{0,300}\s+HTTP/1\.[01]\r\n')

FIELDS = [
    'row_type', 'environment', 'task', 'pcap_file', 'tool_name', 'short_name', 'tool_use_id',
    'protocol', 'category', 'classification_basis', 'classification_reason',
    'first_delta_utc', 'last_delta_utc', 'tool_block_stop_utc',
    'mcp_request_send_utc', 'dispatch_log_utc', 'tool_generated_log_utc',
    'tool_result_log_utc', 'execution_evidence_utc', 'execution_evidence_type',
    'stop_to_execution_evidence_ms', 'execution_evidence_before_stop',
    'tool_kind', 'result_is_error',
    'first_to_last_delta_ms', 'last_delta_to_stop_ms',
    'stop_to_mcp_send_ms', 'stop_to_dispatch_log_ms',
    'mcp_started_before_tool_stop', 'dispatch_before_tool_stop',
    'delta_events', 'tool_argument_bytes', 'arguments_json_valid',
    'mcp_match_method', 'mcp_target', 'mcp_transport',
    'time_source', 'timeline_present', 'tcp_gap_count',
    'tool_calls', 'exact_mcp_matches', 'early_mcp_count',
    'status', 'notes',
]


def iter_pcapng(path):
    """Yield (epoch_seconds, linktype, frame, original_frame_bytes).
    Supports PCAPNG EPB/PB, per-interface timestamp resolution and per-section byte order.
    Does not read entire pcap into memory.
    """
    endian = '<'; interfaces = []
    with path.open('rb') as f:
        while True:
            head = f.read(8)
            if not head:
                break
            if len(head) != 8:
                raise ValueError('PCAPNG block header truncated')
            if head[:4] == b'\x0a\x0d\x0d\x0a':
                bom = f.read(4)
                if bom == b'\x4d\x3c\x2b\x1a': endian = '<'
                elif bom == b'\x1a\x2b\x3c\x4d': endian = '>'
                else: raise ValueError('Invalid PCAPNG byte-order marker')
                size = struct.unpack(endian+'I', head[4:8])[0]
                if size < 28 or size > 256*1024*1024: raise ValueError('Bad section length')
                f.seek(size-12, 1)
                interfaces = []
                continue
            typ, size = struct.unpack(endian+'II', head)
            if size < 12 or size > 256*1024*1024: raise ValueError('Bad PCAPNG block size')
            block = f.read(size-8)
            if len(block) != size-8: raise ValueError('PCAPNG block truncated')
            if struct.unpack_from(endian+'I', block, len(block)-4)[0] != size:
                raise ValueError('PCAPNG block length mismatch')
            body = block[:-4]
            if typ == 1 and len(body) >= 8:
                link = struct.unpack_from(endian+'H', body)[0]
                res = 1e-6; offset = 0
                p = 8
                while p + 4 <= len(body):
                    code, length = struct.unpack_from(endian+'HH', body, p)
                    p += 4
                    if code == 0: break
                    opt = body[p:p+length]
                    if code == 9 and opt:
                        v = opt[0]; res = (2.0**-(v&127) if v & 128 else 10.0**-v)
                    elif code == 14 and len(opt) >= 8:
                        offset = struct.unpack_from(endian+'q', opt)[0]
                    p += (length+3)//4*4
                interfaces.append((link,res,offset))
            elif typ in (6,2) and len(body) >= 20:
                if typ == 6:
                    iid, hi, lo, cap, orig = struct.unpack_from(endian+'IIIII', body)
                else:
                    iid, drop, hi, lo, cap, orig = struct.unpack_from(endian+'HHIIII', body)
                if iid >= len(interfaces) or cap > len(body)-20: continue
                link, res, offs = interfaces[iid]
                yield (((hi<<32)|lo)*res+offs), link, body[20:20+cap], orig


def tcp_packet(linktype, frame):
    """Copied/adapted from user's analyze_sse(6).py; no payload reinterpretation."""
    if linktype == 1:
        if len(frame) < 14: return None
        pos=12; typ=int.from_bytes(frame[pos:pos+2],'big');pos+=2
        while typ in (0x8100,0x88a8,0x9100):
            if len(frame)<pos+4: return None
            typ=int.from_bytes(frame[pos+2:pos+4],'big');pos+=4
        ip=frame[pos:]
    elif linktype == 113:
        if len(frame)<16:return None
        typ=int.from_bytes(frame[14:16],'big');ip=frame[16:]
    elif linktype == 276:
        if len(frame)<20:return None
        typ=int.from_bytes(frame[:2],'big');ip=frame[20:]
    elif linktype == 101:
        ip=frame;typ=0x0800 if ip and ip[0]>>4==4 else 0x86dd
    elif linktype == 0:
        if len(frame)<4:return None
        typ={2:0x0800,24:0x86dd,28:0x86dd,30:0x86dd}.get(int.from_bytes(frame[:4],'little'))
        ip=frame[4:]
    else:return None
    if typ == 0x0800:
        if len(ip)<20 or ip[0]>>4!=4 or ip[9]!=6:return None
        ihl=(ip[0]&15)*4
        if ihl<20 or len(ip)<ihl:return None
        frag=int.from_bytes(ip[6:8],'big')
        if frag & 0x1fff:return None
        src=str(ipaddress.IPv4Address(ip[12:16]))
        dst=str(ipaddress.IPv4Address(ip[16:20]))
        tcp=ip[ihl:]
    elif typ == 0x86dd:
        if len(ip)<40 or ip[0]>>4!=6:return None
        src=str(ipaddress.IPv6Address(ip[8:24]));dst=str(ipaddress.IPv6Address(ip[24:40]))
        nxt=ip[6];pos=40
        for _ in range(8):
            if nxt==6:break
            if nxt in (0,43,60) and len(ip)>=pos+2:
                step=(ip[pos+1]+1)*8;nxt=ip[pos];pos+=step
            elif nxt==44 and len(ip)>=pos+8:
                if int.from_bytes(ip[pos+2:pos+4],'big')&0xfff8:return None
                nxt=ip[pos];pos+=8
            else:return None
        if nxt!=6:return None
        tcp=ip[pos:]
    else:return None
    if len(tcp)<20:return None
    sport,dport,seq=struct.unpack('!HHI',tcp[:8]);off=(tcp[12]>>4)*4
    if off<20 or len(tcp)<off:return None
    return src,sport,dst,dport,seq,tcp[13],tcp[off:]


def discover(root):
    if not root.exists(): raise ValueError('路径不存在: '+str(root))
    if root.is_file():
        if root.suffix.lower()!='.pcapng':raise ValueError('需要 .pcapng 或实验目录')
        return [(root.parent.name,root)],root.parent/OUTPUT
    def choose(folder):
        canonical=folder/'raw_traffic.pcapng'
        if canonical.is_file():return canonical
        candidates=list(folder.glob('*.pcapng'))
        if len(candidates)==1:return candidates[0]
        if len(candidates)>1:raise ValueError('存在多个 PCAPNG，无法选择: '+str(folder))
    direct=choose(root)
    if direct:return [(root.name,direct)],root/OUTPUT
    res=[]
    for folder in sorted(p for p in root.rglob('*') if p.is_dir()):
        p=choose(folder)
        if p:res.append((str(folder.relative_to(root)),p))
    if not res:raise ValueError('未找到 .pcapng')
    return res,root/OUTPUT


def streams_in_pcap(pcap):
    """Collect only gateway SSE and likely plaintext MCP uplink sessions."""
    sessions=[];active={};gid=0
    for ts,link,frame,frame_len in iter_pcapng(pcap):
        pkt=tcp_packet(link,frame)
        if pkt is None:continue
        src,sport,dst,dport,seq,flags,payload=pkt
        is_gateway=(src in GATEWAY_IPS and sport==GATEWAY_PORT)
        # HTTP sent to MCP (possibly over localhost or plaintext remote address).
        is_mcp=((dst not in GATEWAY_IPS or dport!=GATEWAY_PORT)
                and (src in ('127.0.0.1','::1') or dst in ('127.0.0.1','::1')
                     or dport in MCP_HTTP_PORTS
                     or (payload.startswith((b'POST ',b'PUT ',b'PATCH ')) and b'HTTP/1.' in payload[:512])))
        if not (is_gateway or is_mcp):continue
        direction='sse' if is_gateway else 'mcp'
        key=(src,sport,dst,dport,direction)
        if flags & 0x02:
            old=active.get(key)
            if old is None or old['syn_seq']!=seq:
                gid+=1
                entry={'key':key,'direction':direction,'syn_seq':seq,'segments':[],'id':gid}
                active[key]=entry;sessions.append(entry)
        if key not in active:
            gid+=1
            entry={'key':key,'direction':direction,'syn_seq':None,'segments':[],'id':gid}
            active[key]=entry;sessions.append(entry)
        if payload:active[key]['segments'].append((seq,ts,payload))
    return sessions


def rebuild(segments):
    """Return contiguous TCP chunks and byte-offset-to-capture-time spans.
    Repeated bytes are discarded, out-of-order segments ordered by TCP sequence.
    A gap splits the stream (we never stitch missing data)."""
    if not segments:return [],0
    chunks=[];gaps=0
    current=bytearray();spans=[];expected=None
    for seq,ts,data in sorted(segments,key=lambda s:(s[0],s[1])):
        if expected is None:expected=seq
        if seq>expected:
            if current:chunks.append((bytes(current),spans))
            current=bytearray();spans=[];expected=seq;gaps+=1
        overlap=max(0,expected-seq)
        if overlap>=len(data):continue
        a=len(current);new=data[overlap:]
        current.extend(new);spans.append((a,len(current),ts));expected+=len(new)
    if current:chunks.append((bytes(current),spans))
    return chunks,gaps


def time_for_offset(spans,offset,ends=None):
    if not spans or offset<0:return None
    if ends is None:ends=[s[1] for s in spans]
    i=bisect.bisect_right(ends,offset)
    return spans[i][2] if i<len(spans) else None


def utc(value):
    if value is None:return ''
    try:return datetime.datetime.fromtimestamp(value,datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    except (ValueError,OverflowError,OSError):return ''


def millisecond(a,b):
    return round((b-a)*1000,3) if a is not None and b is not None else ''


def add_event_tool(calls,session_id,block_idx,event,data,t):
    key=(session_id,block_idx)
    typ=data.get('type')
    if typ=='content_block_start':
        c=data.get('content_block') or {}
        if c.get('type') not in ('tool_use','server_tool_use','mcp_tool_use'):
            calls.pop(key,None);return
        calls[key]={'protocol':'anthropic_sse','block_type':c.get('type',''), 'tool_use_id':c.get('id') or '',
                    'tool_name':c.get('name') or '', 'first':None,'last':None,
                    'stop':None,'parts':[], 'delta_events':0}
    elif typ=='content_block_delta':
        c=calls.get(key);d=data.get('delta') or {}
        if c and d.get('type')=='input_json_delta' and isinstance(d.get('partial_json'),str):
            if c['first'] is None:c['first']=t
            c['last']=t;c['parts'].append(d['partial_json']);c['delta_events']+=1
    elif typ=='content_block_stop':
        c=calls.pop(key,None)
        if c:
            c['stop']=t
            return c
    return None


def parse_sse(raw,spans,session_id):
    """Return per-tool invocations, bound by SSE content block and tool_use_id."""
    active={};out=[];message=0
    ends=[v[1] for v in spans]
    for match in SSE_RE.finditer(raw):
        frame=match.group();data_raw=[];event=''
        for line in frame.splitlines():
            if line.startswith(b'data:'):data_raw.append(line[5:].lstrip(b' '))
            elif line.startswith(b'event:'):event=line[6:].strip().decode('utf-8','replace')
        if not data_raw:continue
        try:data=json.loads(b'\n'.join(data_raw))
        except (ValueError,UnicodeError):continue
        if not isinstance(data,dict):continue
        t=time_for_offset(spans,match.end()-1,ends)
        typ=data.get('type') or event
        if typ=='message_start':
            message+=1;active={}
        if typ=='content_block_start' or typ=='content_block_delta' or typ=='content_block_stop':
            c=add_event_tool(active,session_id*1000000+message,data.get('index'),event,data,t)
            if c:out.append(c)
        elif typ=='response.output_item.added':
            item=data.get('item') or {}
            if item.get('type') in ('function_call','custom_tool_call'):
                ident=item.get('id') or item.get('call_id') or data.get('output_index')
                active[('openai',ident)]={'protocol':'openai_sse','tool_use_id':item.get('call_id') or item.get('id') or '',
                    'tool_name':item.get('name') or '', 'first':None,'last':None,'stop':None,'parts':[], 'delta_events':0}
        elif typ in ('response.function_call_arguments.delta','response.custom_tool_call_input.delta'):
            ident=data.get('item_id') or data.get('call_id') or data.get('output_index')
            key=('openai',ident)
            c=active.get(key)
            if c is None:
                c={'protocol':'openai_sse','tool_use_id':str(data.get('call_id') or data.get('item_id') or ''),
                    'tool_name':'','first':None,'last':None,'stop':None,'parts':[], 'delta_events':0}
                active[key]=c
            d=data.get('delta')
            if isinstance(d,str):
                if c['first'] is None:c['first']=t
                c['last']=t;c['parts'].append(d);c['delta_events']+=1
        elif typ in ('response.function_call_arguments.done','response.custom_tool_call_input.done'):
            ident=data.get('item_id') or data.get('call_id') or data.get('output_index')
            c=active.pop(('openai',ident),None)
            if c:
                c['stop']=t;out.append(c)
        elif typ in ('response.failed','response.completed','response.incomplete','message_stop'):
            active={}
    return out


def parse_chunked(raw,pos):
    out=[]
    while True:
        end=raw.find(b'\r\n',pos)
        if end<0:return None
        try:n=int(raw[pos:end].split(b';',1)[0],16)
        except ValueError:return None
        pos=end+2
        if n==0:
            if raw[pos:pos+2]==b'\r\n':return b''.join(out),pos+2
            last=raw.find(b'\r\n\r\n',pos)
            return (b''.join(out),last+4) if last>=0 else None
        if n>MAX_HTTP_REQUEST_BODY or pos+n+2>len(raw) or raw[pos+n:pos+n+2]!=b'\r\n':return None
        out.append(raw[pos:pos+n]);pos+=n+2


def parse_mcp_requests(raw,spans,session):
    out=[];pos=0
    ends=[v[1] for v in spans]
    while pos<len(raw):
        m=HTTP_REQ_RE.search(raw,pos)
        if not m:break
        start=m.start();header_end=raw.find(b'\r\n\r\n',m.end())
        if header_end<0:break
        if header_end-start>64*1024:
            pos=m.end();continue
        header=raw[start:header_end];headers={}
        for line in header.decode('latin1','replace').split('\r\n')[1:]:
            if ':' in line:
                k,v=line.split(':',1);headers[k.strip().lower()]=v.strip()
        body_start=header_end+4
        if 'chunked' in headers.get('transfer-encoding','').lower():
            dec=parse_chunked(raw,body_start)
            if not dec:pos=m.end();continue
            body,next_pos=dec
        else:
            try:n=int(headers.get('content-length','-1'))
            except ValueError:n=-1
            if not (0<=n<=MAX_HTTP_REQUEST_BODY) or body_start+n>len(raw):
                pos=m.end();continue
            body=raw[body_start:body_start+n];next_pos=body_start+n
        pos=max(m.end(),next_pos)
        try:obj=json.loads(body)
        except (ValueError,UnicodeError):continue
        if not isinstance(obj,dict) or obj.get('method')!='tools/call':continue
        params=obj.get('params') or {}
        if not isinstance(params,dict):continue
        meta=params.get('_meta') or {}
        if not isinstance(meta,dict):meta={}
        ident=meta.get('claudecode/toolUseId') or meta.get('tool_use_id') or meta.get('toolUseId') or ''
        # First visible byte of HTTP request = capture-estimated actual request send.
        req_t=time_for_offset(spans,start,ends)
        out.append({'tool_use_id':str(ident) if ident else '', 'tool_name':str(params.get('name') or ''),
                    'send':req_t,'target':str(session['key'][2])+':'+str(session['key'][3]),
                    'transport':'HTTP/1.1 MCP tools/call', 'method':'pcap_exact_tool_use_id' if ident else 'pcap_unidentified'})
    return out


def read_timeline(task_dir):
    p=task_dir/'claude_timeline.jsonl'
    if not p.is_file():return {},False
    res={}
    with p.open('r',encoding='utf-8') as f:
        for line in f:
            try:e=json.loads(line)
            except (ValueError,UnicodeError):continue
            tid=e.get('tool_use_id')
            if not tid:continue
            c=res.setdefault(str(tid),{'tool_use_id':str(tid)})
            if e.get('tool_name'):c['tool_name']=e['tool_name']
            evt=e.get('event')
            try:ts=int(e['unix_ns'])/1e9
            except (KeyError,ValueError,TypeError):continue
            if evt=='tool_dispatch_observed':c['dispatch']=ts
            if evt=='tool_use_generated':c['generated']=ts
            if evt=='tool_result_observed':
                c['result']=ts
                c['result_error']=e.get('is_error','')
    return res,True


def short_name(name):
    return name.rsplit('__',1)[-1].lower() if name else ''


def classify(name):
    """Minimal, conservative operational policy; no evidence of tool native streaming."""
    n=short_name(name).replace('_','-').lower()
    if n in VERIFIED_NATIVE_STREAMING_TOOLS:
        return 'native_streaming_supported','explicit_verified_contract','需要额外核对工具 schema 和端到端分块消费能力；不得仅凭 HTTP chunked 推断'
    # Mutation / external side effects; must have complete and validated argument contract.
    unsafe=(
        'create','post-page','patch','update','delete','remove','drop','alter',
        'insert','write','edit','move','rename','copy','push','merge','commit','execute',
        'run-','exec','shell','bash','terminal','click','type','fill','press','submit',
        'navigate','install','upload','deploy','send','publish','add-','set-','apply',
        'truncate','transaction','grant','revoke','replace','restore','format','save',
        'browser-evaluate','browser-drag','reset','close','checkout','fork','issue-comment'
    )
    # Some POST endpoints express read-only searches, not writes. Check first.
    searchable=('search','list-','get-','retrieve','read-','find','inspect','describe',
                'query','lookup','fetch','stat','info','schema','explain','snapshot',
                'status','health','discover','view-','tree','metadata','open-','select')
    if any(x in n for x in unsafe):
        return 'must_wait_complete','heuristic_tool_name','写入/执行/有副作用的工具，完整参数与校验之前不应执行'
    if any(x in n for x in searchable):
        return 'may_prepare_early','heuristic_tool_name','只表示可能预连接/预取；需要稳定关键参数和权限验证，不能据此提前真正调用'
    return 'unknown_needs_contract','insufficient_evidence','工具名无法证明安全性；需检查 schema、实现、事务语义'


def output_row(task,p,name='',id='',protocol='',pcap_tool=None,mcp=None,log=None,timeline_present=False,gaps=0):
    pc=pcap_tool or {}
    m=mcp or {};l=log or {}
    tool=name or pc.get('tool_name') or m.get('tool_name') or l.get('tool_name') or ''
    tid=id or pc.get('tool_use_id') or m.get('tool_use_id') or l.get('tool_use_id') or ''
    cat,basis,reason=classify(tool)
    fst=pc.get('first');last=pc.get('last');stop=pc.get('stop')
    send=m.get('send') if m.get('method')=='pcap_exact_tool_use_id' else None
    dispatch=l.get('dispatch')
    # MCP traffic: exact observed HTTP start. Built-in/local tools: Claude's runtime
    # dispatch event is observable, but is NOT proof of process execution or remote API send.
    tool_kind=('mcp' if tool.lower().startswith(('mcp__','mcp_')) else
               'server_tool' if pc.get('block_type')=='server_tool_use' else 'built_in_or_other')
    if send is not None:
        execution_evidence=send; evidence_type='pcap_mcp_http_send_exact_id'
    elif dispatch is not None:
        execution_evidence=dispatch; evidence_type='claude_timeline_dispatch_only'
    elif l.get('result') is not None:
        execution_evidence=l['result']; evidence_type='claude_timeline_result_only_not_start'
    else:
        execution_evidence=None; evidence_type='unobserved'
    pieces=pc.get('parts') or []
    raw=''.join(pieces)
    valid=''
    if pc and pieces:
        try:json.loads(raw);valid='yes'
        except (ValueError,TypeError):valid='no'
    early=''
    if send is not None and stop is not None: early='yes' if send<stop else 'no'
    early_evidence=('yes' if execution_evidence<stop else 'no') if execution_evidence is not None and stop is not None and evidence_type!='claude_timeline_result_only_not_start' else ''
    early_dispatch=''
    if dispatch is not None and stop is not None:early_dispatch='yes' if dispatch<stop else 'no'
    status='complete_sse_and_exact_mcp' if pc and pc.get('stop') is not None and send is not None else ('sse_complete_no_mcp' if pc and pc.get('stop') is not None else ('mcp_only' if m and not pc else ('log_only' if l and not pc else 'sse_partial')))
    if pc and pc.get('stop') is not None and send is None:
        if dispatch is not None:status='sse_complete_timeline_dispatch'
        elif l.get('result') is not None:status='sse_complete_timeline_result_only'
        else:status='sse_complete_execution_unobserved'
    if gaps and pc: status+=';tcp_gaps_present'
    if m and m.get('method')!='pcap_exact_tool_use_id': status='mcp_unidentified'
    return {'row_type':'tool_call','task':task,'pcap_file':p.name,'tool_name':tool,
            'short_name':short_name(tool), 'tool_use_id':tid,'protocol':protocol or pc.get('protocol',''),
            'category':cat,'classification_basis':basis,'classification_reason':reason,
            'first_delta_utc':utc(fst),'last_delta_utc':utc(last),'tool_block_stop_utc':utc(stop),
            'mcp_request_send_utc':utc(send),'dispatch_log_utc':utc(dispatch),
            'tool_generated_log_utc':utc(l.get('generated')),
            'tool_result_log_utc':utc(l.get('result')),
            'execution_evidence_utc':utc(execution_evidence),
            'execution_evidence_type':evidence_type,
            'stop_to_execution_evidence_ms':millisecond(stop,execution_evidence),
            'execution_evidence_before_stop':early_evidence,
            'tool_kind':tool_kind,'result_is_error':l.get('result_error',''),
            'first_to_last_delta_ms':millisecond(fst,last),
            'last_delta_to_stop_ms':millisecond(last,stop),
            'stop_to_mcp_send_ms':millisecond(stop,send),
            'stop_to_dispatch_log_ms':millisecond(stop,dispatch),
            'mcp_started_before_tool_stop':early,
            'dispatch_before_tool_stop':early_dispatch,
            'delta_events':pc.get('delta_events',0),'tool_argument_bytes':len(raw.encode('utf8')) if pc else '',
            'arguments_json_valid':valid,'mcp_match_method':m.get('method','none'),
            'mcp_target':m.get('target',''),'mcp_transport':m.get('transport',''),
            'time_source':'pcap_event_complete_and_http_first_byte' if pc and send is not None else ('pcap_sse_plus_timeline' if pc and l else ('pcap_sse' if pc else ('pcap_mcp' if m else 'timeline_only'))),
            'timeline_present':'yes' if timeline_present else 'no',
            'tcp_gap_count':gaps,'tool_calls':1,
            'exact_mcp_matches':int(status.startswith('complete_sse_and_exact_mcp')),
            'early_mcp_count':int(early=='yes'),
            'status':status,'notes':'类别是研究假设，非工具接口能力证明'}


def process_task(task,pcap):
    timeline,has_timeline=read_timeline(pcap.parent)
    sessions=streams_in_pcap(pcap)
    sse=[];mcps=[];gaps=0
    for s in sessions:
        chunks,g=rebuild(s['segments'])
        gaps+=g
        for b,spans in chunks:
            if s['direction']=='sse':sse.extend(parse_sse(b,spans,s['id']))
            elif s['direction']=='mcp' and (b'"tools/call"' in b or b'tools/call' in b):
                mcps.extend(parse_mcp_requests(b,spans,s))
    # Exact ID matching only; no guessing from tool-name temporal proximity.
    by_id=collections.defaultdict(list);unlinked=[]
    for m in mcps:
        if m['tool_use_id']:by_id[m['tool_use_id']].append(m)
        else:unlinked.append(m)
    rows=[];seen_sse_ids=set()
    for c in sse:
        tid=str(c.get('tool_use_id') or '')
        matches=by_id.get(tid,[]) if tid else []
        m=matches.pop(0) if matches else None
        l=timeline.get(tid)
        rows.append(output_row(task,pcap,pcap_tool=c,mcp=m,log=l,timeline_present=has_timeline,gaps=gaps))
        if tid:seen_sse_ids.add(tid)
    # All Claude tools in timeline without matching SSE (including Bash/Read/Write/WebSearch).
    for tid,l in timeline.items():
        if tid not in seen_sse_ids:
            matches=by_id.get(tid,[])
            m=matches.pop(0) if matches else None
            rows.append(output_row(task,pcap,id=tid,log=l,mcp=m,timeline_present=has_timeline,gaps=gaps))
    for matches in by_id.values():
        for m in matches:
            rows.append(output_row(task,pcap,mcp=m,timeline_present=has_timeline,gaps=gaps))
    for m in unlinked:
        rows.append(output_row(task,pcap,mcp=m,timeline_present=has_timeline,gaps=gaps))
    # Report a diagnostic row if this task offers no usable tool evidence.
    if not rows:
        rows.append({'row_type':'task_no_tools','task':task,'pcap_file':pcap.name,
                     'status':'no_usable_tools_or_encrypted','notes':'可能是加密 MCP、非 SSE 或无工具调用；不得解释为无工具开销',
                     'tcp_gap_count':gaps,'timeline_present':'yes' if has_timeline else 'no'})
    return rows


def main():
    ap=argparse.ArgumentParser(description='离线关联 LLM 工具参数 SSE 时间与 MCP HTTP 发出时间；仅生成 analyze_tool.csv')
    ap.add_argument('path',help='实验大目录、单任务目录、或单个 .pcapng')
    opts=ap.parse_args()
    try:tasks,out=discover(Path(opts.path).expanduser().resolve())
    except (OSError,ValueError) as e:ap.error(str(e))
    rows=[]
    for name,pcap in tasks:
        try:
            batch=process_task(name,pcap)
            environment=(name.split('/',1)[0] if '/' in name else
                (Path(opts.path).expanduser().resolve().name if Path(opts.path).is_dir() else pcap.parent.name))
            for item in batch:item['environment']=environment
            rows.extend(batch)
        except Exception as e:
            rows.append({'row_type':'task_error','task':name,'pcap_file':pcap.name,
                         'status':'error','notes':str(e)[:180]})
    # One CSV contains ALL tool calls followed by tool-level evidence summaries.
    group=collections.defaultdict(list)
    for r in rows:
        if r.get('row_type')=='tool_call' and r.get('tool_name'):
            group[(r.get('environment',''),r.get('tool_name',''))].append(r)
    for (env,tool),calls in sorted(group.items()):
        rows.append({'row_type':'env_tool_summary','environment':env, 'tool_name':tool,
            'short_name':short_name(tool),'category':calls[0]['category'],
            'classification_basis':calls[0]['classification_basis'],
            'classification_reason':calls[0]['classification_reason'],
            'tool_calls':len(calls),
            'exact_mcp_matches':sum(c['mcp_match_method']=='pcap_exact_tool_use_id' for c in calls),
            'early_mcp_count':sum(c['mcp_started_before_tool_stop']=='yes' for c in calls),
            'status':'aggregated_tool_summary',
            'notes':'汇总行；按 tool_name 统计，缺少精确匹配时不能推断无提前执行'})
    with out.open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=FIELDS,extrasaction='ignore');w.writeheader();w.writerows(rows)
    c=collections.Counter(r.get('status','') for r in rows)
    print('完成：%d 个任务，%d 行；输出：%s'%(len(tasks),len(rows),out))
    print('精确 SSE↔MCP 匹配：%d；SSE 已结束但没有 MCP HTTP 发送证据：%d'%(
        sum(r.get('status','').startswith('complete_sse_and_exact_mcp') for r in rows),
        sum(r.get('status','').startswith('sse_complete_no_mcp') for r in rows)))
    print('SSE↔Claude 分发日志可关联：%d；有工具结果日志：%d'% (
        sum(bool(r.get('row_type')=='tool_call' and r.get('first_delta_utc') and r.get('dispatch_log_utc')) for r in rows),
        sum(bool(r.get('row_type')=='tool_call' and r.get('tool_result_log_utc')) for r in rows)))
    print('注意：所有 Claude 工具均列出；对非 MCP 工具，dispatch 只证明框架分发，不能当作真实网络发送或进程执行。')

if __name__=='__main__':main()

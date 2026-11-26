#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线批量 SSE 编码开销统计。Python 3.9+，仅标准库。
用法: python3 analyze_sse.py /path/to/task_collection
只在输入目录生成 analyze_sse.csv；不会访问网络，不修改抓包。
识别 Anthropic 与 OpenAI 的工具参数增量、文本增量；统计 SSE 编码冗余，并模拟文本增量按 50/100/200 ms 合并的编码收益与等待时间。
结合网关方向的 TCP/IP 包及 SSE 字节边界，保留原有网络开销与事件/包映射分析。
只使用本地 PCAPNG，不声称被动抓包能证明优化后收益或实际瓶颈。
"""
import argparse
import bisect
import collections
import csv
import copy
import hashlib
import ipaddress
import json
import re
import struct
import sys
from pathlib import Path

GATEWAY_IPS = {'192.168.3.125', '172.17.192.1'}
GATEWAY_PORT = 8317
OUT_NAME = 'analyze_sse.csv'
# A fixed set of observed-receipt-time windows for consistent CSV comparisons.
TEXT_WINDOWS_MS = (50, 100, 200)


def _pcapng_options(buf, end):
    """Read aligned PCAPNG options from an IDB; supports if_tsresol/if_tsoffset."""
    out = {}
    i = 0
    while i + 4 <= len(buf):
        code, n = struct.unpack(end+'HH', buf[i:i+4])
        i += 4
        if code == 0:
            break
        if i+n > len(buf):
            break
        out[code] = buf[i:i+n]
        i += (n + 3) & ~3
    return out

def iter_pcapng(path):
    """Yield (linktype, packet, original_frame_length, epoch_timestamp_ns|None).

    Stream PCAPNG; retain precise time resolution from each interface's IDB.
    SPB/PB without a timestamp yields None, never fabricated time values.
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
                    options = _pcapng_options(body[8:], end)
                    ts_raw = options.get(9, b'\x06')
                    r = ts_raw[0] if ts_raw else 6
                    units = (2**(r & 0x7f)) if r & 0x80 else 10**r
                    offset = struct.unpack(end+'q', options[14][:8])[0] if len(options.get(14,b'')) >= 8 else 0
                    interfaces.append((struct.unpack(end+'H',body[:2])[0], units, offset))
            elif typ == 6 and len(body)>=20:
                iid,hi,lo,caplen,origlen = struct.unpack(end+'IIIII',body[:20])
                if iid < len(interfaces) and caplen <= len(body)-20:
                    linktype, units, offset = interfaces[iid]
                    stamp = ((hi<<32) | lo) * 1000000000 // units + offset*1000000000
                    yield linktype, body[20:20+caplen], origlen, stamp
            elif typ == 2 and len(body)>=20:
                iid,drop,hi,lo,caplen,origlen = struct.unpack(end+'HHIIII',body[:20])
                if iid < len(interfaces) and caplen <= len(body)-20:
                    linktype, units, offset = interfaces[iid]
                    stamp = ((hi<<32) | lo) * 1000000000 // units + offset*1000000000
                    yield linktype, body[20:20+caplen], origlen, stamp

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

def ip_tcp_header_lengths(linktype,frame):
    """返回观察到的 IPv4/IPv6(+扩展) 和 TCP 报头字节，不包括链路层。"""
    if linktype==1:
        if len(frame)<14:return 0,0
        o=12;et=int.from_bytes(frame[o:o+2],'big');o+=2
        while et in (0x8100,0x88a8,0x9100):
            if len(frame)<o+4:return 0,0
            et=int.from_bytes(frame[o+2:o+4],'big');o+=4
    elif linktype==113:
        if len(frame)<16:return 0,0
        et=int.from_bytes(frame[14:16],'big');o=16
    elif linktype==276:
        if len(frame)<20:return 0,0
        et=int.from_bytes(frame[:2],'big');o=20
    elif linktype==101:
        o=0;et=0x0800 if frame and frame[0]>>4==4 else 0x86dd
    elif linktype==0:
        if len(frame)<4:return 0,0
        et=0x0800 if int.from_bytes(frame[:4],'little')==2 else 0x86dd;o=4
    else:return 0,0
    if et==0x0800:
        if len(frame)<o+20 or frame[o]>>4!=4:return 0,0
        iph=(frame[o]&15)*4;t=o+iph
    elif et==0x86dd:
        if len(frame)<o+40 or frame[o]>>4!=6:return 0,0
        nxt=frame[o+6];pos=o+40
        for _ in range(8):
            if nxt==6:break
            if nxt in (0,43,60) and len(frame)>=pos+2:
                step=(frame[pos+1]+1)*8;nxt=frame[pos];pos+=step
            elif nxt==44 and len(frame)>=pos+8:
                nxt=frame[pos];pos+=8
            else:return 0,0
        if nxt!=6:return 0,0
        iph=pos-o;t=pos
    else:return 0,0
    if len(frame)<t+20:return 0,0
    tcph=(frame[t+12]>>4)*4
    if tcph<20 or len(frame)<t+tcph:return 0,0
    return iph,tcph

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


EVENT_RE = re.compile(rb'(?:(?:event:|data:|id:)[^\n]*\r?\n)+(?:\r?\n)')
PARTIAL_RE = re.compile(rb'"partial_json"\s*:\s*("(?:\\.|[^"\\])*")')

COLUMNS = [
    'row_type','task','pcap_file','status','error','sse_events',
    'tool_blocks','valid_tool_blocks','incomplete_tool_blocks',
    'input_json_delta_events','tiny_delta_le_8_pct',
    'tool_payload_bytes','sse_delta_encoded_bytes','encoded_overhead_bytes',
    'encoded_overhead_pct','one_event_encoded_bytes_est',
    'removable_encoded_bytes_est','removable_encoded_pct_est',
    'high_fragmentation_blocks_ge_10','tcp_stream_gaps',
    'sse_tool_delta_events_all','openai_tool_delta_events','anthropic_tool_delta_events',
    'openai_text_delta_events','openai_text_delta_encoded_bytes','openai_text_payload_bytes',
    'sse_encoded_bytes_total','sse_tool_delta_pct_of_all_sse',
    'removable_pct_of_all_sse_est','websocket_detected',
    'gateway_down_frame_bytes','gateway_down_tcp_payload_bytes_captured',
    'gateway_down_tcp_payload_unique_bytes','gateway_down_payload_packets_captured',
    'gateway_down_payload_packets_unique','gateway_down_ack_only_packets',
    'gateway_down_nonpayload_frame_bytes','gateway_down_frame_headers_and_other_bytes',
    'gateway_up_ack_only_packets','gateway_up_ack_only_frame_bytes',
    'gateway_down_repeated_tcp_payload_bytes',
    'gateway_down_payload_gt_1460_packets',
    'sse_pct_of_down_tcp_unique_payload', 'sse_pct_of_down_frame_bytes',
    'removable_pct_of_down_tcp_unique_payload_est','removable_pct_of_down_frame_bytes_est',
    'sse_events_mapped_to_tcp','sse_events_in_one_tcp_segment',
    'sse_events_spanning_multiple_tcp_segments','sse_tcp_segments_with_events',
    'sse_tcp_segments_with_multiple_events','sse_event_tcp_segment_links',
    'sse_events_per_tcp_segment_avg',
    'sse_carrier_tcp_payload_bytes_captured','sse_carrier_frame_bytes',
    'sse_carrier_frame_other_bytes',
    'sse_events_spanning_multiple_pct','sse_carrier_segments_multi_event_pct',
    'gateway_down_ip_header_bytes','gateway_down_tcp_header_bytes',
    'sse_carrier_ip_header_bytes','sse_carrier_tcp_header_bytes',
    'text_blocks','valid_text_blocks','incomplete_text_blocks',
    'text_blocks_in_tool_messages','text_blocks_in_client_tool_messages',
    'text_blocks_in_server_tool_messages','text_blocks_in_text_only_messages',
    'text_delta_events','text_delta_encoded_bytes','text_payload_bytes',
    'anthropic_text_delta_events','anthropic_text_delta_encoded_bytes','anthropic_text_payload_bytes',
    'text_events_in_valid_blocks','text_valid_delta_encoded_bytes','text_valid_payload_bytes',
    'text_tiny_delta_le_8_pct','text_encoded_overhead_bytes','text_encoded_overhead_pct',
    'text_coverage_pct','text_metadata_variant_blocks','text_blocks_missing_timestamps',
    'text_one_event_encoded_bytes_est','text_one_event_removable_bytes_est',
    'text_one_event_removable_pct_est','text_delta_pct_of_all_sse',
    'text_50ms_batches_est','text_50ms_encoded_bytes_est','text_50ms_removable_bytes_est',
    'text_50ms_removable_pct_est','text_50ms_delay_p50_ms','text_50ms_delay_p90_ms',
    'text_100ms_batches_est','text_100ms_encoded_bytes_est','text_100ms_removable_bytes_est',
    'text_100ms_removable_pct_est','text_100ms_delay_p50_ms','text_100ms_delay_p90_ms',
    'text_200ms_batches_est','text_200ms_encoded_bytes_est','text_200ms_removable_bytes_est',
    'text_200ms_removable_pct_est','text_200ms_delay_p50_ms','text_200ms_delay_p90_ms',
    'text_100ms_removable_pct_of_all_sse_est',
    # 事件类别明细行专用列，原有任务和 TOTAL 统计列保持不变。
    'event_category','event_type','event_count','event_encoded_bytes',
]
SUM_KEYS=['sse_events','tool_blocks','valid_tool_blocks','incomplete_tool_blocks',
          'input_json_delta_events','tool_payload_bytes','sse_delta_encoded_bytes',
          'encoded_overhead_bytes','one_event_encoded_bytes_est',
          'removable_encoded_bytes_est','high_fragmentation_blocks_ge_10','tcp_stream_gaps',
          'sse_tool_delta_events_all','openai_tool_delta_events','anthropic_tool_delta_events',
          'openai_text_delta_events','openai_text_delta_encoded_bytes','openai_text_payload_bytes',
          'sse_encoded_bytes_total','websocket_detected',
          'gateway_down_frame_bytes','gateway_down_tcp_payload_bytes_captured',
          'gateway_down_tcp_payload_unique_bytes','gateway_down_payload_packets_captured',
          'gateway_down_payload_packets_unique','gateway_down_ack_only_packets',
          'gateway_down_nonpayload_frame_bytes','gateway_down_frame_headers_and_other_bytes',
          'gateway_up_ack_only_packets','gateway_up_ack_only_frame_bytes',
          'gateway_down_repeated_tcp_payload_bytes','gateway_down_payload_gt_1460_packets',
          'sse_events_mapped_to_tcp','sse_events_in_one_tcp_segment',
          'sse_events_spanning_multiple_tcp_segments','sse_tcp_segments_with_events',
          'sse_tcp_segments_with_multiple_events','sse_event_tcp_segment_links',
          'sse_carrier_tcp_payload_bytes_captured','sse_carrier_frame_bytes',
          'sse_carrier_frame_other_bytes',
          'gateway_down_ip_header_bytes','gateway_down_tcp_header_bytes',
           'sse_carrier_ip_header_bytes','sse_carrier_tcp_header_bytes',
           'text_blocks','valid_text_blocks','incomplete_text_blocks',
           'text_blocks_in_tool_messages','text_blocks_in_client_tool_messages',
           'text_blocks_in_server_tool_messages','text_blocks_in_text_only_messages',
           'text_delta_events','text_delta_encoded_bytes','text_payload_bytes',
           'anthropic_text_delta_events','anthropic_text_delta_encoded_bytes','anthropic_text_payload_bytes',
           'text_events_in_valid_blocks','text_valid_delta_encoded_bytes','text_valid_payload_bytes',
           'text_metadata_variant_blocks','text_blocks_missing_timestamps',
           'text_one_event_encoded_bytes_est','text_one_event_removable_bytes_est',
           'text_50ms_batches_est','text_50ms_encoded_bytes_est','text_50ms_removable_bytes_est',
           'text_100ms_batches_est','text_100ms_encoded_bytes_est','text_100ms_removable_bytes_est',
           'text_200ms_batches_est','text_200ms_encoded_bytes_est','text_200ms_removable_bytes_est']

def pct(a,b):
    return round(100*a/b,2) if b else ''

def choose_pcap(folder):
    wanted=folder/'raw_traffic.pcapng'
    if wanted.is_file():return wanted
    opts=sorted(folder.glob('*.pcapng'))
    if len(opts)==1:return opts[0]
    if len(opts)>1:raise ValueError('目录包含多个 pcapng，请明确保留一个或命名 raw_traffic.pcapng: '+str(folder))
    return None

def discover(root):
    if not root.exists():raise ValueError('路径不存在: '+str(root))
    if root.is_file():
        if root.suffix.lower()!='.pcapng':raise ValueError('需要 .pcapng 文件或实验目录')
        return [(root.parent.name,root)],root.parent/OUT_NAME
    direct=choose_pcap(root)
    if direct:return [(root.name,direct)],root/OUT_NAME
    tasks=[]
    for folder in sorted(p for p in root.rglob('*') if p.is_dir()):
        file=choose_pcap(folder)
        if file:tasks.append((str(folder.relative_to(root)),file))
    if not tasks:raise ValueError('没有找到任何 .pcapng')
    return tasks,root/OUT_NAME

def gateway_down_sessions(path):
    """返回抓包观察到的网关下行 TCP 会话、包级数据及方向统计；不复制造成副作用。"""
    active={};sessions=[];net=collections.Counter();down_meta={}
    pid=0
    for link,frame,frame_len,stamp_ns in iter_pcapng(path):
        pkt=tcp_packet(link,frame)
        if pkt is None:continue
        src,sport,dst,dport,seq,flags,payload=pkt
        if src in GATEWAY_IPS and sport==GATEWAY_PORT:
            direction='down'
        elif dst in GATEWAY_IPS and dport==GATEWAY_PORT:
            direction='up'
        else:continue
        net['gateway_'+direction+'_frame_bytes']+=frame_len
        if flags == 0x10 and len(payload)==0:
            net['gateway_'+direction+'_ack_only_packets']+=1
            net['gateway_'+direction+'_ack_only_frame_bytes']+=frame_len
        if direction!='down':continue
        ip_h,tcp_h=ip_tcp_header_lengths(link,frame)
        net['gateway_down_ip_header_bytes']+=ip_h
        net['gateway_down_tcp_header_bytes']+=tcp_h
        net['gateway_down_tcp_payload_bytes_captured']+=len(payload)
        net['gateway_down_frame_headers_and_other_bytes']+=max(0,frame_len-len(payload))
        key=(src,sport,dst,dport)
        if flags & 0x02:  # 通常是服务器 SYN+ACK；端口复用时重开会话
            old=active.get(key)
            if old is None or old['syn_seq']!=seq:
                entry={'syn_seq':seq,'segments':[]};active[key]=entry;sessions.append(entry)
        if not payload:
            net['gateway_down_nonpayload_frame_bytes']+=frame_len
            continue
        net['gateway_down_payload_packets_captured']+=1
        if len(payload)>1460:net['gateway_down_payload_gt_1460_packets']+=1
        if key not in active:
            entry={'syn_seq':None,'segments':[]};active[key]=entry;sessions.append(entry)
        pid+=1
        down_meta[pid]={'frame_len':frame_len,'payload_len':len(payload),'ip_h':ip_h,'tcp_h':tcp_h,'time_ns':stamp_ns}
        active[key]['segments'].append((seq,payload,pid))
    return sessions,net,down_meta


def contiguous_chunks_with_packet_spans(segs):
    """TCP 去重/重组：映射原始 TCP payload 字节区间到原始报文，拒绝跨缺口合并。"""
    if not segs:return [],0,0,0
    segs.sort(key=lambda x:x[0]);chunks=[]
    current=bytearray();spans=[];expected=None;unique=0;gaps=0;unique_packets=set()
    for seq,data,pid in segs:
        if expected is None:expected=seq
        if seq>expected:
            if current:chunks.append((bytes(current),spans))
            current=bytearray();spans=[];expected=seq;gaps+=1
        overlap=max(0,expected-seq)
        if overlap>=len(data):continue
        start=len(current);added=data[overlap:]
        current.extend(added);spans.append((start,len(current),pid))
        unique+=len(added);unique_packets.add(pid);expected+=len(added)
    if current:chunks.append((bytes(current),spans))
    return chunks,unique,gaps,len(unique_packets)


def event_packet_ids(start,end,spans,ends):
    """一个完整 SSE frame 的字节区间可能交叉多个 TCP payload 数据段。"""
    i=bisect.bisect_right(ends,start)
    ids=set()
    while i<len(spans) and spans[i][0]<end:
        a,b,pid=spans[i]
        if a<end and start<b:ids.add(pid)
        i+=1
    return ids

def events_from_chunk(raw):
    """保留原始 SSE 序列化字节；不把 TCP 分片数当事件数。"""
    for m in EVENT_RE.finditer(raw):
        frame=m.group()
        obj=None
        for line in frame.splitlines():
            if line.startswith(b'data:'):
                try:obj=json.loads(line[5:].strip())
                except (ValueError,UnicodeError):pass
        if isinstance(obj,dict):yield obj,frame,m.start(),m.end()

def classify_sse_event(obj):
    """按消息语义分类；未知事件保留原始类型，避免统计遗漏。"""
    typ = obj.get('type', '')
    if not isinstance(typ, str):
        typ = str(typ)
    if typ == 'content_block_delta':
        delta = obj.get('delta') or {}
        sub = delta.get('type', 'unknown') if isinstance(delta, dict) else 'unknown'
        if sub == 'input_json_delta': category = '工具参数增量'
        elif sub == 'text_delta': category = '文本增量'
        elif sub in ('thinking_delta', 'signature_delta'): category = '推理相关增量'
        else: category = '其他内容增量'
        return category, str(sub)
    if typ == 'content_block_start':
        block = obj.get('content_block') or {}
        sub = block.get('type', 'unknown') if isinstance(block, dict) else 'unknown'
        return '内容块开始', 'content_block_start: ' + str(sub)
    if typ == 'content_block_stop':
        return '内容块结束', typ
    if typ == 'message_start':
        return '消息开始', typ
    if typ == 'message_delta':
        return '消息结束信息', typ
    if typ == 'message_stop':
        return '消息结束标志', typ
    if typ.startswith('response.'):
        if typ in ('response.output_text.delta', 'response.refusal.delta'):
            return '文本增量', typ
        if typ in ('response.function_call_arguments.delta', 'response.custom_tool_call_input.delta'):
            return '工具参数增量', typ
        if typ in ('response.function_call_arguments.done', 'response.custom_tool_call_input.done'):
            return '工具参数结束', typ
        if typ in ('response.created', 'response.in_progress'):
            return '消息开始/进行', typ
        if typ in ('response.completed', 'response.failed', 'response.incomplete'):
            return '消息结束信息', typ
        if typ.startswith('response.output_text.'):
            return '文本状态', typ
        return '其他 OpenAI 事件', typ
    if typ == 'ping':
        return '心跳', typ
    return '其他事件', typ or '(missing type)'


def delta_string_wire_len(frame):
    m=PARTIAL_RE.search(frame)
    return len(m.group(1)) if m else None

def _serialize_merge(template, key, value):
    # Reencode the first real event using its original type, retaining metadata.
    # Estimate is comparable to actual event encoding, NOT network/frame savings.
    import copy
    obj=copy.deepcopy(template)
    obj[key]=value
    event=obj.get('type','')
    return len(('event: '+event+'\n'+'data: '+json.dumps(obj,ensure_ascii=False,separators=(',',':'))+'\n\n').encode('utf8'))


def quantile(values, q):
    """Linear interpolated quantile, returning blank if there are no valid samples."""
    if not values:
        return ''
    values = sorted(values)
    x = (len(values)-1)*q
    i = int(x)
    return round(values[i] + (values[min(i+1, len(values)-1)]-values[i])*(x-i), 3)


def reencode_delta(original, obj, dialect, text):
    """Keep the first event's SSE envelope, reserialize its JSON with new delta.

    This is an *offline counterfactual*: changing SSE event count can require an
    application-compatible sender/receiver protocol, especially for sequence ids.
    """
    item = copy.deepcopy(obj)
    if dialect == 'anthropic':
        item['delta']['text'] = text
    else:
        item['delta'] = text
    # Reuse exact prefix / line endings from the first observed SSE event.
    line = re.search(rb'(?m)^data:[^\r\n]*', original)
    payload = json.dumps(item, ensure_ascii=False, separators=(',',':')).encode('utf8')
    if line:
        # Keep the original newline style and header lines; replace this data line.
        return len(original) - (line.end()-line.start()) + len(b'data: ') + len(payload)
    return _serialize_merge(item, 'delta', item['delta'])


def get_metadata_signature(obj, dialect):
    """Detect varying non-content fields, which may prevent drop-in SSE merging."""
    o = copy.deepcopy(obj)
    if dialect == 'anthropic':
        o.get('delta', {}).pop('text', None)
    else:
        o.pop('delta', None)
    return json.dumps(o, ensure_ascii=False, sort_keys=True, separators=(',',':'))


def text_batches(parts, window_ms, stop_ns):
    """Greedy receipt-time batching *within one complete text block*.

    Each event timestamp is the capture timestamp for the packet carrying its
    final byte. A batch flush is scheduled by its first event's receipt + window
    (or block_stop, whichever earlier); event delay is nonnegative and <=window.
    """
    window_ns = window_ms * 1000000
    batches = []
    start = 0
    while start < len(parts):
        first_t = parts[start]['time_ns']
        finish = start + 1
        while finish < len(parts) and parts[finish]['time_ns'] - first_t < window_ns:
            finish += 1
        batch = parts[start:finish]
        flush_ns = first_t + window_ns
        if stop_ns is not None:
            flush_ns = min(flush_ns, max(stop_ns, batch[-1]['time_ns']))
        flush_ns = max(flush_ns, batch[-1]['time_ns'])
        batches.append((batch,flush_ns))
        start = finish
    return batches


def build_text_block(group, dialect, task, pcap_name, row, window_delays):
    """Finalize a complete text block; add unbiased observed totals and model estimates."""
    parts = group['text_parts']
    if not parts:
        return None
    row['text_blocks'] += 1
    total_text = ''.join(p['text'] for p in parts)
    # OpenAI done payload can validate captured delta completeness.
    done = group.get('done')
    if isinstance(done, str) and done != total_text:
        row['incomplete_text_blocks'] += 1
        return None
    row['valid_text_blocks'] += 1
    n = len(parts)
    raw_bytes = sum(len(p['frame']) for p in parts)
    payload_bytes = len(total_text.encode('utf8'))
    row['text_events_in_valid_blocks'] += n
    row['text_valid_delta_encoded_bytes'] += raw_bytes
    row['text_valid_payload_bytes'] += payload_bytes
    if len(set(get_metadata_signature(p['obj'], dialect) for p in parts)) > 1:
        row['text_metadata_variant_blocks'] += 1
        varying_meta = 1
    else:
        varying_meta = 0
    one_bytes = reencode_delta(parts[0]['frame'],parts[0]['obj'],dialect,total_text)
    row['text_one_event_encoded_bytes_est'] += one_bytes
    row['text_one_event_removable_bytes_est'] += max(0,raw_bytes-one_bytes)
    timestamps = [p['time_ns'] for p in parts]
    stop_ns = group.get('stop_ns')
    have_times = all(t is not None for t in timestamps)
    if not have_times:
        row['text_blocks_missing_timestamps'] += 1
    output = {
        'task':task,'pcap_file':pcap_name,'dialect':dialect,
        'message_index':group.get('message_index',''),
        'block_index':group.get('block_index',''),
        'delta_events':n,'payload_bytes':payload_bytes,
        'sse_delta_encoded_bytes':raw_bytes,'sse_overhead_bytes':raw_bytes-payload_bytes,
        'tiny_delta_le_8_events':sum(len(p['text'].encode('utf8')) <= 8 for p in parts),
        'first_delta_epoch_ns':timestamps[0] if have_times else '',
        'last_delta_epoch_ns':timestamps[-1] if have_times else '',
        'observed_delta_span_ms':round((timestamps[-1]-timestamps[0])/1e6,3) if have_times else '',
        'metadata_varies_between_deltas':varying_meta,
        'content_sha256':hashlib.sha256(total_text.encode('utf8')).hexdigest(),
        'one_event_encoded_bytes_est':one_bytes,
        'one_event_saving_bytes_est':max(0,raw_bytes-one_bytes),
    }
    for window in TEXT_WINDOWS_MS:
        label = f'text_{window}ms'
        if not have_times:
            output[label+'_batches'] = ''
            output[label+'_bytes_est'] = ''
            output[label+'_savings_est'] = ''
            output[label+'_delay_p90_ms'] = ''
            continue
        batches = text_batches(parts, window, stop_ns)
        new_bytes = 0
        local_delays = []
        for batch, flush in batches:
            new_bytes += reencode_delta(batch[0]['frame'], batch[0]['obj'], dialect,
                                        ''.join(p['text'] for p in batch))
            local_delays.extend(max(0,(flush-p['time_ns'])/1e6) for p in batch)
        saving = max(0,raw_bytes-new_bytes)
        row[label+'_batches_est'] += len(batches)
        row[label+'_encoded_bytes_est'] += new_bytes
        row[label+'_removable_bytes_est'] += saving
        window_delays[window].extend(local_delays)
        output[label+'_batches'] = len(batches)
        output[label+'_bytes_est'] = new_bytes
        output[label+'_savings_est'] = saving
        output[label+'_delay_p90_ms'] = quantile(local_delays,0.9)
    return output


def text_finalize(group, dialect, task, pcap_name, row, window_delays, details):
    if group and group.get('text_parts'):
        record = build_text_block(group, dialect, task, pcap_name, row, window_delays)
        if record is not None:
            details.append(record)


def text_metrics_final(row, window_delays):
    row['text_encoded_overhead_bytes'] = row['text_delta_encoded_bytes'] - row['text_payload_bytes']
    row['text_encoded_overhead_pct'] = pct(row['text_encoded_overhead_bytes'],row['text_delta_encoded_bytes'])
    row['text_delta_pct_of_all_sse'] = pct(row['text_delta_encoded_bytes'],row['sse_encoded_bytes_total'])
    row['text_coverage_pct'] = pct(row['text_events_in_valid_blocks'],row['text_delta_events'])
    row['text_one_event_removable_pct_est'] = pct(row['text_one_event_removable_bytes_est'],row['text_valid_delta_encoded_bytes'])
    for window in TEXT_WINDOWS_MS:
        p = f'text_{window}ms'
        # Only complete, timestamped text blocks participate in window simulations.
        row[p+'_removable_pct_est'] = pct(row[p+'_removable_bytes_est'],row['text_valid_delta_encoded_bytes']) if not row['text_blocks_missing_timestamps'] else ''
        row[p+'_delay_p50_ms'] = quantile(window_delays[window],0.5)
        row[p+'_delay_p90_ms'] = quantile(window_delays[window],0.9)
    row['text_100ms_removable_pct_of_all_sse_est'] = pct(row['text_100ms_removable_bytes_est'],row['sse_encoded_bytes_total'])
    row['text_tiny_delta_le_8_pct'] = pct(row.get('_tiny_text_count',0),row['text_delta_events'])
    row.pop('_tiny_text_count',None)

def analyze_one(task,pcap):
    row={k:0 for k in SUM_KEYS}
    row.update(row_type='task',task=task,pcap_file=pcap.name,status='no_sse',error='')
    small=0;gaps=0;detected_ws=False
    details = []
    event_breakdown = collections.Counter()
    delays = {w:[] for w in TEXT_WINDOWS_MS}
    message_index = 0
    tool_message_indices = set()
    client_tool_message_indices = set()
    server_tool_message_indices = set()
    segments_with_events=set();segments_with_multiple_events=set()
    sessions,net,packet_meta=gateway_down_sessions(pcap)
    row.update(net)
    # 即使不是 SSE 也统计网关方向的已捕获帧字节。
    for session in sessions:
        chunks,unique,g,unique_packets=contiguous_chunks_with_packet_spans(session['segments'])
        row['gateway_down_tcp_payload_unique_bytes']+=unique
        row['gateway_down_payload_packets_unique']+=unique_packets
        gaps+=g
        for raw,spans in chunks:
            if b'101 Switching Protocols' in raw[:1024] or b'Sec-WebSocket-Accept:' in raw[:1024]:
                detected_ws=True
            # Different SSE dialects use different block delimiters. TCP reassembly is mandatory.
            active={}
            ends=[x[1] for x in spans]
            for obj,frame,start,end in events_from_chunk(raw):
                ids=event_packet_ids(start,end,spans,ends)
                count=len(ids)
                if count:
                    row['sse_events_mapped_to_tcp']+=1
                    row['sse_event_tcp_segment_links']+=count
                    if count==1:row['sse_events_in_one_tcp_segment']+=1
                    else:row['sse_events_spanning_multiple_tcp_segments']+=1
                    for pid in ids:
                        # 数据段可能跨 chunk 多个事件；须按唯一 pid 聚合
                        if pid in segments_with_events:segments_with_multiple_events.add(pid)
                        segments_with_events.add(pid)
                typ=obj.get('type','');idx=obj.get('index')
                event_time_ns=max((packet_meta[p]['time_ns'] for p in ids if packet_meta[p]['time_ns'] is not None), default=None)
                row['sse_events']+=1
                row['sse_encoded_bytes_total']+=len(frame)
                category, event_type = classify_sse_event(obj)
                event_breakdown[(category,event_type,'count')] += 1
                event_breakdown[(category,event_type,'bytes')] += len(frame)
                if typ in ('message_start','response.created'):
                    for old in active.values():
                        if old.get('text_parts'):
                            row['incomplete_text_blocks'] += 1
                    active={}
                    message_index += 1
                if typ=='content_block_start':
                    block=obj.get('content_block') or {}
                    active[('anthropic',idx)]={'tool':block.get('type') in ('tool_use','server_tool_use','mcp_tool_use') or bool(block.get('name')),
                          'parts':[],'frames':[],'objs':[],
                          'text_parts':[],'message_index':message_index,'block_index':idx}
                    if active[('anthropic',idx)]['tool']:
                        tool_message_indices.add(message_index)
                        if block.get('type') == 'server_tool_use':
                            server_tool_message_indices.add(message_index)
                        else:
                            client_tool_message_indices.add(message_index)
                elif typ=='content_block_delta':
                    d=obj.get('delta') or {}
                    if d.get('type')=='input_json_delta':
                        a=active.get(('anthropic',idx))
                        if a is not None and isinstance(d.get('partial_json'),str):
                            a['parts'].append(d['partial_json']);a['frames'].append(frame);a['objs'].append(obj)
                            row['anthropic_tool_delta_events']+=1
                    elif d.get('type')=='text_delta' and isinstance(d.get('text'),str):
                        text = d['text']
                        row['text_delta_events']+=1
                        row['anthropic_text_delta_events']+=1
                        row['text_delta_encoded_bytes']+=len(frame)
                        row['anthropic_text_delta_encoded_bytes']+=len(frame)
                        row['text_payload_bytes']+=len(text.encode('utf8'))
                        row['anthropic_text_payload_bytes']+=len(text.encode('utf8'))
                        row['_tiny_text_count']=row.get('_tiny_text_count',0)+int(len(text.encode('utf8'))<=8)
                        a=active.get(('anthropic',idx))
                        if a is None:
                            row['incomplete_text_blocks']+=1
                        else:
                            a['text_parts'].append({'text':text,'frame':frame,'obj':obj,'time_ns':event_time_ns})
                elif typ=='content_block_stop':
                    a=active.pop(('anthropic',idx),None)
                    if a is not None:
                        finish(a,'anthropic',row)
                        a['stop_ns']=event_time_ns
                        text_finalize(a,'anthropic',task,pcap.name,row,delays,details)
                elif typ in ('response.custom_tool_call_input.delta','response.function_call_arguments.delta'):
                    item=(obj.get('item_id') or obj.get('call_id') or obj.get('output_index'))
                    key=('openai',item)
                    tool_message_indices.add(message_index)
                    client_tool_message_indices.add(message_index)
                    a=active.setdefault(key,{'tool':True,'parts':[],'frames':[],'objs':[],'text_parts':[]})
                    d=obj.get('delta')
                    if isinstance(d,str):
                        a['parts'].append(d);a['frames'].append(frame);a['objs'].append(obj)
                        row['openai_tool_delta_events']+=1
                elif typ in ('response.custom_tool_call_input.done','response.function_call_arguments.done'):
                    item=(obj.get('item_id') or obj.get('call_id') or obj.get('output_index'))
                    a=active.pop(('openai',item),None)
                    if a is not None:finish(a,'openai',row,done=obj.get('input') if isinstance(obj.get('input'),str) else obj.get('arguments'))
                elif typ=='response.output_text.delta':
                    d=obj.get('delta')
                    if isinstance(d,str):
                        row['openai_text_delta_events']+=1
                        row['openai_text_payload_bytes']+=len(d.encode('utf8'))
                        row['openai_text_delta_encoded_bytes']+=len(frame)
                        row['text_delta_events']+=1
                        row['text_delta_encoded_bytes']+=len(frame)
                        row['text_payload_bytes']+=len(d.encode('utf8'))
                        row['_tiny_text_count']=row.get('_tiny_text_count',0)+int(len(d.encode('utf8'))<=8)
                        item=obj.get('item_id') or obj.get('output_index') or obj.get('content_index') or 0
                        key=('openai-text',item,obj.get('content_index',0))
                        a=active.setdefault(key,{'tool':False,'parts':[],'text_parts':[],
                                                 'message_index':message_index,'block_index':item})
                        a['text_parts'].append({'text':d,'frame':frame,'obj':obj,'time_ns':event_time_ns})
                elif typ=='response.output_text.done':
                    item=obj.get('item_id') or obj.get('output_index') or obj.get('content_index') or 0
                    key=('openai-text',item,obj.get('content_index',0))
                    a=active.pop(key,None)
                    if a is not None:
                        a['done']=obj.get('text')
                        a['stop_ns']=event_time_ns
                        text_finalize(a,'openai',task,pcap.name,row,delays,details)
                elif typ in ('response.completed','response.failed','response.incomplete','message_stop'):
                    # Do not mix unfinished streams with the next response.
                    row['incomplete_tool_blocks']+=sum(bool(a.get('tool')) and bool(a['parts']) for a in active.values())
                    row['incomplete_text_blocks']+=sum(bool(a.get('text_parts')) for a in active.values())
                    active={}
            row['incomplete_tool_blocks']+=sum(bool(a.get('tool')) and bool(a['parts']) for a in active.values())
            row['incomplete_text_blocks']+=sum(bool(a.get('text_parts')) for a in active.values())
    row['tcp_stream_gaps']=gaps
    row['sse_tcp_segments_with_events']=len(segments_with_events)
    row['sse_tcp_segments_with_multiple_events']=len(segments_with_multiple_events)
    row['sse_carrier_tcp_payload_bytes_captured']=sum(packet_meta[p]['payload_len'] for p in segments_with_events)
    row['sse_carrier_frame_bytes']=sum(packet_meta[p]['frame_len'] for p in segments_with_events)
    row['sse_carrier_frame_other_bytes']=row['sse_carrier_frame_bytes']-row['sse_carrier_tcp_payload_bytes_captured']
    row['sse_carrier_ip_header_bytes']=sum(packet_meta[p]['ip_h'] for p in segments_with_events)
    row['sse_carrier_tcp_header_bytes']=sum(packet_meta[p]['tcp_h'] for p in segments_with_events)
    row['sse_events_spanning_multiple_pct']=pct(row['sse_events_spanning_multiple_tcp_segments'],row['sse_events_mapped_to_tcp'])
    row['sse_carrier_segments_multi_event_pct']=pct(len(segments_with_multiple_events),len(segments_with_events))
    row['gateway_down_repeated_tcp_payload_bytes']=max(0,row['gateway_down_tcp_payload_bytes_captured']-row['gateway_down_tcp_payload_unique_bytes'])
    row['sse_pct_of_down_tcp_unique_payload']=pct(row['sse_encoded_bytes_total'],row['gateway_down_tcp_payload_unique_bytes'])
    row['sse_pct_of_down_frame_bytes']=pct(row['sse_encoded_bytes_total'],row['gateway_down_frame_bytes'])
    row['removable_pct_of_down_tcp_unique_payload_est']=pct(row['removable_encoded_bytes_est'],row['gateway_down_tcp_payload_unique_bytes'])
    row['removable_pct_of_down_frame_bytes_est']=pct(row['removable_encoded_bytes_est'],row['gateway_down_frame_bytes'])
    row['sse_events_per_tcp_segment_avg']=round(row['sse_event_tcp_segment_links']/len(segments_with_events),3) if segments_with_events else ''
    row['websocket_detected']=int(detected_ws)
    row['sse_tool_delta_events_all']=row['input_json_delta_events']
    row['encoded_overhead_bytes']=row['sse_delta_encoded_bytes']-row['tool_payload_bytes']
    row['encoded_overhead_pct']=pct(row['encoded_overhead_bytes'],row['sse_delta_encoded_bytes'])
    row['removable_encoded_pct_est']=pct(row['removable_encoded_bytes_est'],row['sse_delta_encoded_bytes'])
    row['tiny_delta_le_8_pct']=pct(row.get('_tiny_count',0),row['input_json_delta_events'])
    row['sse_tool_delta_pct_of_all_sse']=pct(row['sse_delta_encoded_bytes'],row['sse_encoded_bytes_total'])
    row['removable_pct_of_all_sse_est']=pct(row['removable_encoded_bytes_est'],row['sse_encoded_bytes_total'])
    row.pop('_tiny_count',None)
    if row['valid_tool_blocks'] or row['valid_text_blocks']:
        row['status']='partial' if gaps or row['incomplete_tool_blocks'] or row['incomplete_text_blocks'] else 'parsed'
    elif row['sse_events']:
        row['status']='no_complete_tool_delta' if not gaps else 'partial_no_complete_tool_delta'
    elif detected_ws:
        row['status']='websocket_non_sse'
    elif gaps:row['status']='tcp_gaps_no_sse'
    for block in details:
        block['same_message_with_tool']=int(block['message_index'] in tool_message_indices)
        block['same_message_with_client_tool']=int(block['message_index'] in client_tool_message_indices)
        block['same_message_with_server_tool']=int(block['message_index'] in server_tool_message_indices)
        if block['same_message_with_tool']:
            row['text_blocks_in_tool_messages']+=1
        else:
            row['text_blocks_in_text_only_messages']+=1
        row['text_blocks_in_client_tool_messages'] += block['same_message_with_client_tool']
        row['text_blocks_in_server_tool_messages'] += block['same_message_with_server_tool']
    text_metrics_final(row, delays)
    return row, details, delays, event_breakdown

def finish(a,dialect,row,done=None):
    if not a['parts'] or not a['tool']:return
    row['tool_blocks']+=1
    combined=''.join(a['parts'])
    # Done events may supply an authoritative assembled string.
    # A mismatch means measurement is incomplete and is excluded.
    if isinstance(done,str) and done!=combined:
        row['incomplete_tool_blocks']+=1;return
    if dialect=='anthropic':
        try:json.loads(combined)
        except (ValueError,TypeError):
            row['incomplete_tool_blocks']+=1;return
    row['valid_tool_blocks']+=1
    n=len(a['parts']);wire=sum(map(len,a['frames']))
    size=len(combined.encode('utf8'))
    row['input_json_delta_events']+=n
    row['_tiny_count']=row.get('_tiny_count',0)+sum(len(v.encode('utf8'))<=8 for v in a['parts'])
    row['tool_payload_bytes']+=size
    row['sse_delta_encoded_bytes']+=wire
    row['high_fragmentation_blocks_ge_10']+=int(n>=10)
    import copy
    first=copy.deepcopy(a['objs'][0])
    if dialect=='anthropic':first['delta']['partial_json']=combined
    else:first['delta']=combined
    # We calculate merged length using original first event envelope, and compact JSON serialization.
    merged=len(('event: '+first['type']+'\n'+'data: '+json.dumps(first,ensure_ascii=False,separators=(',',':'))+'\n\n').encode('utf8'))
    row['one_event_encoded_bytes_est']+=merged
    row['removable_encoded_bytes_est']+=max(0,wire-merged)

def main():
    ap = argparse.ArgumentParser(description='离线分析 Anthropic/OpenAI SSE 工具参数与文本增量编码开销，仅输出 analyze_sse.csv')
    ap.add_argument('path', help='任务集合目录、单任务目录或单个 .pcapng')
    args = ap.parse_args()
    try:
        tasks, out = discover(Path(args.path).expanduser().resolve())
    except (OSError, ValueError) as e:
        ap.error(str(e))
    rows = []
    all_delays = {w: [] for w in TEXT_WINDOWS_MS}
    all_blocks = []
    event_rows = []
    event_totals = collections.Counter()
    for name, pcap in tasks:
        try:
            row, blocks, delays, breakdown = analyze_one(name, pcap)
            # 每个任务的事件类别/具体事件/次数/编码字节明细。
            for category, event_type, field in sorted(breakdown):
                if field != 'count':
                    continue
                event_rows.append({
                    'row_type':'EVENT_CATEGORY','task':name,'pcap_file':pcap.name,
                    'status':row['status'], 'event_category':category,
                    'event_type':event_type,
                    'event_count':breakdown[(category,event_type,'count')],
                    'event_encoded_bytes':breakdown[(category,event_type,'bytes')],
                })
            event_totals.update(breakdown)
            all_blocks.extend(blocks)
            for w in TEXT_WINDOWS_MS:
                all_delays[w].extend(delays[w])
        except Exception as e:
            row = {k: 0 for k in SUM_KEYS}
            row.update(row_type='task', task=name, pcap_file=pcap.name,
                       status='error', error=str(e)[:180])
        rows.append(row)
    total = {k: sum(r.get(k, 0) for r in rows if r['status'] != 'error') for k in SUM_KEYS}
    total.update(row_type='TOTAL', task='ALL_TASKS', pcap_file='', error='',
                 status=f'{sum(r["status"] != "error" for r in rows)}/{len(rows)} counted')
    total['encoded_overhead_pct'] = pct(total['encoded_overhead_bytes'], total['sse_delta_encoded_bytes'])
    total['removable_encoded_pct_est'] = pct(total['removable_encoded_bytes_est'], total['sse_delta_encoded_bytes'])
    total['tiny_delta_le_8_pct'] = ''
    total['sse_pct_of_down_tcp_unique_payload'] = pct(total['sse_encoded_bytes_total'], total['gateway_down_tcp_payload_unique_bytes'])
    total['sse_pct_of_down_frame_bytes'] = pct(total['sse_encoded_bytes_total'], total['gateway_down_frame_bytes'])
    total['removable_pct_of_down_tcp_unique_payload_est'] = pct(total['removable_encoded_bytes_est'], total['gateway_down_tcp_payload_unique_bytes'])
    total['removable_pct_of_down_frame_bytes_est'] = pct(total['removable_encoded_bytes_est'], total['gateway_down_frame_bytes'])
    total['sse_events_per_tcp_segment_avg'] = round(total['sse_event_tcp_segment_links']/total['sse_tcp_segments_with_events'], 3) if total['sse_tcp_segments_with_events'] else ''
    total['sse_events_spanning_multiple_pct'] = pct(total['sse_events_spanning_multiple_tcp_segments'], total['sse_events_mapped_to_tcp'])
    total['sse_carrier_segments_multi_event_pct'] = pct(total['sse_tcp_segments_with_multiple_events'], total['sse_tcp_segments_with_events'])
    total['sse_tool_delta_pct_of_all_sse'] = pct(total['sse_delta_encoded_bytes'], total['sse_encoded_bytes_total'])
    total['removable_pct_of_all_sse_est'] = pct(total['removable_encoded_bytes_est'], total['sse_encoded_bytes_total'])
    text_metrics_final(total, all_delays)
    total['text_tiny_delta_le_8_pct'] = pct(sum(b['tiny_delta_le_8_events'] for b in all_blocks), total['text_delta_events'])
    rows.extend(event_rows)
    for category, event_type, field in sorted(event_totals):
        if field != 'count':
            continue
        rows.append({
            'row_type':'EVENT_CATEGORY_TOTAL','task':'ALL_TASKS','pcap_file':'',
            'status':total['status'], 'event_category':category,
            'event_type':event_type,
            'event_count':event_totals[(category,event_type,'count')],
            'event_encoded_bytes':event_totals[(category,event_type,'bytes')],
        })
    rows.append(total)
    with out.open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)
    print(f'完成：{len(tasks)} 个任务；结果：{out}（含 EVENT_CATEGORY / EVENT_CATEGORY_TOTAL 明细行）')
    print('仅输出 analyze_sse.csv；合并节省值是离线 SSE 编码估计，不代表实际 TCP 或任务时延收益。')

if __name__ == '__main__':
    main()

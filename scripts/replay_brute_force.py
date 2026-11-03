#!/usr/bin/env python3
"""Offline sliding-window replay of SYNTHETIC Windows failed-logon samples.

Reads a local training log, never connects to Windows or a SIEM, and never
blocks accounts or IPs. Findings mean a rate threshold was exceeded, not
proof of compromise or of a particular credential attack technique.
"""
from __future__ import annotations
import argparse
from collections import deque
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re

EVENT = re.compile(r"^(?P<timestamp>\d{4}-\d\d-\d\dT\S+) .*\bEventID=(?P<id>4625|4771)\b")
IP = re.compile(r"\bSourceIP=([^\s]+)")
USER = re.compile(r"\bTargetUser=([^\s]+)")
DEFAULT = Path(__file__).resolve().parents[1]/"detections"/"brute_force_windows"/"simulated_logs.log"

def extract_events(source: str):
    events=[]
    for line in source.splitlines():
        m=EVENT.match(line)
        if not m: continue
        ip=IP.search(line)
        if not ip or ip.group(1) in ("-", "127.0.0.1", "::1"):continue
        user=USER.search(line)
        when=datetime.fromisoformat(m.group("timestamp").replace("Z","+00:00"))
        events.append({"timestamp":when,"source_ip":ip.group(1),"target_user":user.group(1) if user else "(unknown)","event_id":int(m.group("id"))})
    return sorted(events,key=lambda x:(x["source_ip"],x["timestamp"]))

def replay(text: str, threshold: int=6, window_minutes: int=5):
    if threshold<1 or window_minutes<1: raise ValueError("Threshold and window must be positive")
    events=extract_events(text)
    groups={}
    for event in events: groups.setdefault(event["source_ip"],[]).append(event)
    alerts=[]
    span=timedelta(minutes=window_minutes)
    for ip,ordered in sorted(groups.items()):
        # Report the most concentrated window in each distinct time-separated session.
        session=[]; prev=None
        sessions=[]
        for event in ordered:
            if prev is not None and event["timestamp"]-prev>span:
                sessions.append(session);session=[]
            session.append(event);prev=event["timestamp"]
        if session:sessions.append(session)
        for series in sessions:
            window=deque()
            peak=[]
            for event in series:
                while window and event["timestamp"]-window[0]["timestamp"]>span:
                    window.popleft()
                window.append(event)
                if len(window)>len(peak):peak=list(window)
            if len(peak)>=threshold:
                alerts.append({
                    "source_ip": ip,
                    "first_seen": peak[0]["timestamp"].isoformat(),
                    "last_seen": peak[-1]["timestamp"].isoformat(),
                    "failures_in_peak_window": len(peak),
                    "distinct_target_users": len({x["target_user"] for x in peak}),
                    "event_ids": sorted({x["event_id"] for x in peak}),
                    "window_minutes":window_minutes,
                    "assessment":"Rate-threshold lead, synthetic only; investigate context before classifying"
                })
    return alerts

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file",type=Path,default=DEFAULT)
    parser.add_argument("--threshold",type=int,default=6)
    parser.add_argument("--window-minutes",type=int,default=5)
    args=parser.parse_args()
    findings=replay(args.file.read_text(encoding="utf-8"),args.threshold,args.window_minutes)
    print(json.dumps({"dataset":"SYNTHETIC / portfolio exercise", "findings":findings},indent=2))
if __name__=="__main__":main()

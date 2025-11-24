#!/usr/bin/env python3
import time
import re
import pandas as pd
import ipaddress
from datetime import datetime
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
import yagmail
import os
import warnings
import json
import math
from collections import Counter

# --- Ignore warnings ---
warnings.filterwarnings("ignore", message=".*arrow.*", category=FutureWarning)
warnings.filterwarnings("ignore", message=".*DeprecationWarning:.*pandas.*", category=DeprecationWarning)

# --- Configuration (env override) ---
INFLUX_URL = os.getenv("INFLUX_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "iot-admin-token-123")
INFLUX_ORG = os.getenv("INFLUX_ORG", "iot-org")
SRC_BUCKET = os.getenv("SRC_BUCKET", "iot-data")
ALERT_BUCKET = os.getenv("ALERT_BUCKET", "iot-data") 

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
EMAIL_TO = os.getenv("EMAIL_TO", "").split(",")

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "5"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "300"))
PAYLOAD_LIMIT = int(os.getenv("PAYLOAD_LIMIT", "1024"))
RETAIN_QOS_LIMIT = int(os.getenv("RETAIN_QOS_LIMIT", "5"))
RECONNECT_LIMIT = int(os.getenv("RECONNECT_LIMIT", "10"))
PUBLISH_FLOOD_LIMIT = int(os.getenv("PUBLISH_FLOOD_LIMIT", "10000"))

# --- Ngưỡng đã giảm theo yêu cầu ---
ENUM_LIMIT = int(os.getenv("ENUM_LIMIT", "10")) # Giảm từ 20 xuống 10
BRUTE_FORCE_LIMIT = int(os.getenv("BRUTE_FORCE_LIMIT", "5")) # Thêm mới, ngưỡng 5

ALERT_COOLDOWN = int(os.getenv("ALERT_COOLDOWN", "60")) # 1 phút

# --- Cấu hình Rule ---
ALLOWED_TOPICS_REGEX = [
    r"^/devices/+/events$",
    r"^/devices/+/config$",
    r"^/admin/status$",
    r"^factory/production/.*",
    r"^factory/office/.*",
    r"^factory/energy/.*",
    r"^factory/security/.*",
    r"^factory/storage/.*",
]
SUSPICIOUS_CLIENT_ID_PREFIXES = [
    "mqtt-explorer", "mqtt-spy", "mosquitto_sub", "mosquitto_pub", "MQTTBox"
]
SUSPICIOUS_PAYLOAD_KEYWORDS = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION",
    "../", "%2F", "%5C", "passwd", "shadow", "credentials"
]

# --- CẤU HÌNH WHITELIST ---
WHITELISTED_CLIENT_PREFIXES = [
    "giamdoc_gay", "truongphong_security", "truongphong_office", "truongphong_production",
    "sensor_", "meter_", "printer_", "pc_", "plc_", "robot_", "cam_", "access_", "forklift_",  
]

# --- Global state ---
yag = None
if EMAIL_USER and EMAIL_PASS and EMAIL_TO:
    try:
        yag = yagmail.SMTP(EMAIL_USER, EMAIL_PASS)
        print("[INFO] Email client initialized.")
    except Exception as e:
        print(f"[WARN] Could not initialize email client: {e}")

# (rule_name, key) -> timestamp
alert_cooldown_cache = {}

def should_alert(key):
    """Check if an alert for this key is in cooldown."""
    now = time.time()
    if key in alert_cooldown_cache:
        last_alerted = alert_cooldown_cache[key]
        if (now - last_alerted) < ALERT_COOLDOWN:
            print(f"[COOLDOWN] Skipping alert for {key}")
            return False
    alert_cooldown_cache[key] = now
    return True

def send_email(subject, body):
    if yag and EMAIL_TO:
        print(f"[ALERT] Sending email: {subject}")
        try:
            yag.send(to=EMAIL_TO, subject=subject, contents=body)
        except Exception as e:
            print(f"[ERROR] Failed to send email: {e}")
    else:
        print("[ALERT] Email client not configured, skipping send.")

# --- Đã xóa src_ip khỏi hàm write_alert ---
def write_alert(write_api, rule_name, client_id, message):
    """Write an alert to the InfluxDB alert bucket."""
    point = Point("mqtt_alert") \
        .tag("rule", rule_name) \
        .tag("client_id", str(client_id)) \
        .field("message", str(message)) \
        .time(datetime.utcnow(), WritePrecision.NS)
    
    write_api.write(bucket=ALERT_BUCKET, org=INFLUX_ORG, record=point)
    print(f"[ALERT] Rule: {rule_name} | Client: {client_id} | Msg: {message}")


# --- Rule Functions (Không bị ảnh hưởng) ---

# def detect_duplicate_client_id(df, write_api):
#     connect_df = df[df["mqtt_type"] == "connect"].copy()
#     if connect_df.empty:
#         return
        
#     client_ports = connect_df.groupby("client_id")["src_port"].nunique()
#     duplicates = client_ports[client_ports > 1] 
    
#     for client_id, port_count in duplicates.items():
#         if not client_id or client_id == "unknown":
#             continue
        
#         key = ("duplicate_client_id", client_id)
#         if should_alert(key):
#             msg = f"Duplicate client_id: '{client_id}' seen using {port_count} different source ports."
#             write_alert(write_api, "duplicate_client_id", client_id, msg)
#             send_email("MQTT Security Alert: Duplicate Client ID", msg)

def detect_reconnect_storm(df, write_api):
    connect_events = df[df["mqtt_type"].isin(["connect", "disconnect"])]
    if connect_events.empty:
        return

    storm_counts = connect_events.groupby("client_id").size().reset_index(name="count")
    for _, row in storm_counts.iterrows():
        if row["count"] > RECONNECT_LIMIT and row["client_id"] != "unknown":
            
            key = ("reconnect_storm", row["client_id"]) 
            if should_alert(key):
                msg = f"Reconnect storm: {row['count']} connect/disconnect events from client '{row['client_id']}'"
                write_alert(write_api, "reconnect_storm", row["client_id"], msg)
                send_email("MQTT Security Alert: Reconnect Storm", msg)

def detect_retain_qos_abuse(df, write_api):
    publish_df = df[df["mqtt_type"] == "publish"].copy()
    if publish_df.empty:
        return

    publish_df["qos_num"] = pd.to_numeric(publish_df["qos"], errors="coerce")
    publish_df["retain_bool"] = pd.to_numeric(publish_df["retain"], errors="coerce").fillna(0).astype(bool)

    abuse_df = publish_df[(publish_df["retain_bool"] == True) | (publish_df["qos_num"] > 0)]
    
    abuse_counts = abuse_df.groupby("client_id").size().reset_index(name="count")
    for _, row in abuse_counts.iterrows():
        if row["count"] > RETAIN_QOS_LIMIT and row["client_id"] != "unknown":
            
            key = ("retain_qos_abuse", row["client_id"])
            if should_alert(key):
                msg = f"Retain/QoS abuse: {row['count']} messages with Retain=True and QoS>0 from client '{row['client_id']}'"
                write_alert(write_api, "retain_qos_abuse", row["client_id"], msg)
                send_email("MQTT Security Alert: Retain/QoS Abuse", msg)


def shannon_entropy(s):
    """Tính entropy của chuỗi payload để đánh giá tính ngẫu nhiên."""
    if not s:
        return 0
    prob = [n / len(s) for n in Counter(s).values()]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def detect_payload_flow_anomaly(df, write_api):
    """
    Rule – Payload Flow Anomaly
    Phát hiện hành vi bất thường trong luồng PUBLISH:
      - Payload kích thước bất thường
      - Payload entropy bất thường (binary / dữ liệu lặp)
      - Flood (số lượng hoặc tổng dung lượng quá lớn)
    """
    # Lọc các flow publish
    publish_df = df[df["mqtt_type"] == "publish"].copy()
    if publish_df.empty:
        return

    # Chuẩn hóa payload
    def normalize_payload(val):
        if val is None or str(val).lower() == "nan":
            return ""
        if isinstance(val, bytes):
            try:
                return val.decode("utf-8", errors="ignore")
            except Exception:
                return val.hex()
        return str(val)

    publish_df["payload_text"] = publish_df["payload_raw"].apply(normalize_payload)
    publish_df["payload_len"] = publish_df["payload_text"].apply(len)
    publish_df["entropy"] = publish_df["payload_text"].apply(lambda x: shannon_entropy(x[:1000]))

    # === 1️⃣ PHÂN TÍCH CÁC PAYLOAD CÁ BIỆT TRONG FLOW ===
    for _, row in publish_df.iterrows():
        cid = row.get("client_id", "unknown")
        if cid == "unknown":
            continue
        topic = row.get("topic", "")
        plen = row.get("payload_len", 0)
        ent = row.get("entropy", 0)

        # --- Oversized payload ---
        if plen > PAYLOAD_LIMIT * 5:
            key = ("publish_payload_large", cid)
            if should_alert(key):
                msg = f"[Flow] Oversized payload ({plen} bytes) from {cid} on '{topic}'"
                write_alert(write_api, "publish_payload_large", cid, msg)
                send_email("MQTT Flow Alert: Oversized Payload", msg)

        # --- Entropy anomaly (too random or too repetitive) ---
        if ent < 2.5 or ent > 7.5:
            key = ("publish_payload_entropy", cid)
            if should_alert(key):
                msg = f"[Flow] Entropy anomaly ({ent:.2f}) from {cid} on '{topic}'"
                write_alert(write_api, "publish_payload_entropy", cid, msg)
                send_email("MQTT Flow Alert: Payload Entropy Anomaly", msg)

    # === 2️⃣ PHÂN TÍCH THEO DÒNG FLOW (CLIENT) ===
    flow_stats = (
        publish_df.groupby("client_id")
        .agg(
            msg_count=("mqtt_type", "count"),
            total_bytes=("payload_len", "sum"),
            avg_entropy=("entropy", "mean"),
            max_payload=("payload_len", "max")
        )
        .reset_index()
    )

    BYTE_LIMIT = PAYLOAD_LIMIT * 200  # Giới hạn tổng dung lượng (ví dụ 200 KB)

    for _, row in flow_stats.iterrows():
        cid = row["client_id"]
        if cid == "unknown":
            continue
        msg_count = int(row["msg_count"])
        total_bytes = int(row["total_bytes"])
        avg_ent = float(row["avg_entropy"])
        max_plen = int(row["max_payload"])

        # --- Flood detection ---
        if msg_count > PUBLISH_FLOOD_LIMIT or total_bytes > BYTE_LIMIT:
            key = ("publish_flow_flood", cid)
            if should_alert(key):
                msg = (
                    f"[Flow] Payload flood: {cid} sent {msg_count} msgs "
                    f"({total_bytes} bytes, max={max_plen}, avg_entropy={avg_ent:.2f}) "
                    f"in {WINDOW_SECONDS}s"
                )
                write_alert(write_api, "publish_flow_flood", cid, msg)
                send_email("MQTT Flow Alert: Payload Flood", msg)

def detect_publish_flood(df, write_api):
    """
    Rule 4 – Publish Flood (Cải tiến)
    Phát hiện client gửi quá nhiều bản tin publish hoặc tổng dung lượng payload lớn bất thường.
    """
    publish_df = df[df["mqtt_type"] == "publish"].copy()
    if publish_df.empty:
        return

    # Bổ sung: tính độ dài payload nếu chưa có
    if "payload_len" not in publish_df.columns:
        publish_df["payload_len"] = publish_df["payload_raw"].astype(str).apply(len)
    else:
        publish_df["payload_len"] = pd.to_numeric(publish_df["payload_len"], errors="coerce").fillna(0)

    # Gộp theo client_id
    agg_df = publish_df.groupby("client_id").agg(
        message_count=("mqtt_type", "count"),
        total_bytes=("payload_len", "sum")
    ).reset_index()

    for _, row in agg_df.iterrows():
        cid = row["client_id"]
        if cid == "unknown":
            continue
        
        msg_count = int(row["message_count"])
        total_bytes = int(row["total_bytes"])

        # Ngưỡng cảnh báo (có thể tinh chỉnh)
        msg_limit = PUBLISH_FLOOD_LIMIT
        byte_limit = PUBLISH_FLOOD_LIMIT * 5000  # ví dụ: 100 messages ≈ 500 KB

        if msg_count > msg_limit or total_bytes > byte_limit:
            key = ("publish_flood", cid)
            if should_alert(key):
                msg = (
                    f"Publish flood detected: client '{cid}' sent {msg_count} publish messages "
                    f"totaling {total_bytes} bytes in the last window."
                )
                write_alert(write_api, "publish_flood", cid, msg)
                send_email("MQTT Security Alert: Publish Flood", msg)
                print(f"[ALERT] Rule: publish_flood | Client: {cid} | Msgs: {msg_count} | Bytes: {total_bytes}")


def detect_suspicious_client_id(df, write_api):
    if not SUSPICIOUS_CLIENT_ID_PREFIXES:
        return
    if "client_id" not in df.columns:
        return

    unique_client_ids = df["client_id"].dropna().unique()
    for client_id in unique_client_ids:
        client_id_lower = str(client_id).lower()
        for prefix in SUSPICIOUS_CLIENT_ID_PREFIXES:
            if client_id_lower.startswith(prefix.lower()):
                key = ("suspicious_client_id", client_id)
                if should_alert(key):
                    msg = f"Suspicious client_id detected: '{client_id}' matches prefix '{prefix}'"
                    write_alert(write_api, "suspicious_client_id", client_id, msg)
                    send_email("Suspicious MQTT Client ID", msg)
                break 

# ===================================================================
# === BẮT ĐẦU THAY THẾ ===
# ===================================================================

def detect_brute_force(df, write_api):
    """
    DEBUGGING VERSION - replace the original detect_brute_force with this.
    - Prints debug info to stdout so you can tail the daemon logs.
    - Triggers an alert immediately if any client_id starts with 'bruteforce_' (test-mode trigger).
    - Otherwise, detects brute force by counting 'connect' events per username in WINDOW_SECONDS
      and/or counting distinct client_ids per username.
    """
    try:
        print("[DBG] detect_brute_force: called")
        if df is None:
            print("[DBG] detect_brute_force: df is None")
            return
        if df.empty:
            print("[DBG] detect_brute_force: df is empty")
            return

        # find time column
        time_col = None
        for c in ["_time", "time", "timestamp", "ts", "datetime"]:
            if c in df.columns:
                time_col = c
                break
        if time_col is None:
            print("[DBG] detect_brute_force: no time column found; cols:", list(df.columns)[:20])
            # still try without time, but we will not perform windowed detection
        else:
            print(f"[DBG] detect_brute_force: using time column '{time_col}'")

        # Ensure required columns exist
        for col in ["mqtt_type", "username", "client_id", "client_identifier"]:
            if col not in df.columns:
                df[col] = None

        # Normalize mqtt_type text
        df["mqtt_type_norm"] = df["mqtt_type"].astype(str).str.lower()

        # QUICK CHECK: are there any client_ids starting with 'bruteforce_'? If yes, force alert
        def client_key_from_row(r):
            cid = r.get("client_id")
            cidf = r.get("client_identifier")
            if pd.notna(cid) and str(cid).strip() and str(cid).strip().lower() != "nan":
                return str(cid).strip()
            if pd.notna(cidf) and str(cidf).strip() and str(cidf).strip().lower() != "nan":
                return str(cidf).strip()
            return None

        # create client_key column
        df["client_key"] = df.apply(client_key_from_row, axis=1)

        # immediate bruteforce_ client_id detection (helpful test)
        if "client_key" in df.columns:
            bruteforce_rows = df[df["client_key"].astype(str).str.startswith("bruteforce_", na=False)]
            if not bruteforce_rows.empty:
                sample = bruteforce_rows.head(10).to_dict(orient="records")
                msg = (f"[DBG/ALERT] Found {len(bruteforce_rows)} rows with client_id starting with 'bruteforce_'. "
                       f"Sample rows: {sample}")
                print(msg)
                # attempt to alert (use username if available, otherwise 'bruteforce_test')
                try:
                    # pick username from first bruteforce row if present
                    uname = bruteforce_rows.iloc[0].get("username") or "bruteforce_test"
                except Exception:
                    uname = "bruteforce_test"
                key = ("brute_force", uname)
                if should_alert(key):
                    try:
                        write_alert(write_api, "brute_force", uname, msg)
                        print("[DBG] write_alert called for bruteforce_ match")
                    except Exception as e:
                        print(f"[DBG] write_alert exception: {e}")
                    try:
                        send_email("MQTT Security Alert: Brute Force (test-match)", msg)
                        print("[DBG] send_email called for bruteforce_ match")
                    except Exception as e:
                        print(f"[DBG] send_email exception: {e}")
                else:
                    print("[DBG] should_alert returned False for bruteforce_ match")
                # continue to also run normal detection below (do not return)

        # Filter connect events
        connects = df[df["mqtt_type_norm"] == "connect"].copy()
        if connects.empty:
            print("[DBG] No connect events found in this batch.")
            return

        # parse time if available
        if time_col:
            connects["_parsed_time"] = pd.to_datetime(connects[time_col], errors="coerce")
            # drop rows without parsed time (we print sample instead)
            if connects["_parsed_time"].isna().all():
                print("[DBG] All connect times could not be parsed. Sample connect rows:", connects.head(10).to_dict(orient="records"))
                # fallback: try detection without time (count total attempts in df)
                # We'll perform a simple count per username in the whole df if timestamps not usable.
                time_available = False
            else:
                time_available = True
        else:
            time_available = False

        # Normalization
        connects["username_norm"] = connects["username"].astype(str).str.strip()
        connects["client_key"] = connects.apply(client_key_from_row, axis=1)

        # read global limit/window if exist
        try:
            limit = int(BRUTE_FORCE_LIMIT)
            print(f"[DBG] Using BRUTE_FORCE_LIMIT from globals: {limit}")
        except Exception:
            limit = 5
            print(f"[DBG] Using default BRUTE_FORCE_LIMIT: {limit}")
        WINDOW_SECONDS = globals().get("BRUTE_FORCE_WINDOW_SECONDS", 60)
        print(f"[DBG] Detection window seconds: {WINDOW_SECONDS}")

        # If no usable timestamps, do a simple heuristic: count attempts per username in this batch
        if not time_available:
            counts = connects.groupby("username_norm").size().reset_index(name="count")
            for _, r in counts.iterrows():
                uname = r["username_norm"]
                cnt = int(r["count"])
                if uname and cnt > limit:
                    msg = f"[DBG/ALERT] (no-time) {cnt} connect attempts for username '{uname}' in batch."
                    print(msg)
                    key = ("brute_force", uname)
                    if should_alert(key):
                        try:
                            write_alert(write_api, "brute_force", uname, msg)
                            print("[DBG] write_alert called (no-time)")
                        except Exception as e:
                            print(f"[DBG] write_alert exception (no-time): {e}")
                        try:
                            send_email("MQTT Security Alert: Brute Force", msg)
                        except Exception as e:
                            print(f"[DBG] send_email exception (no-time): {e}")
                    else:
                        print("[DBG] should_alert returned False (no-time) for", uname)
            return

        # Otherwise run sliding-window per username
        grouped = connects[connects["username_norm"].notna() & (connects["username_norm"] != "")].groupby("username_norm")
        any_alert = False
        for username, g in grouped:
            g_sorted = g.sort_values("_parsed_time")
            times = list(g_sorted["_parsed_time"].astype("datetime64[ns]"))
            client_keys = list(g_sorted["client_key"].astype(object))
            n = len(times)
            if n == 0:
                continue
            i = 0
            while i < n:
                j = i
                while j < n and (times[j] - times[i]).total_seconds() <= WINDOW_SECONDS:
                    j += 1
                window_count = j - i
                ck_slice = [client_keys[k] for k in range(i, j)]
                distinct_clients = len(set([c for c in ck_slice if c and str(c).strip() != "None"]))
                if window_count > limit or distinct_clients > limit:
                    any_alert = True
                    # prepare sample rows for debug
                    sample_rows = g_sorted.iloc[i:j].head(20).to_dict(orient="records")
                    msg = (f"[DBG/ALERT] username='{username}' had {window_count} connect attempts "
                           f"({distinct_clients} distinct client_ids) within {WINDOW_SECONDS}s. Sample: {sample_rows}")
                    print(msg)
                    key = ("brute_force", username)
                    if should_alert(key):
                        try:
                            write_alert(write_api, "brute_force", username, msg)
                            print("[DBG] write_alert called for", username)
                        except Exception as e:
                            print(f"[DBG] write_alert exception for {username}: {e}")
                        try:
                            send_email("MQTT Security Alert: Brute Force", msg)
                            print("[DBG] send_email called for", username)
                        except Exception as e:
                            print(f"[DBG] send_email exception for {username}: {e}")
                    else:
                        print("[DBG] should_alert returned False for", username, "window_count:", window_count, "distinct:", distinct_clients)
                    # advance i past this window
                    i = j
                    continue
                i += 1

        if not any_alert:
            print("[DBG] detect_brute_force: no alert windows found in this batch.")
    except Exception as e:
        print(f"[ERROR] detect_brute_force exception: {e}")
        return


# ===================================================================
# === KẾT THÚC THAY THẾ ===
# ===================================================================


# ===================================================================
# === CÁC RULE ĐÃ ĐƯỢC VIẾT LẠI (ĐƠN GIẢN HÓA) ===
# ===================================================================

def detect_wildcard_abuse(df, write_api):
    """
    (ĐÃ VIẾT LẠI)
    Phát hiện lạm dụng wildcard.
    Rule này giờ đây đọc trực tiếp trường 'topic' từ các sự kiện 'subscribe'.
    """
    # Lấy các sự kiện subscribe CÓ chứa trường 'topic' (đã được chuẩn hóa)
    subscribe_df = df[
        (df["mqtt_type"] == "subscribe") &
        (df["topic"].notna())
    ].copy()

    if subscribe_df.empty:
        return

    # Tìm các topic chứa '#' hoặc '+' trực tiếp trong cột 'topic'
    wildcard_abuse_df = subscribe_df[subscribe_df["topic"].str.contains(r"#|.*\+.*", na=False)]
    
    # Lặp qua các vi phạm
    for _, row in wildcard_abuse_df.iterrows():
        topic = row["topic"]
        client_id = row["client_id"]
        
        key = ("wildcard_abuse", client_id, topic)
        if should_alert(key):
            msg = f"Wildcard abuse: Client {client_id} subscribed to '{topic}'"
            write_alert(write_api, "wildcard_abuse", client_id, msg)
            send_email("MQTT Security Alert: Wildcard Abuse", msg)

def detect_unauthorized_topics(df, write_api):
    """
    (ĐÃ VIẾT LẠI)
    Phát hiện truy cập topic không được phép (publish và subscribe).
    Rule này giờ đây đọc trực tiếp trường 'topic' cho CẢ HAI sự kiện.
    """
    if not ALLOWED_TOPICS_REGEX:
        return
    
    # Biên dịch 1 lần
    allowed_topics_pattern = re.compile("|".join(f"({r})" for r in ALLOWED_TOPICS_REGEX))

    # Lấy TẤT CẢ sự kiện (publish HOẶC subscribe) CÓ chứa trường 'topic'
    df_with_topic = df[
        df["mqtt_type"].isin(["publish", "subscribe"]) &
        df["topic"].notna()
    ].copy()

    if df_with_topic.empty:
        return

    # Thêm một cột 'is_allowed' để kiểm tra regex
    # (Vector hóa nhanh hơn là lặp)
    df_with_topic["is_allowed"] = df_with_topic["topic"].apply(
        lambda t: bool(allowed_topics_pattern.fullmatch(t))
    )
    
    # Lọc ra những sự kiện không được phép
    unauth_df = df_with_topic[df_with_topic["is_allowed"] == False]

    # Lặp qua các vi phạm
    for _, row in unauth_df.iterrows():
        if row["client_id"] == "unknown": continue
        
        topic = row["topic"]
        client_id = row["client_id"]
        mqtt_type = row["mqtt_type"]
        
        key = ("unauth_topic", client_id, topic)
        if should_alert(key):
            msg = f"Unauthorized {mqtt_type}: Client {client_id} tried to access unauthorized topic '{topic}'"
            write_alert(write_api, "unauth_topic", client_id, msg)
            send_email("MQTT Security Alert: Unauthorized Topic", msg)

def detect_topic_enumeration(df, write_api):
    """
    (ĐÃ VIẾT LẠI)
    Phát hiện dò quét topic (publish và subscribe).
    Rule này giờ đây đọc trực tiếp trường 'topic' cho CẢ HAI sự kiện.
    """
    # Lấy TẤT CẢ sự kiện (publish HOẶC subscribe) CÓ chứa trường 'topic'
    all_topics_df = df[
        df["mqtt_type"].isin(["publish", "subscribe"]) &
        df["topic"].notna()
    ].copy()

    if all_topics_df.empty:
        return
    
    # Nhóm theo client_id và đếm số topic DUY NHẤT
    unique_topic_counts = all_topics_df.groupby("client_id")["topic"].nunique()
    
    for client_id, count in unique_topic_counts.items():
        # Kiểm tra với ENUM_LIMIT (đã giảm xuống 10)
        if count > ENUM_LIMIT and client_id != "unknown": 
            key = ("topic_enumeration", client_id)
            if should_alert(key):
                msg = f"Topic enumeration: Client '{client_id}' accessed {count} unique topics"
                write_alert(write_api, "topic_enumeration", client_id, msg)
                send_email("MQTT Security Alert: Topic Enumeration", msg)

# ===================================================================
# === KẾT THÚC PHẦN VIẾT LẠI ===
# ===================================================================


def normalize_columns_safely(df):
    """Ensure all expected columns exist, fill with None if not."""
    
    all_cols = [
        "src_ip", "src_port", "client_id", "mqtt_type", "topic", "payload_raw", "retain", "qos",
        "client_identifier", "bytes_toserver", "pkts_toserver", "state",
        "protocol_version", "flags_clean_session", "flags_username", "flags_password",
        "flags_will", "flags_will_retain", "topics", "dup", "message_id",
        "password", "protocol_string", "return_code", "session_present",
        "username", "qos_granted", "reason_codes"
    ]

    for col in all_cols:
        if col not in df.columns:
            df[col] = None
    
    if "client_id" in df.columns:
        df["client_id"] = df["client_id"].fillna("unknown")
    
    return df

def main():
    print("MQTT Rule Detect Daemon Starting...")
    client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    query_api = client.query_api()
    write_api = client.write_api(write_options=SYNCHRONOUS)

    try:
        health = client.health()
        print(f"[INFO] InfluxDB health: {health.status}")
    except Exception as e:
        print(f"[FATAL] Cannot connect to InfluxDB: {e}")
        return

    while True:
        try:
            # 1. Query data from InfluxDB
            print(f"[INFO] Querying data for the last {WINDOW_SECONDS} seconds...")
            
            # Query này vẫn đúng vì nó lấy _measurement == "mqtt_event"
            # và file log mới của bạn vẫn ghi vào "mqtt_event"
            query = f"""
            from(bucket: "{SRC_BUCKET}")
              |> range(start: -{WINDOW_SECONDS}s)
              |> filter(fn: (r) => r._measurement == "mqtt_event")
              |> filter(fn: (r) => 
                  r.mqtt_type == "connect" or 
                  r.mqtt_type == "publish" or 
                  r.mqtt_type == "subscribe" or 
                  r.mqtt_type == "disconnect" or
                  r.mqtt_type == "connack" 
              )
              |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
              |> keep(columns: [
                  "_time", "src_ip", "src_port", "client_id", "mqtt_type", "topic", "payload_raw", 
                  "retain", "qos", "client_identifier", "bytes_toserver", "pkts_toserver", 
                  "state", "protocol_version", "flags_clean_session", "flags_username", 
                  "flags_password", "flags_will", "flags_will_retain", "topics", 
                  "dup", "message_id", "password", "protocol_string", "return_code", 
                  "session_present", "username", "qos_granted", "reason_codes"
              ])
              |> sort(columns: ["_time"], desc: false)
            """
            
            # (Ghi chú nhỏ: Tôi đã thêm 'connack' vào query để đảm bảo nó luôn được lấy)
            # (Trong file gốc của bạn, 'connack' bị thiếu, nhưng có thể nó vẫn chạy 
            # do một query khác, tuy nhiên thêm vào đây sẽ chắc chắn hơn)
            if 'r.mqtt_type == "connack"' not in query:
                 query = query.replace(
                     'r.mqtt_type == "disconnect"',
                     'r.mqtt_type == "disconnect" or r.mqtt_type == "connack"'
                 )


            result = query_api.query_data_frame(query=query)
            
            if isinstance(result, list):
                if not result:
                    print("[INFO] No data returned. Skipping.")
                    time.sleep(CHECK_INTERVAL)
                    continue
                df = pd.concat(result, ignore_index=True)
            else:
                df = result

            if df.empty:
                print("[INFO] No data in window. Skipping.")
                time.sleep(CHECK_INTERVAL)
                continue
            
            print(f"[INFO] Fetched {len(df)} events.")
            
            # 2. Normalize data
            df = normalize_columns_safely(df)
            
            # 2.5. Áp dụng Whitelist
            df_filtered = df 
            try:
                if WHITELISTED_CLIENT_PREFIXES:
                    mask = df['client_id'].apply(
                        lambda x: any(str(x).startswith(prefix) for prefix in WHITELISTED_CLIENT_PREFIXES)
                    )
                    df_filtered = df[~mask] 
                
                print(f"[INFO] Original events: {len(df)}, Filtered events (after whitelist): {len(df_filtered)}")

                if df_filtered.empty:
                    print("[INFO] All events in window were whitelisted. Skipping rules.")
                    time.sleep(CHECK_INTERVAL)
                    continue
            
            except Exception as e:
                print(f"[ERROR] Failed to apply whitelist: {e}")
                df_filtered = df 
            
            # 3. Run detection rules
            
            try:
                detect_duplicate_client_id(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] duplicate_client_id: {e}")

            try:
                detect_reconnect_storm(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] reconnect_storm: {e}")

            try:
                detect_wildcard_abuse(df_filtered, write_api) # (Đã được viết lại)
            except Exception as e:
                print(f"[RULE ERROR] wildcard_abuse: {e}")

            try:
                detect_retain_qos_abuse(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] retain_qos_abuse: {e}")

            try:
                detect_payload_flow_anomaly(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] payload_anomaly: {e}")

            try:
                detect_unauthorized_topics(df_filtered, write_api) # (Đã được viết lại)
            except Exception as e:
                print(f"[RULE ERROR] unauthorized_topics: {e}")

            try:
                detect_publish_flood(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] publish_flood: {e}")
                
            try:
                detect_topic_enumeration(df_filtered, write_api) # (Đã được viết lại)
            except Exception as e:
                print(f"[RULE ERROR] topic_enumeration: {e}")
            
            try:
                detect_suspicious_client_id(df_filtered, write_api)
            except Exception as e:
                print(f"[RULE ERROR] suspicious_client_id: {e}")

            try:
                detect_brute_force(df_filtered, write_api) # (ĐÃ SỬA)
            except Exception as e:
                print(f"[RULE ERROR] brute_force: {e}")

        except Exception as e:
            print(f"[ERROR] Query/Detect: {e}")
            time.sleep(CHECK_INTERVAL)
            continue

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()

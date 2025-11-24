# MQtrace
File back-end chính


mqtt_eve_forwarder6.py (Đọc file eve.json trên máy host, lọc event_type liên quan đến MQTT, thu thập trường từ file eve.json, đẩy lên influxDB)

mqtt_rule_detect_daemon.py (rule based)

Dịch vụ suricata chạy trên máy host

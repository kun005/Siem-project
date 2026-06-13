import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from datetime import datetime
from elasticsearch import Elasticsearch, helpers
from config.settings import ES_HOST, ES_INDEX_PREFIX

#Kết nối Elasticsearch 
def connect_elasticsearch() -> Elasticsearch | None:
    try:
        es = Elasticsearch(
            ES_HOST,
            verify_certs=False,       
            ssl_show_warn=False,      
            retry_on_timeout=True,
            max_retries=3
        )
        if es.ping():
            print(f"[+] Kết nối Elasticsearch thành công: {ES_HOST}")
            return es
        else:
            print(f"[ERROR] Elasticsearch không phản hồi tại {ES_HOST}")
            return None
    except Exception as e:
        print(f"[ERROR] Lỗi kết nối: {e}")
        return None

#Tạo tên index theo ngày 
def get_index_name(timestamp: str = None) -> str:
    if timestamp:
        try:
            dt = datetime.strptime(timestamp[:10], "%Y-%m-%d")
            return f"{ES_INDEX_PREFIX}-{dt.strftime('%Y.%m.%d')}"
        except Exception:
            pass
    return f"{ES_INDEX_PREFIX}-{datetime.now().strftime('%Y.%m.%d')}"

# Hàm 3: Lưu một document 
def index_document(es: Elasticsearch, document: dict) -> bool:
    if not es or not document:
        return False

    try:
        index_name = get_index_name(document.get("@timestamp"))

        es.index(
            index=index_name,
            document=document,
            refresh=False
        )
        return True

    except Exception as e:
        print(f"[ERROR] Lưu document thất bại: {e}")
        return False

# Lưu nhiều document cùng lúc
def bulk_index_documents(es: Elasticsearch,
                         documents: list[dict]) -> tuple[int, int]:
    if not es or not documents:
        return 0, 0

    # Chuẩn bị hđ cho bulk API
    actions = [
        {
            "_index":  get_index_name(doc.get("@timestamp")),
            "_source": doc
        }
        for doc in documents
    ]

    try:
        success, errors = helpers.bulk(
            es,
            actions,
            chunk_size=500,
            raise_on_error=False
        )
        if errors:
            print(f"[WARN] Bulk index: {success} thành công, "
                  f"{len(errors)} thất bại")
        return success, len(errors) if errors else 0

    except Exception as e:
        print(f"[ERROR] Bulk index thất bại: {e}")
        return 0, len(documents)

# Truy vấn alert trong khoảng thời gian 
def query_recent_events(es: Elasticsearch,
                        src_ip: str = None,
                        minutes: int = 60,
                        event_type: str = None) -> list[dict]:
    if not es:
        return []

    # Xây dựng query động
    must_conditions = [
        {
            "range": {
                "@timestamp": {
                    "gte": f"now-{minutes}m",
                    "lte": "now"
                }
            }
        }
    ]

    # Thêm filter IP nếu có
    if src_ip:
        must_conditions.append({
            "term": { "source.ip": src_ip }
        })

    # Thêm filter loại event nếu có
    if event_type:
        must_conditions.append({
            "term": { "event.type": event_type }
        })

    query = {
        "query": {
            "bool": { "must": must_conditions }
        },
        "sort": [
            { "@timestamp": { "order": "desc" } }
        ],
        "size": 1000
    }

    try:
        response = es.search(
            index=f"{ES_INDEX_PREFIX}-*",
            body=query
        )
        # Trích xuất _source từ mỗi hit
        return [hit["_source"] for hit in response["hits"]["hits"]]

    except Exception as e:
        print(f"[ERROR] Query thất bại: {e}")
        return []

#Đếm số lần thất bại theo IP 
def count_failed_events(es: Elasticsearch,
                        src_ip: str,
                        seconds: int = 60) -> int:
    if not es:
        return 0

    query = {
        "query": {
            "bool": {
                "must": [
                    { "term":  { "source.ip":     src_ip } },
                    { "term":  { "event.outcome": "failure" } },
                    { "range": { "@timestamp": { "gte": f"now-{seconds}s" } } }
                ]
            }
        }
    }

    try:
        response = es.count(
            index=f"{ES_INDEX_PREFIX}-*",
            body=query
        )
        return response["count"]

    except Exception as e:
        print(f"[ERROR] Count thất bại: {e}")
        return 0

if __name__ == "__main__":
    from module2_parser.auth_parser     import parse_auth_log
    from module2_parser.suricata_parser import parse_eve_json
    from module2_parser.normalizer      import normalize
    from config.settings import AUTH_LOG_PATH, EVE_JSON_PATH

    # 1. Kết nối ES
    es = connect_elasticsearch()
    if not es:
        sys.exit(1)

    # 2. Parse + normalize auth log
    print("\n[*] Đang xử lý auth.log...")
    auth_raw    = parse_auth_log(AUTH_LOG_PATH)
    auth_docs   = [normalize(r) for r in auth_raw if normalize(r)]

    # 3. Parse + normalize suricata log
    print("[*] Đang xử lý eve.json...")
    suri_raw    = parse_eve_json(EVE_JSON_PATH)
    suri_docs   = [normalize(r) for r in suri_raw if normalize(r)]

    all_docs    = auth_docs + suri_docs
    print(f"[*] Tổng document cần lưu: {len(all_docs)}")

    # 4. Bulk index
    success, failed = bulk_index_documents(es, all_docs)
    print(f"[+] Lưu thành công: {success} | Thất bại: {failed}")

    # 5. Truy vấn kiểm tra
    print("\n[*] Truy vấn lại từ Elasticsearch...")
    import time
    time.sleep(2)  # Chờ ES index xong

    events = query_recent_events(es, minutes=43200) # 30 ngày
    print(f"[+] Tìm thấy {len(events)} event trong 30 ngày qua")

    for ev in events[:3]:  # In 3 event đầu
        print(json.dumps(ev, indent=2, ensure_ascii=False))
        print("-" * 50)
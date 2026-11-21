"""Target and decoy HTTP backend; state operations belong to honeypatch."""
import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json

from . import config, proc
from .memory import Heap, heap_to_list, initial_heap, view
from .honeypatch import (
    ServerState, SessionForked, SKIPPED, hp_init, hp_fork, hp_skip,
    restore, terminate,
)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "hp-sim"
    sys_version = ""

    # 기본 접근 로그 호출 -> 출력 생략.
    # 입력: 로그 형식과 인자. 출력: 없음(None), 로그를 기록하지 않음.
    def log_message(self, format, *args):
        pass

    # 미지원 메서드는 요청 분기로 전달 -> 나머지는 기본 오류 응답 처리.
    # 입력: 오류 코드와 선택적 설명. 출력: 없음(None), HTTP 응답 전송.
    def send_error(self, code, message=None, explain=None):
        # The base handler sends 501 before dispatching unknown methods.
        if code == 501:
            self.close_connection = True
            self.dispatch()
            return
        super().send_error(code, message, explain)

    # 상태와 헤더 작성 -> 본문 전송(HEAD는 본문 생략).
    # 입력: 상태 코드, 본문 바이트, 콘텐츠 유형, 추가 헤더. 출력: 없음(None), HTTP 응답 전송.
    def respond(self, status, body=b"", content_type="text/plain", headers=None):
        if self.command == "POST" and self.path == "/heartbeat":
            content_type = "application/octet-stream"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            self.send_header("Connection", "close")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    # 데이터를 JSON으로 변환 -> HTTP 응답 전송.
    # 입력: 상태 코드와 직렬화할 데이터. 출력: 없음(None), JSON 응답 전송.
    def json_response(self, status, data):
        self.respond(status, json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                     "application/json")

    # 본문 길이와 전송 형식 검사 -> 지정된 길이만큼 읽기.
    # 입력: limited는 MAX_BODY 제한 적용 여부. 출력: 본문 바이트, 형식 오류 시 ValueError.
    def read_body(self, limited=True):
        # Reject ambiguous framing rather than leave unread bytes on keep-alive.
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") is not None or len(lengths) != 1:
            self.close_connection = True
            raise ValueError("invalid framing")
        raw = lengths[0]
        if not raw.isascii() or not raw.isdecimal():
            self.close_connection = True
            raise ValueError("invalid length")
        length = int(raw)
        if limited and length > config.MAX_BODY:
            self.close_connection = True
            raise ValueError("body too large")
        body = self.rfile.read(length)
        if len(body) != length:
            self.close_connection = True
            raise ValueError("incomplete body")
        return body

    # GET 요청 수신 -> 공통 요청 처리로 전달.
    # 입력: 처리기에 저장된 요청 정보. 출력: 없음(None), HTTP 응답 전송.
    def do_GET(self):
        self.dispatch()

    # POST 요청 수신 -> 공통 요청 처리로 전달.
    # 입력: 처리기에 저장된 요청 정보. 출력: 없음(None), HTTP 응답 전송.
    def do_POST(self):
        self.dispatch()

    # 경로와 세션 확인 -> heartbeat 형식 검증 -> 해당 요청 처리.
    # 입력: 현재 요청과 서버 상태. 출력: 없음(None), HTTP 응답 및 필요한 상태 변경.
    def dispatch(self):
        state = self.server.state
        if self.path.startswith("/_hp/"):
            self.internal(state)
            return
        conn_id = self.headers.get("X-HP-Conn")
        if not conn_id:
            self.close_connection = True
            self.respond(400, config.BAD_REQUEST_BODY)
            return
        with state.lock:
            session = state.sessions.get(conn_id)
        if session is None and state.context == "decoy":
            self.close_connection = True
            self.respond(503)
            return
        is_heartbeat = self.command == "POST" and self.path == "/heartbeat"
        if is_heartbeat:
            # Validate before hp_init: even a first malformed request must leave
            # the session table and heap unchanged.
            try:
                payload, length = self.parse_heartbeat(self.read_body())
            except (ValueError, UnicodeError):
                self.respond(400, config.BAD_REQUEST_BODY)
                return
        if session is None:
            session = hp_init(state, conn_id)
        if is_heartbeat:
            try:
                self.heartbeat(state, session, payload, length)
            except SessionForked:
                self.respond(204, headers={"X-HP-Forked": "1"})
        elif self.command == "GET" and self.path == "/index.html":
            with state.lock:
                session.requests += 1
            self.respond(200, config.INDEX_HTML, "text/html")
        elif self.command == "GET" and self.path == "/session":
            with state.lock:
                session.requests += 1
                data = {"requests": session.requests, "token": session.token.decode("utf-8")}
            self.json_response(200, data)
        else:
            if self.command == "POST":
                self.close_connection = True
            self.respond(404, b"not found\n")

    # JSON 구조와 필드 검사 -> payload를 UTF-8 바이트로 변환.
    # 입력: 요청 본문 바이트. 출력: (payload 바이트, 요청 길이), 잘못된 입력은 예외 발생.
    @staticmethod
    def parse_heartbeat(body):
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError("object required")
        payload, length = data.get("payload"), data.get("len")
        if not isinstance(payload, str) or type(length) is not int or length < 0:
            raise ValueError("invalid heartbeat")
        payload = payload.encode("utf-8")
        if len(payload) > config.BUF_SIZE:
            raise ValueError("payload too long")
        return payload, length

    # mode별 패치 적용 -> 허용 시 버퍼 갱신 -> 메모리 뷰 응답.
    # 입력: 서버 상태, 세션, 검증된 payload와 길이. 출력: 없음(None), 응답 또는 포크 예외.
    def heartbeat(self, state, session, payload, length):
        def reject():
            return (400, config.REJECT_BODY)

        if length > len(payload):
            if state.mode == "patched":
                self.respond(*reject())
                return
            if state.mode == "honeypatched":
                hp_fork(state, session)
                result = hp_skip(state, reject)
                if result is not SKIPPED:
                    self.respond(*result)
                    return
        with state.lock:
            session.buf[:len(payload)] = payload
            response = view(bytes(session.buf), state.heap)[:length]
            session.requests += 1
        self.respond(200, response)

    # 내부 경로 확인 -> 상태 조회, 복원 또는 세션 종료 -> 결과 응답.
    # 입력: 서버 상태와 현재 내부 요청. 출력: 없음(None), HTTP 응답 및 필요한 상태 변경.
    def internal(self, state):
        try:
            if self.command == "GET" and self.path == "/_hp/state":
                with state.lock:
                    data = {
                        "context": state.context, "heap": heap_to_list(state.heap),
                        "sessions": [{"conn_id": s.conn_id, "requests": s.requests,
                                      "buf": base64.b64encode(s.buf).decode("ascii")}
                                     for s in state.sessions.values()],
                    }
                self.json_response(200, data)
                return
            if self.command == "POST" and self.path == "/_hp/restore" and state.context == "decoy":
                # Whole heaps can exceed the public heartbeat body limit.
                restore(state, json.loads(self.read_body(limited=False)))
                self.json_response(200, {"ok": True})
                return
            if self.command == "POST" and self.path == "/_hp/close" and state.context == "target":
                data = json.loads(self.read_body())
                if not isinstance(data, dict) or not isinstance(data.get("conn_id"), str):
                    raise ValueError("conn_id required")
                terminate(state, data["conn_id"])
                self.json_response(200, {"ok": True})
                return
        except (ValueError, UnicodeError):
            self.json_response(400, {"ok": False})
            return
        if self.command == "POST":
            self.close_connection = True
        self.respond(404, b"not found\n")


# 실행 인자 해석 -> 서버 상태 생성 -> 로컬 포트 개방 -> READY 출력 -> 요청 대기.
# 입력: 명령행 실행 옵션. 출력: 반환값 없음(None), 서버 실행과 READY 신호 출력.
def main():
    proc.exit_when_parent_dies()
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, choices=("target", "decoy"))
    parser.add_argument("--mode", required=True, choices=("unpatched", "patched", "honeypatched"))
    parser.add_argument("--redact", default="on", choices=("on", "off", "nofreed"))
    parser.add_argument("--proxy-control", type=int, default=0)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    state = ServerState(context=args.context, mode=args.mode, redact=args.redact,
                        name=args.name, proxy_control_port=args.proxy_control,
                        heap=initial_heap() if args.context == "target" else Heap())
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.daemon_threads = True
        server.state = state
        proc.announce_ready({"port": server.server_port})
        server.serve_forever()


if __name__ == "__main__":
    main()

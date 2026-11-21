"""Portable child process lifecycle shared by all simulator processes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from typing import Callable, Optional

from . import config


# 자식 프로세스를 실행 -> READY 신호를 확인 -> 프로세스와 기동 정보를 반환.
# 입력: module은 실행할 모듈 이름, args는 모듈에 전달할 명령행 인자 목록.
# 출력: (자식 프로세스 제어 객체, READY의 JSON을 해석한 기동 정보 사전).
# 예외: READY 대기 시간 초과, 조기 종료, 형식 오류 시 자식을 정리하고 RuntimeError 발생.
def spawn(module: str, args: list[str]) -> tuple[subprocess.Popen, dict]:
    proc = subprocess.Popen(
        [sys.executable, "-m", module, *args],
        cwd=Path(__file__).resolve().parent.parent,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None,
    )
    result = []

    def read():
        try:
            result.append(proc.stdout.readline())
        except (OSError, ValueError):
            result.append(b"")

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    reader.join(config.READY_TIMEOUT)
    try:
        if reader.is_alive():
            raise ValueError("READY timeout")
        line = result[0].decode("utf-8")
        if not line.startswith("READY ") or not line.endswith("\n"):
            raise ValueError("invalid READY line")
        info = json.loads(line[6:])
        if not isinstance(info, dict):
            raise ValueError("READY payload must be an object")
        if proc.poll() is not None:
            raise ValueError("child exited before startup completed")
        return proc, info
    except (ValueError, IndexError) as exc:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        reader.join()
        stop(proc)
        raise RuntimeError(
            "{}: {} (exit code {})".format(module, exc, proc.returncode)
        ) from exc


# 종료 콜백 실행 -> stdin 닫기 -> 종료 대기 -> 필요 시 강제 종료 -> 파이프 정리.
# 입력: proc은 종료할 자식 프로세스, shutdown은 선택적인 종료 요청 함수(인자 없음).
# 출력: 반환값 없음(None). 자식 프로세스 종료와 파이프 정리를 완료.
def stop(proc: subprocess.Popen, shutdown: Optional[Callable[[], None]] = None) -> None:
    if shutdown is not None:
        try:
            shutdown()
        except Exception:
            pass
    if proc.stdin is not None:
        try:
            proc.stdin.close()
        except (OSError, ValueError):
            pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    if proc.stdout is not None:
        proc.stdout.close()


# 기동 정보를 JSON으로 변환 -> READY 한 줄 출력 -> 출력 버퍼를 즉시 비우기.
# 입력: info는 포트 등 부모에게 전달할 JSON 직렬화 가능한 기동 정보 사전.
# 출력: 반환값 없음(None). 표준 출력에 'READY <JSON>\n'을 기록.
def announce_ready(info: dict) -> None:
    print("READY " + json.dumps(info, ensure_ascii=True), flush=True)


# 감시 스레드 시작 -> 부모의 stdin 파이프 종료 감지 -> 현재 자식 프로세스 종료.
# 입력: 함수 인자 없음. 부모가 연결한 표준 입력 파이프를 감시 대상으로 사용.
# 출력: 반환값 없음(None). 감시 스레드를 시작한 뒤 즉시 반환.
def exit_when_parent_dies() -> None:
    def watch():
        try:
            sys.stdin.buffer.read()
        finally:
            os._exit(0)
    threading.Thread(target=watch, daemon=True).start()

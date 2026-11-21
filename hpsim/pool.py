"""M4 pool: released decoys are stopped and remain recycling until close."""
from dataclasses import dataclass
from subprocess import Popen
import threading
from typing import Optional

from . import proc


@dataclass
class Decoy:
    name: str
    port: int
    proc: Popen
    state: str
    conn_id: Optional[str] = None


class Pool:
    # 지정 개수의 미끼 실행 -> READY 확인 -> available 상태로 등록.
    # 입력: 미끼 개수와 서버 실행 인자 목록. 출력: 없음(None), 풀 초기화 완료.
    def __init__(self, size: int, server_args: list) -> None:
        if type(size) is not int or size < 0:
            raise ValueError("size must be a nonnegative integer")
        self._lock = threading.Lock()
        self._decoys = []
        self._workers = []
        self._closed = False
        try:
            for number in range(1, size + 1):
                name = "decoy-{}".format(number)
                child, ready = proc.spawn("hpsim.server", server_args + ["--context", "decoy", "--name", name])
                try:
                    port = ready["port"]
                    if type(port) is not int or not 0 < port < 65536:
                        raise ValueError("invalid decoy port")
                    self._decoys.append(Decoy(name, port, child, "available"))
                except Exception:
                    proc.stop(child)
                    raise
        except Exception:
            self.close()
            raise

    # 번호가 가장 작은 available 미끼 선택 -> 연결 배정 -> running으로 변경.
    # 입력: 점유할 연결 ID. 출력: 배정된 Decoy, 배정 불가 시 None.
    def acquire(self, conn_id: str) -> Optional[Decoy]:
        with self._lock:
            if not self._closed:
                for decoy in self._decoys:
                    if decoy.state == "available":
                        decoy.state, decoy.conn_id = "running", conn_id
                        return decoy
        return None

    # 점유 해제 -> recycling으로 변경 -> 백그라운드에서 프로세스 종료.
    # 입력: 반납할 Decoy. 출력: 없음(None), 종료 완료를 기다리지 않고 반환(M4는 재생성 없음).
    def release(self, decoy: Decoy) -> None:
        with self._lock:
            if self._closed or not any(d is decoy for d in self._decoys) or decoy.state != "running":
                return
            decoy.state, decoy.conn_id = "recycling", None
            ready = threading.Event()

            def clean():
                ready.wait()
                proc.stop(decoy.proc)

            worker = threading.Thread(target=clean, daemon=True)
            self._workers.append(worker)
            worker.start()
        ready.set()

    # 풀 상태를 잠금 안에서 조회 -> 미끼별 이름과 상태 목록 생성.
    # 입력: 인자 없음, 현재 풀 참조. 출력: 이름과 상태를 담은 사전 목록.
    def status(self) -> list:
        with self._lock:
            return [{"name": d.name, "state": d.state} for d in self._decoys]

    # 풀 사용 중단 -> 반납 작업 완료 대기 -> 나머지 미끼 종료.
    # 입력: 인자 없음, 현재 풀 참조. 출력: 없음(None), 모든 미끼 프로세스 정리 완료.
    def close(self) -> None:
        with self._lock:
            self._closed = True
            workers = list(self._workers)
            # Release workers own their child until joined; avoid concurrent stop.
            active = [d.proc for d in self._decoys if d.state != "recycling"]
            for decoy in self._decoys:
                decoy.state, decoy.conn_id = "recycling", None
        for worker in workers:
            worker.join()
        for child in active:
            proc.stop(child)

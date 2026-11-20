# honeypatch-sim 구현 명세 (v1.4.1)

Honey-Patches(Araujo et al., ACM CCS 2014)의 세션 포크 절차를 로컬 프로세스로 모사하는 시뮬레이터의 구현 명세다. 이 문서 하나만 보고 LLM이 처음부터 끝까지 구현할 수 있도록, 선택지가 있는 곳은 모두 하나로 정해 두었다. 구현자는 이 문서에 없는 동작을 임의로 추가하지 않는다. 문서가 모호하면 15절의 우선순위를 따른다.

**v1.1 변경 사항 (12주차 조교 피드백 반영).**

| 피드백 | 반영 |
|---|---|
| 풀 재활용보다 3연속 요청 복원부터 우선 확인 | 14절 단계를 재구성. 프록시·풀 없이 상태 복원만 검증하는 단계(M3, `test_fork.py`)를 포크 통합(M4)보다 앞에 두고, 풀 재생성·타임아웃은 13주차(M6)로 미룸. 8절에 M4용 단순 반납 규칙 추가 |
| 해제 메모리 치환(논문 4.1절) 참고 | 고정 사례 attack.json의 ②(len=64)는 해제 메모리 H3(오프셋 64~83) 직전에서 끝나 이를 검증하지 못함. 정적 해제 레코드(H3)와 종료된 세션의 토큰을 함께 검증하는 `freed_session.json`(on)과 `freed_session_nofreed.json`을 12주차 필수 사례로 추가(11.2절), 5.3절에 redaction 기준 사례 추가 |
| 원논문 차이 기록 | 1절 대응표에 400 응답, 세션 종료 시점, 결정적 가짜 값 3행 추가 |
| 전·후 결과 비교·저장, 재현 환경 명세 | 10.3절에 `results/` 저장 규칙, 3절에 README 필수 항목 추가 |

고정 사례 3종(11.1절)의 입력과 기대값은 바꾸지 않았다.

**v1.2 변경 사항.** 대상 OS를 **Windows와 macOS**로 확정하고, 두 OS 모두 README만 따라 하면 같은 결과가 나오도록 2.1~2.3절(플랫폼 규칙, README 실행 안내, 두 OS 검증 절차)을 추가했다. M5 완료 기준을 "두 OS에서 확인"으로 바꿨다.

**v1.3 변경 사항.** 6절의 자식 프로세스 기동·종료 규약을 공용 모듈 `proc.py`로 묶었다(6.1절). runner→proxy, proxy→server·decoy가 같은 코드를 쓰게 해 OS 관련 버그를 한 곳에서 고치기 위함이다. 12주차 업무 분담을 부록 A로 추가했다.

**v1.4 변경 사항.** 분담 전에 프로세스 안의 모듈 인터페이스를 확정했다. 3.1절(import 방향, 파일 소유자, 락 규칙), 5.4절(`memory.py` 공개 API, `Session` 이동), 7.4절(`ServerState`와 honeypatch 함수 시그니처), 8.1절(`pool.py` API)을 추가하고, 7.3절 의사 코드를 새 시그니처에 맞췄다. 동작과 기대값은 바뀌지 않았다.

**v1.4.1 변경 사항.** 14절 표에 중복으로 들어간 3열 머리글을 지웠다. 내용은 바뀌지 않았다.

## 1. 목표와 범위

**보여줄 것.** 같은 공격 요청에 대해 세 서버가 다르게 반응한다.

| mode | 공격 요청(len > payload 길이)에 대한 동작 | 공격자가 보는 것 |
|---|---|---|
| `unpatched` | 검사 없음. 버퍼 뒤 메모리를 그대로 읽어 반환 | 200, 실제 비밀 |
| `patched` | 검사 후 거부 | 400 (패치 사실이 드러남) |
| `honeypatched` | 검사 후 세션을 미끼로 포크, 미끼가 미패치처럼 응답 | 200, 같은 길이의 가짜 비밀 |

**범위 안.** hp_init / hp_fork / hp_skip 구조, 리버스 프록시의 연결 유지와 라우팅 전환, 세션 상태의 직렬화·복원, 메모리 redaction, 미끼 풀의 획득·반납·재생성, 포크 실패 시 원래 패치로 복귀.

**범위 밖.** CRIU, LXC, TCP repair, TLS, 실제 Apache. 인증, 영속 저장, 성능 최적화도 하지 않는다.

**원논문과의 대응.**

| 논문 | 이 구현 |
|---|---|
| CRIU 체크포인트·복원 | 세션 객체와 힙 레코드의 JSON 직렬화·복원 |
| 요청 처리 도중 재개 | 복원된 상태 위에서 같은 요청을 미끼에 재전송(replay). 7.3절의 멱등성 불변식으로 동일 결과 보장 |
| LXC 컨테이너 풀 | 로컬 프로세스 풀 (재생성 = 프로세스 종료 후 새로 실행) |
| TCP 연결 재배치 | 프록시가 클라이언트 연결을 쥔 채 업스트림만 교체 |
| 메모리 redaction (구조체 단위, 해제된 메모리도 검색 대상, 4.1절) | 힙 레코드 단위 치환, `freed` 레코드 포함 (해제된 정적 레코드 H3, 종료된 세션의 토큰 `S:<conn_id>`) |
| 패치의 차단 동작: 요청을 조용히 버림(Listing 1) | 400과 `heartbeat rejected\n` (공격자가 패치 여부를 알아채는 차이를 출력으로 보이기 위함) |
| 체크포인트 직후 target의 공격자 세션 종료(Fig. 3 4.2단계) | 미끼 복원이 성공한 뒤에 종료. 복원 실패 시 원래 패치로 돌아가려면 세션이 남아 있어야 하기 때문 |
| 가짜 값을 무작위로 생성(4.1절) | 시드 기반 해시로 결정적으로 생성. 팀원 누구의 환경에서나 같은 출력을 얻기 위함 |

## 2. 실행 환경과 제약

- Python 3.9 이상. **런타임은 표준 라이브러리만** 쓴다: `http.server`, `http.client`, `socketserver`, `subprocess`, `threading`, `json`, `hashlib`, `base64`, `argparse`, `time`. 테스트에만 `pytest`를 쓴다.
- **대상 OS는 Windows 10/11과 macOS(Intel, Apple Silicon)다.** 두 OS에서 README만 따라 했을 때 같은 결과가 나와야 한다. Linux는 보장 대상이 아니다.
- `multiprocessing`과 `os.fork`는 쓰지 않는다. 프로세스는 `subprocess.Popen([sys.executable, "-m", ...])`로만 띄운다.
- 모든 소켓은 `127.0.0.1`에만 바인드하고, 포트는 `0`(자동 할당)으로 받는다. 고정 포트 금지.
- 난수(`random`, `secrets`, `uuid`)와 현재 시각을 출력 내용에 쓰지 않는다. 응답 시간만 예외이며, 응답 시간은 합격 판정에 쓰지 않는다.

### 2.1 플랫폼 규칙 (Windows·macOS 공통)

아래 규칙은 한 OS에서만 문제가 드러나는 지점들이다. 작성자 PC에서 통과해도 다른 OS에서 실패하거나 멈출 수 있으므로 모두 지킨다.

| 항목 | 규칙 | 지키지 않으면 |
|---|---|---|
| 접속 주소 | 바인드와 **접속 모두** 문자열 `"127.0.0.1"`을 쓴다. `"localhost"` 금지 | Windows에서 `localhost`가 IPv6(`::1`)로 먼저 풀려 연결마다 약 2초 지연, 타임아웃 실패 |
| 0.0.0.0 | 바인드 금지 | Windows 방화벽·macOS 방화벽 허용 창이 떠 실행이 멈춤 |
| 파일 인코딩 | 모든 `open()`에 `encoding="utf-8"`을 명시한다 | 한국어 Windows는 기본이 cp949라 JSON 읽기·쓰기에서 오류 |
| 줄바꿈 | 쓰는 파일은 `open(..., "w", encoding="utf-8", newline="\n")` | Windows에서 CRLF로 저장되어 두 OS의 `results/` 비교가 어긋남 |
| 화면 출력 | 콘솔에 쓰는 모든 문자열은 **ASCII만** 쓴다(`×`, `✓`, `—`, 한글 금지). 본문의 비ASCII 바이트는 `\xNN`으로 표시 | Windows 콘솔(cp949)에서 `UnicodeEncodeError`로 중단 |
| 경로 | 저장소 루트는 `Path(__file__).resolve().parent`에서 구하고, 시나리오·결과 경로는 이를 기준으로 만든다. 경로 문자열 결합(`"/"`, `"\\"`) 금지 | 저장소 밖 폴더에서 실행하거나 OS가 바뀌면 파일을 못 찾음 |
| 자식 프로세스 위치 | `Popen(..., cwd=<저장소 루트>)`로 띄운다 | `-m hpsim.server`가 패키지를 못 찾음 |
| 자식 프로세스 입출력 | `stdin=PIPE`(종료 감지용), `stdout=PIPE`(READY 한 줄만), `stderr`는 상속. 자식은 READY 이후 stdout에 아무것도 쓰지 않는다. `BaseHTTPRequestHandler.log_message`는 아무것도 하지 않게 재정의한다. READY 줄은 바이트로 읽고 `utf-8`로 디코드한다 | 읽지 않는 파이프 버퍼가 차서 자식이 멈춤(Windows는 버퍼가 작아 먼저 드러남) |
| 자식 종료 | 6절의 stdin 감시 규칙만 쓴다. 시그널(`SIGTERM`, `os.kill`) 기반 종료 금지 | Windows에는 해당 시그널이 없음 |
| 대기 시간 | `READY_TIMEOUT`은 20초로 한다(4절 값 대체) | Windows에서 백신 검사로 첫 기동이 느려 오탐 실패 |
| 파이썬 문법 | 3.9에서 동작하는 문법만 쓴다. `X \| Y` 타입 표기, `match` 문 금지(`Optional`, `Union` 사용) | macOS 기본 `python3`(Xcode 도구, 3.9)에서 문법 오류 |
| Git 줄바꿈 | 저장소에 `.gitattributes`를 두고 `* text=auto eol=lf`로 고정한다 | Windows에서 clone 시 시나리오·결과 파일이 CRLF로 바뀜 |

### 2.2 README 실행 안내 (그대로 쓴다)

명령은 OS마다 한 줄이다. 파이썬 실행 이름만 다르다.

````markdown
## 실행

준비: Python 3.9 이상. 추가 설치는 없습니다.
- Windows: python.org 설치 프로그램으로 설치(설치 화면에서 "Add python.exe to PATH" 선택)
- macOS: 터미널에서 `python3 --version`으로 확인(없으면 python.org에서 설치)

저장소 폴더에서 한 줄 실행:

| OS | 명령 |
|---|---|
| Windows (PowerShell, 명령 프롬프트) | `py demo.py` |
| macOS (터미널) | `python3 demo.py` |

마지막 줄이 `ALL PASS`이면 정상입니다. 결과는 `results/demo.txt`, `results/demo.json`에 저장됩니다.

테스트(선택): `py -m pip install pytest` 후 `py -m pytest` (macOS는 `py` 대신 `python3`)

확인한 환경: Windows 11 / Python 3.x.x, macOS 1x / Python 3.x.x
````

- `demo.py`는 시작할 때 `sys.version_info < (3, 9)`이면 `Python 3.9 or later is required`를 출력하고 종료 코드 2로 끝난다.
- `demo.py`의 마지막 줄은 전부 통과면 `ALL PASS`, 아니면 `FAIL: <시나리오 이름들>`이다.
- Windows의 `python` 명령은 Microsoft Store 안내로 연결될 수 있어 README에는 `py`를 쓴다.

### 2.3 두 OS 검증 절차

M5에서 아래를 **Windows PC 1대, macOS PC 1대**에서 각각 수행하고, 결과를 12주차 보고서의 재현 확인 메모로 쓴다.

1. 저장소를 새 폴더에 clone한다(작성자의 작업 폴더를 쓰지 않는다).
2. README의 명령 한 줄만 실행한다. 다른 명령이나 설정을 하지 않는다.
3. 마지막 줄이 `ALL PASS`인지 확인한다.
4. 실행이 끝난 뒤 `python -m hpsim` 프로세스가 남아 있지 않은지 확인한다(Windows: 작업 관리자, macOS: `ps aux | grep hpsim`).
5. 두 OS의 `results/demo.txt`에서 `ms` 열을 뺀 내용이 같은지 비교한다. `python3 -m hpsim.cli compare A.txt B.txt`가 `ms` 열을 제외하고 비교해 같으면 `SAME`을 출력한다.
6. OS 이름·버전, Python 버전, 소요 시간, 결과를 기록한다.

## 3. 저장소 구조

```
honeypatch-sim/
  README.md            # 설치 없음, OS별 명령 한 줄 (2.2절)
  .gitattributes       # * text=auto eol=lf (2.1절)
  demo.py              # 기본 3종 + 12주차 필수 사례 × mode 3개 실행, 비교표 출력·저장
  hpsim/
    __init__.py
    config.py          # 4절 상수
    proc.py            # 자식 프로세스 기동·종료 공용 함수 (6.1절)
    memory.py          # Record, Heap, Session, view(), redact(), 스냅샷 변환 (5.4절)
    honeypatch.py      # ServerState, hp_init, hp_fork, hp_skip, checkpoint, terminate, restore (7.4절)
    server.py          # 백엔드 서버(target/decoy) 프로세스 진입점
    pool.py            # 미끼 풀
    proxy.py           # 리버스 프록시 + 포크 조율, 프로세스 진입점
    runner.py          # 시나리오 실행, 기대값 대조
    report.py          # 표·JSON 출력
    cli.py             # `python -m hpsim.cli run ...`
  scenarios/           # 11절의 JSON 파일
  tests/
    test_memory.py  test_proc.py  test_modes.py  test_fork.py  test_pool.py  test_indistinguishable.py
  results/             # demo.py가 쓰는 실행 결과 (10.3절). 저장소에 커밋한다
```

### 3.1 모듈 경계 규칙

**import 방향.** 화살표 방향으로만 import한다. 표에 없는 hpsim 모듈은 import하지 않는다. 프로세스가 다른 모듈끼리(예: proxy와 server)는 import하지 않고 HTTP로만 통신한다.

| 모듈 | import해도 되는 hpsim 모듈 | 소유자(부록 A) |
|---|---|---|
| `config` | 없음 | A |
| `proc` | `config` | B |
| `memory` | `config` | A |
| `honeypatch` | `config`, `memory` | A |
| `server` | `config`, `memory`, `honeypatch`, `proc` | B |
| `pool` | `config`, `proc` | B |
| `proxy` | `config`, `proc`, `pool` | C |
| `runner`, `report`, `cli`, `demo.py` | `config`, `proc`, `memory`(10.2절의 실제 비밀 계산용 `session_token`과 초기 레코드만), 그리고 서로 | D |

**파일당 소유자는 한 명이다.** 다른 사람의 파일이 필요하면 그 파일의 공개 API만 쓰고, 고칠 일이 있으면 소유자에게 요청한다. 공개 API는 5.4, 6.1, 7.4, 8.1절에 적힌 이름이 전부이며, 이름이 `_`로 시작하는 함수는 다른 파일에서 쓰지 않는다.

**락 규칙.** 서버 상태는 `ServerState.lock`(`threading.Lock`, 재진입 불가) 하나로 보호한다.

1. `memory.py`의 함수는 락을 모른다. 인자만 읽고, 원본을 바꾸지 않는 함수는 그렇다고 적혀 있다.
2. `honeypatch.py`의 상태 함수(`hp_init`, `checkpoint`, `terminate`, `restore`)는 **내부에서** 락을 잡는다. 호출자는 락을 쥐지 않은 채로 부른다.
3. `hp_fork`는 락을 잡은 채로 HTTP를 호출하지 않는다. 락은 `checkpoint`와 `terminate` 안에서만 잠깐 잡힌다.
4. `server.py`는 세션 조회, `/heartbeat` (c)단계, `/session` 응답을 만들 때만 직접 `with state.lock:`을 쓰고, 그 블록 안에서 honeypatch 함수나 HTTP를 호출하지 않는다.

**README 필수 항목.** 2.2절의 실행 안내(OS별 명령 한 줄, 확인한 OS와 Python 버전, 테스트 명령, 결과 파일 위치), 13절의 한계. 저장소 루트에 `.gitattributes`(2.1절)를 둔다.

## 4. 상수 (`config.py`)

| 이름 | 값 | 뜻 |
|---|---|---|
| `SEED` | `"honeypatch-sim"` | 가짜 값·세션 토큰 생성용 시드 |
| `BUF_SIZE` | `16` | 세션 버퍼 바이트 수 |
| `BUF_FILL` | `b"."` | 세션 버퍼 초기값 |
| `MAX_BODY` | `4096` | 요청 본문 최대 바이트 |
| `IDLE_TIMEOUT` | `5.0` | 클라이언트 연결 유휴 타임아웃(초) |
| `SESSION_TIMEOUT` | `30.0` | 미끼 점유 최대 시간(초) |
| `UPSTREAM_TIMEOUT` | `5.0` | 프록시→백엔드, 백엔드→프록시 호출 타임아웃(초) |
| `READY_TIMEOUT` | `20.0` | 자식 프로세스 기동 대기(초). Windows 첫 기동 지연을 고려한 값(2.1절) |
| `INDEX_HTML` | `b"<html><body><h1>hp-sim</h1></body></html>\n"` | `/index.html` 본문 |
| `REJECT_BODY` | `b"heartbeat rejected\n"` | 패치의 거부 응답 본문 |
| `BAD_REQUEST_BODY` | `b"bad request\n"` | 형식 오류 응답 본문 |

**초기 힙 레코드.** 서버(target)가 시작할 때 아래 순서로 넣는다. 값은 한 글자도 바꾸지 않는다.

| id | kind | owner | sensitive | freed | value | 길이 |
|---|---|---|---|---|---|---|
| H0 | banner | server | false | false | `SRVMEM::` | 8 |
| H1 | session_token | alice | true | false | `tok_alice_7f3a9c2e51` | 20 |
| H2 | session_token | bob | true | false | `tok_bob_c41d88e0a7f2` | 20 |
| H3 | session_token | carol | true | **true** | `tok_carol_09be3d71c6` | 20 |
| H4 | api_key | admin | true | false | `key_admin_5d2f90ab13c7e8` | 24 |

H3은 "로그아웃한 사용자의 토큰이 해제된 메모리에 남아 있는" 상황을 나타낸다. 초기 힙은 합계 92바이트다.

## 5. 메모리 모델 (`memory.py`)

### 5.1 자료 구조

```python
@dataclass
class Record:
    id: str          # "H0".."H4" 또는 "S:<conn_id>"
    kind: str
    owner: str       # "server", 사용자 이름, 또는 conn_id
    sensitive: bool
    freed: bool
    value: bytes

class Heap:
    records: list[Record]          # 순서가 곧 메모리 배치
```

세션마다 `BUF_SIZE` 바이트의 버퍼를 가지며, **세션의 메모리 뷰는 "자기 버퍼 바로 뒤에 힙 전체가 이어진 것"**으로 정의한다.

```
view(buf, heap) = buf (16B)  ||  H0 || H1 || H2 || H3 || H4 || S:c1 || S:c2 || ...
offset             0..15           16   24   44   64   84    108     128
```

`S:<conn_id>`는 세션이 만들어질 때 힙 끝에 붙는 그 세션의 토큰 레코드다(kind=`session_token`, owner=`<conn_id>`, sensitive=true, freed=false). 세션이 끝나면 레코드를 지우지 않고 `freed=True`로만 바꾼다.

### 5.2 결정적 값 생성

```python
def _hex(s: str, n: int) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:n]

def session_token(conn_id: str) -> bytes:              # 항상 20바이트
    return ("tok_" + _hex(f"{SEED}:session:{conn_id}", 16)).encode()

def fake_value(record_id: str, value: bytes) -> bytes:  # 길이 보존, 앞 4바이트 접두어 보존
    return value[:4] + _hex(f"{SEED}:fake:{record_id}", len(value) - 4).encode()
```

기준값(구현 검증용, `test_memory.py`에 그대로 넣는다):

| 입력 | 결과 |
|---|---|
| `session_token("c1")` | `tok_8aa31bd77f104c99` |
| `session_token("c2")` | `tok_e2276907212c22f0` |
| `fake_value("H1", …)` | `tok_a9bd82d091d5d37e` |
| `fake_value("H2", …)` | `tok_6d6ecbe54f5f762b` |
| `fake_value("H3", …)` | `tok_5beae03b78e5d643` |
| `fake_value("H4", …)` | `key_4bbbdc254ea321a390c5` |
| `fake_value("S:c2", session_token("c2"))` | `tok_3cc8dc7f7e58e11c` |

### 5.3 redaction 규칙

`redact(heap, attacker_conn_id, policy) -> (새 Heap, 치환 개수)`. 원본 힙은 건드리지 않고 복사본을 만든다.

| policy | 치환 대상 |
|---|---|
| `on` | `sensitive` 이고 `owner != attacker_conn_id` 인 모든 레코드 (**freed 포함**) |
| `nofreed` | 위 조건에서 `freed == True` 인 레코드를 제외 (반례 실험용) |
| `off` | 없음 |

치환은 `value = fake_value(id, value)` 이다. 공격자 자신의 레코드(`S:<attacker>`)는 어떤 policy에서도 그대로 둔다. 치환 개수는 실제로 값을 바꾼 레코드 수다.

**해제 메모리.** 논문 4.1절은 해제된 메모리도 redaction 검색 대상에 넣는다. 이 구현에서 해제 메모리는 두 종류다: 처음부터 `freed=True`인 H3, 그리고 세션이 끝나 `freed=True`가 된 `S:<conn_id>`. 둘 다 `on`에서 치환되어야 한다. `freed` 여부로 치환 대상을 거르는 코드는 `nofreed` 분기 하나뿐이어야 한다.

**기준 사례** (`test_memory.py`에 그대로 넣는다). 힙 = 초기 레코드 H0~H4 + `S:c1`(freed=True) + `S:c2`(freed=False), 공격자 = `c2`.

| policy | 치환 개수 | 치환되는 id | `S:c1`의 결과 값 |
|---|---|---|---|
| `on` | 5 | H1, H2, H3, H4, S:c1 | `tok_8b6fdefa40886a62` |
| `nofreed` | 3 | H1, H2, H4 | `tok_8aa31bd77f104c99` (원래 값) |
| `off` | 0 | 없음 | `tok_8aa31bd77f104c99` (원래 값) |

세 경우 모두 `S:c2`는 `tok_e2276907212c22f0`으로 그대로 남는다.

### 5.4 `memory.py` 공개 API

모두 순수 함수다(파일·네트워크·락·전역 상태를 쓰지 않는다). 7.1절의 `Session`은 여기에 정의한다.

```python
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Record:                     # 5.1절과 같음
    id: str; kind: str; owner: str; sensitive: bool; freed: bool; value: bytes

@dataclass
class Heap:
    records: list = field(default_factory=list)      # list[Record], 순서가 곧 배치
    def copy(self) -> "Heap": ...                     # Record까지 깊은 복사
    def get(self, record_id: str) -> Optional[Record]: ...   # 없으면 None
    def append(self, rec: Record) -> None: ...        # 같은 id가 있으면 ValueError

@dataclass
class Session:
    conn_id: str
    token: bytes                  # session_token(conn_id)
    buf: bytearray                # BUF_SIZE 바이트, BUF_FILL로 초기화
    requests: int = 0             # 성공(200) 처리한 요청 수

def session_token(conn_id: str) -> bytes: ...                 # 5.2절
def fake_value(record_id: str, value: bytes) -> bytes: ...    # 5.2절
def initial_heap() -> Heap: ...                               # 4절 표의 H0~H4, 새 객체
def new_session(conn_id: str) -> Session: ...                 # token, buf 초기화
def session_record(session: Session) -> Record: ...           # 5.1절의 S:<conn_id> 레코드
def view(buf: bytes, heap: Heap) -> bytes: ...                # 5.1절. 아무것도 바꾸지 않음
def redact(heap: Heap, attacker_conn_id: str, policy: str) -> tuple:
    """(새 Heap, 치환 개수)를 돌려준다. 원본은 바꾸지 않는다.
    policy가 "on"/"off"/"nofreed"가 아니면 ValueError."""
def heap_to_list(heap: Heap) -> list: ...          # 7.5절 "heap" 배열(값은 base64)
def heap_from_list(items: list) -> Heap: ...       # 형식 오류면 ValueError
def to_snapshot(session: Session, heap: Heap) -> dict: ...    # 7.5절 형식 전체
def from_snapshot(data: dict) -> tuple: ...        # (Session, Heap). version != 1이거나 형식 오류면 ValueError
```

## 6. 프로세스 구성과 수명

```
runner ──spawn──▶ proxy ──spawn──▶ target
                        └─spawn──▶ decoy-1 … decoy-N
```

- **runner** (`demo.py`, `cli.py`): mode 하나를 실행할 때마다 proxy를 새로 띄우고, 시나리오가 끝나면 내린다. 따라서 mode마다 conn_id가 `c1`부터 다시 시작한다.
- **proxy**: 공개 포트(클라이언트용)와 제어 포트(내부용) 두 개를 연다. target 1개와, `honeypatched`일 때만 미끼 `pool`개를 띄운다. 다른 mode에서는 `pool`을 0으로 강제한다.
- **target / decoy**: 같은 `server.py`를 `--context target|decoy`로 실행한다. 포트는 하나다.

**기동 규약.** 자식은 리슨을 시작한 직후 표준 출력에 한 줄을 쓰고 flush 한다.

```
READY {"port": 51234}                          # server
READY {"public_port": 51200, "control_port": 51201}   # proxy
```

부모는 이 줄을 `READY_TIMEOUT` 안에 읽지 못하면 자식을 죽이고 오류로 끝낸다. `time.sleep`으로 기동을 기다리지 않는다.

**종료 규약.** 부모는 자식의 stdin을 파이프로 연다. 자식은 데몬 스레드에서 `sys.stdin.read()`를 호출하고, 반환되면(부모가 죽었거나 파이프를 닫음) `os._exit(0)` 한다. runner는 제어 포트의 `POST /shutdown` → `wait(3초)` → `kill` 순으로 정리한다. 실행이 예외로 끝나도 `try/finally`로 반드시 정리한다.

### 6.1 공용 모듈 `proc.py`

위 기동·종료 규약은 이 모듈에서만 구현한다. runner, proxy, server, pool은 아래 네 함수만 쓰고, `subprocess`를 직접 호출하지 않는다. `proc.py`는 `config` 외의 hpsim 모듈을 import하지 않는다.

```python
from subprocess import Popen
from typing import Callable, Optional

def spawn(module: str, args: list[str]) -> tuple[Popen, dict]:
    """부모가 호출. 자식을 띄우고 READY 줄의 JSON을 dict로 돌려준다.
    - Popen([sys.executable, "-m", module, *args], cwd=<저장소 루트>,
            stdin=PIPE, stdout=PIPE, stderr=None)
    - READY 줄은 별도 스레드에서 stdout.readline()으로 읽고 READY_TIMEOUT 동안 join한다.
      (Windows 파이프에는 select를 쓸 수 없으므로 스레드로 시간 제한을 건다)
    - 줄은 바이트로 읽어 utf-8로 디코드하고, "READY " 접두어 뒤를 json.loads 한다.
    - 시간 초과, 자식의 조기 종료, 형식 오류면 자식을 kill하고 RuntimeError를 낸다.
      메시지에 모듈 이름과 자식의 종료 코드를 넣는다."""

def stop(proc: Popen, shutdown: Optional[Callable[[], None]] = None) -> None:
    """부모가 호출. 자식을 정리한다. 여러 번 불러도 안전해야 한다.
    1) shutdown이 있으면 호출한다(예: runner가 프록시의 POST /shutdown). 예외는 무시한다.
    2) stdin을 닫는다. 3) 3초 기다린다. 4) 아직 살아 있으면 kill 후 wait."""

def announce_ready(info: dict) -> None:
    """자식이 리슨을 시작한 직후 호출. sys.stdout에 "READY " + json.dumps(info)
    한 줄을 쓰고 flush한다. 이후 자식은 stdout에 아무것도 쓰지 않는다."""

def exit_when_parent_dies() -> None:
    """자식이 시작하자마자 호출. 데몬 스레드에서 sys.stdin.buffer.read()가 반환되면
    os._exit(0) 한다. 부모가 비정상 종료해도 자식이 남지 않게 한다."""
```

사용 위치: runner는 `spawn("hpsim.proxy", ...)`와 `stop(proc, shutdown=...)`, proxy는 target과 각 미끼에 `spawn("hpsim.server", ...)`와 `stop(proc)`, pool은 미끼 반납 시 `stop(proc)`. server와 proxy의 진입점은 `exit_when_parent_dies()`로 시작하고 리슨 후 `announce_ready(...)`를 호출한다. proxy가 `/shutdown`을 받으면 자기 자식 전부에 `stop`을 부른 뒤 종료한다.

**단독 검증** (`tests/test_proc.py`): 테스트 전용 자식 모듈(READY만 출력하고 대기)로 ① `spawn`이 dict를 돌려줌 ② READY를 내지 않는 자식은 `READY_TIMEOUT` 뒤 RuntimeError ③ `stop` 후 프로세스가 끝나 있음 ④ 부모 쪽에서 stdin만 닫아도 자식이 종료됨. 테스트에서는 `READY_TIMEOUT`을 짧게 바꿔 쓸 수 있게, `spawn`은 config 값을 호출 시점에 읽는다.

**명령행.**

```
python -m hpsim.proxy  --mode M --redact R --pool N --idle-timeout T --session-timeout T
python -m hpsim.server --context target|decoy --mode M --redact R --proxy-control PORT --name target|decoy-1
```

## 7. 백엔드 서버 (`server.py`, `honeypatch.py`)

`ThreadingHTTPServer` + `BaseHTTPRequestHandler`. `protocol_version = "HTTP/1.1"`, 모든 응답에 `Content-Length`를 넣는다. 서버 상태는 7.4절의 `ServerState` 객체 하나에 담고, 처리기 클래스는 이 객체를 서버 인스턴스의 속성(`self.server.state`)으로 받는다. 모듈 전역 변수에 상태를 두지 않는다. 락은 3.1절 규칙을 따른다.

**진입점.** `python -m hpsim.server ...`은 `proc.exit_when_parent_dies()` → 인자 해석 → `ServerState` 생성(target은 `heap=initial_heap()`, decoy는 빈 `Heap()`) → 리슨 → `proc.announce_ready({"port": ...})` → `serve_forever()` 순서다.

### 7.1 세션

`Session`은 `memory.py`에 정의한다(5.4절).

프록시가 붙여 주는 `X-HP-Conn` 헤더가 세션의 열쇠다. 헤더가 없으면 400이다.

- **target**: `with state.lock:`으로 `state.sessions`를 조회하고, 없으면 락을 푼 뒤 `hp_init(state, conn_id)`로 세션을 만든다(`S:<conn_id>` 레코드가 힙 끝에 붙는다).
- **decoy**: 복원된 세션의 conn_id만 받는다. 다른 conn_id면 `503`과 빈 본문.

### 7.2 공개 엔드포인트

성공(200) 응답을 만들 때마다 `session.requests += 1` 한다. 4xx 응답은 세지 않는다.

| 요청 | 응답 |
|---|---|
| `POST /heartbeat` | 7.3절. `Content-Type: application/octet-stream` |
| `GET /index.html` | 200, `INDEX_HTML`, `text/html` |
| `GET /session` | 200, `application/json`. 본문은 `json.dumps({"requests": n, "token": token}, sort_keys=True, separators=(",", ":"))`. `n`은 이 요청을 포함한 값 |
| 그 외 | 404, 본문 `not found\n`, `text/plain` |

### 7.3 `/heartbeat` 처리 순서

요청 본문은 JSON `{"payload": <문자열>, "len": <정수>}` 이다. `payload`는 UTF-8로 인코딩한 **바이트** 기준으로 길이를 잰다.

```python
def handle_heartbeat(self, state, session, body):
    # (a) 형식 검증: 모든 mode 공통, 실패하면 400 BAD_REQUEST_BODY
    #     - 본문 > MAX_BODY, JSON 아님, 객체 아님, 키 누락
    #     - payload가 str이 아님, len이 int가 아님(bool 금지), len < 0
    #     - len(payload_bytes) > BUF_SIZE
    payload, length = parse(body)

    # (b) 패치 지점: 이 시점까지 세션·힙을 절대 변경하지 않는다
    if state.mode == "patched":
        if length > len(payload):
            return reject()                      # 400 REJECT_BODY
    elif state.mode == "honeypatched":
        if length > len(payload):
            hp_fork(state, session)              # 락 없이 호출. 성공하면 SessionForked 예외
            r = hp_skip(state, reject)           # decoy에서는 SKIPPED
            if r is not SKIPPED:
                return r
    # unpatched: 검사 없음

    # (c) 취약한 원래 코드 (이 블록 안에서 다른 함수 호출·HTTP 금지)
    with state.lock:
        session.buf[0:len(payload)] = payload    # 나머지 바이트는 그대로(이전 내용 잔존)
        data = view(bytes(session.buf), state.heap)[:length]   # 뷰보다 길면 뷰 길이까지만
        session.requests += 1
    return 200, data
```

**멱등성 불변식.** (b) 이전에는 상태를 바꾸지 않는다. 그래야 target이 찍은 스냅샷 위에서 미끼가 같은 요청을 처음부터 다시 처리해도, 논문처럼 "처리 도중에 재개"한 것과 결과가 같다.

### 7.4 honey-patch API (`honeypatch.py`)

```python
import threading
from dataclasses import dataclass, field
from typing import Callable

@dataclass
class ServerState:
    context: str                  # "target" | "decoy"
    mode: str                     # "unpatched" | "patched" | "honeypatched"
    redact: str                   # "on" | "off" | "nofreed"
    name: str                     # "target" | "decoy-1" ...
    proxy_control_port: int
    heap: Heap
    sessions: dict = field(default_factory=dict)        # conn_id -> Session
    lock: threading.Lock = field(default_factory=threading.Lock)

class SessionForked(Exception): ...
SKIPPED = object()

def hp_init(state: ServerState, conn_id: str) -> Session:
    """target 전용. 락을 잡고, 세션이 이미 있으면 그대로 돌려준다.
    없으면 new_session → state.sessions에 등록 → session_record를 heap에 append."""

def checkpoint(state: ServerState, session: Session) -> tuple:
    """락을 잡고 (snapshot dict, 치환 개수)를 만든다.
    redact(state.heap, session.conn_id, state.redact) 결과와 session으로 to_snapshot.
    state는 바꾸지 않는다. 스냅샷에는 공격자 세션 하나만 넣는다."""

def terminate(state: ServerState, conn_id: str) -> None:
    """락을 잡고 state.sessions에서 conn_id를 제거하고, heap의 S:<conn_id>를 freed=True로.
    세션이나 레코드가 없으면 조용히 넘어간다. /_hp/close도 이 함수를 쓴다."""

def restore(state: ServerState, snapshot: dict) -> None:
    """decoy 전용. from_snapshot으로 읽은 뒤 락을 잡고 state.heap을 교체하고
    state.sessions를 {conn_id: session} 하나로 교체한다. 형식 오류면 ValueError(상태 변경 없음)."""

def hp_fork(state: ServerState, session: Session) -> None:
    """호출자는 락을 쥐지 않는다.
    decoy면 즉시 반환. target이면:
      1) POST /fork/acquire {conn_id}            -> ok가 아니면 반환
      2) snapshot, n = checkpoint(state, session)
      3) POST /fork/restore {conn_id, snapshot, redacted: n} -> ok가 아니면 반환
      4) terminate(state, session.conn_id)
      5) raise SessionForked()
    제어 호출은 http.client로 127.0.0.1:state.proxy_control_port에 보내고,
    타임아웃(UPSTREAM_TIMEOUT)·연결 실패·JSON 오류는 모두 "ok가 아님"으로 처리한다.
    반환(=포크 실패)했을 때 state와 session은 호출 전과 같다."""

def hp_skip(state: ServerState, block: Callable):
    """decoy면 SKIPPED, 아니면 block()의 반환값."""
```

제어 호출이 타임아웃되거나 연결에 실패해도 `hp_fork`는 예외를 내지 않고 반환한다(= 포크 실패).

요청 처리기는 `SessionForked`를 잡아 **포크 표식 응답**을 돌려준다: 상태 `204`, 헤더 `X-HP-Forked: 1`, 본문 없음.

### 7.5 스냅샷 형식

```json
{
  "version": 1,
  "session": {"conn_id": "c1", "token": "<b64>", "buf": "<b64>", "requests": 1},
  "heap": [{"id": "H0", "kind": "banner", "owner": "server",
            "sensitive": false, "freed": false, "value": "<b64>"}, ...]
}
```

- 바이트 값은 모두 base64다.
- `heap`은 5.3절의 redaction을 **적용한 뒤**의 전체 레코드 목록이다. 다른 사용자의 세션 객체는 스냅샷에 넣지 않는다.
- redaction은 target 프로세스 안에서 끝난다. 실제 비밀은 `redact=on`일 때 target 밖으로 나가지 않는다.

### 7.6 내부 엔드포인트 (프록시 전용)

| 요청 | 동작 |
|---|---|
| `POST /_hp/restore` (decoy) | `restore(state, 본문)`. 성공 `{"ok": true}`, `ValueError`면 400과 `{"ok": false}` |
| `POST /_hp/close` (target) | `terminate(state, conn_id)`. 세션 표에서 제거하고 `S:<conn_id>`를 `freed=True`로 바꾼다(없으면 무시). `{"ok": true}` |
| `GET /_hp/state` | 테스트·디버그용. `{"context": ..., "heap": heap_to_list(...), "sessions": [{"conn_id": ..., "requests": n, "buf": <b64>}, ...]}`. 락 안에서 만든다 |

## 8. 미끼 풀 (`pool.py`)

미끼 상태는 `available → running → recycling → available` 로만 움직인다.

- `acquire(conn_id)`: 번호가 가장 작은 `available` 미끼를 `running`으로 바꾸고 돌려준다. 없으면 `None`.
- `release(decoy)`: `recycling`으로 바꾸고, 백그라운드 스레드에서 프로세스를 종료 → 새로 실행 → READY 대기 → `available`. 이름(`decoy-1`)은 유지한다.
- 풀 전체는 하나의 락으로 보호한다.

**반납 조건** (논문 3절의 네 가지):

1. 클라이언트가 연결을 닫음
2. 유휴 시간이 `IDLE_TIMEOUT`을 넘음 (프록시가 클라이언트 연결을 닫는다)
3. 미끼가 죽거나 응답하지 않음 (프록시는 `502`와 `bad gateway\n`를 돌려주고 연결을 닫는다)
4. 미끼 점유 시간이 `SESSION_TIMEOUT`을 넘음 (다음 요청이 도착했을 때 검사, 응답 없이 연결을 닫는다)

어느 경우든 그 클라이언트 연결은 끝난다. 반납된 미끼로 다시 라우팅되는 일은 없다.

### 8.1 `pool.py` 공개 API

```python
from dataclasses import dataclass
from subprocess import Popen
from typing import Optional

@dataclass
class Decoy:
    name: str                     # "decoy-1" ...
    port: int                     # 미끼 서버의 리슨 포트 (READY에서 읽음)
    proc: Popen
    state: str                    # "available" | "running" | "recycling"
    conn_id: Optional[str] = None # running일 때 점유한 연결

class Pool:
    def __init__(self, size: int, server_args: list) -> None:
        """size개의 미끼를 proc.spawn("hpsim.server", server_args + ["--context", "decoy",
        "--name", name])으로 띄우고 모두 READY를 받은 뒤 반환한다. size=0이면 아무것도 띄우지 않는다."""
    def acquire(self, conn_id: str) -> Optional[Decoy]: ...   # 8절 규칙. 없으면 None
    def release(self, decoy: Decoy) -> None:
        """락 안에서 state="recycling", conn_id=None으로 바꾸고 즉시 반환한다.
        프로세스 정리(proc.stop)는 데몬 스레드에서 한다. 같은 미끼를 두 번 반납해도 안전."""
    def status(self) -> list: ...      # [{"name": ..., "state": ...}], 9.2절 /pool 본문
    def close(self) -> None: ...       # 모든 미끼를 proc.stop. 프록시 종료 시 호출
```

`server_args`는 프록시가 만든다: `["--mode", M, "--redact", R, "--proxy-control", str(control_port)]`. 따라서 프록시는 **제어 포트를 먼저 연 뒤** target과 풀을 띄운다. 풀 내부 락을 쥔 채로 `proc` 함수를 부르지 않는다.

**단계별 구현 범위.** M4(12주차)에서는 `release`를 "프로세스를 종료하고 `recycling` 상태로 남김"으로만 구현하고, 반납 조건도 1번(연결 닫힘)만 처리한다. 재생성(`recycling → available`)과 반납 조건 2~4번은 M6(13주차)에서 구현한다. `demo.py`는 시나리오마다 프록시를 새로 띄우므로 M4에서도 기본 3종의 결과는 같다.

## 9. 리버스 프록시 (`proxy.py`)

### 9.1 공개 포트

- `ThreadingHTTPServer`, `protocol_version = "HTTP/1.1"`. 클라이언트 연결 하나에 처리기 인스턴스 하나가 대응한다.
- `setup()`에서 전역 카운터로 `conn_id`(`c1`, `c2`, …)를 발급하고, 이 연결의 백엔드를 `target`으로 둔다. `finish()`에서 정리한다: 백엔드가 미끼면 `release`, target이면 `POST /_hp/close`.
- 처리기의 `timeout`을 `IDLE_TIMEOUT`으로 둔다.
- 경로가 `/_hp/`로 시작하면 백엔드로 보내지 않고 `404 not found\n`을 직접 돌려준다.

**요청 하나의 처리.**

1. 요청줄, 본문(`Content-Length` 기준)을 읽는다. 본문이 `MAX_BODY`를 넘으면 `400 bad request\n`.
2. 현재 백엔드로 새 `http.client.HTTPConnection`을 열어 method, path, body를 보낸다. 붙이는 헤더는 `X-HP-Conn`, `Content-Type`, `Content-Length` 뿐이다.
3. 백엔드가 **target이고** 응답에 `X-HP-Forked: 1`이 있으면, 9.2절에서 예약해 둔 미끼로 이 연결의 백엔드를 바꾸고 **같은 요청을 미끼에 다시 보낸다.** 미끼의 응답을 최종 응답으로 쓴다.
4. 클라이언트에게는 상태 코드, `Content-Type`, `Content-Length`, 본문만 전달한다.

**구분 불가능성 규칙.** 클라이언트가 받는 헤더는 어떤 mode, 어떤 백엔드에서도 `Server: hp-sim`, `Date`, `Content-Type`, `Content-Length` 네 개뿐이다. `X-HP-*`를 포함한 백엔드 헤더는 전달하지 않는다. `server_version = "hp-sim"`, `sys_version = ""`로 둔다.

### 9.2 제어 포트 (백엔드·runner 전용)

| 요청 | 동작 |
|---|---|
| `POST /fork/acquire {conn_id}` | 풀에서 미끼를 확보해 conn_id에 예약. `{"ok": true, "decoy": "decoy-1"}` 또는 `{"ok": false, "reason": "pool_exhausted"}` |
| `POST /fork/restore {conn_id, snapshot, redacted}` | 예약된 미끼의 `/_hp/restore`에 스냅샷 전달. 성공하면 `{"ok": true}`. 실패하면 미끼를 `release`하고 `{"ok": false, "reason": "restore_failed"}` |
| `GET /events` | 9.3절의 이벤트 목록 |
| `GET /pool` | `[{"name": "decoy-1", "state": "available"}, ...]` |
| `POST /shutdown` | 자식을 모두 내리고 종료 |

`acquire`만 성공하고 target이 포크 표식을 돌려주지 않은 경우(restore 실패 등), 프록시는 요청 처리가 끝날 때 예약을 풀고 미끼를 반납한다.

### 9.3 이벤트 로그

요청 하나마다 레코드 하나를 프록시 메모리에 쌓는다. **판정 근거는 이 로그에서만 나온다.** 응답 본문이나 헤더에 넣지 않는다.

```json
{"type": "request", "seq": 2, "conn_id": "c1", "method": "POST", "path": "/heartbeat",
 "handled_by": "decoy", "backend": "decoy-1",
 "forked": true, "fork_result": "ok", "redacted": 4,
 "status": 200, "body_len": 64, "elapsed_ms": 12.3}
```

- `handled_by`: 최종 응답을 만든 쪽. `target` 또는 `decoy`.
- `forked`: 이 요청이 포크를 일으켰는가.
- `fork_result`: `none`(포크 시도 없음), `ok`, `pool_exhausted`, `restore_failed`.
- `redacted`: 포크가 성공했을 때의 치환 개수, 아니면 0.

클라이언트 연결이 끝나면 `finish()`의 정리(미끼 반납 또는 `/_hp/close` 응답 수신)가 **끝난 뒤에** 레코드 하나를 더 쌓는다: `{"type": "close", "seq": N, "conn_id": "c1"}`. runner는 이 레코드로 정리 완료를 확인한다(10.1절 `close`).

## 10. 시나리오와 runner (`runner.py`)

### 10.1 시나리오 파일

```json
{
  "name": "attack",
  "options": {"pool": 2, "redact": "on"},
  "steps": [
    {"conn": "A", "method": "POST", "path": "/heartbeat", "body": {"payload": "hello", "len": 5}},
    {"conn": "A", "method": "POST", "path": "/heartbeat", "body": {"payload": "hi", "len": 64}},
    {"conn": "A", "method": "GET",  "path": "/session"},
    {"conn": "A", "op": "close"}
  ],
  "expect": {
    "unpatched":    [ {...}, {...}, {...} ],
    "patched":      [ {...}, {...}, {...} ],
    "honeypatched": [ {...}, {...}, {...} ]
  }
}
```

- `steps`는 **위에서 아래로 한 번에 하나씩** 실행한다. 스레드를 쓰지 않는다. "동시 연결"은 여러 연결을 열어 둔 채 번갈아 요청하는 것으로 표현한다.
- `conn` 라벨은 처음 등장할 때 `http.client.HTTPConnection`을 새로 연다. 라벨이 등장한 순서대로 `c1`, `c2`, …가 된다. 한 라벨의 요청은 반드시 같은 TCP 연결로 보낸다.
- `op`: `close`(연결을 닫은 뒤, `/events`에 그 연결의 `type: close` 레코드가 나타날 때까지 폴링, 최대 `READY_TIMEOUT`. 다음 step이 "세션이 끝난 뒤의 힙"을 보도록 보장한다), `sleep`(`seconds`), `wait_pool`(모든 미끼가 `available`이 될 때까지 `/pool`을 폴링, 최대 `READY_TIMEOUT`).
- `options`는 기본값이며 명령행 인자가 우선한다.
- `expect[mode]`는 요청 step(=`op`가 없는 step)과 순서대로 짝을 이룬다. 적힌 필드만 비교한다.

| expect 필드 | 비교 대상 |
|---|---|
| `status`, `body`, `body_len` | 클라이언트가 받은 응답. `body`는 ASCII 문자열 |
| `handled_by`, `forked`, `fork_result`, `redacted` | 프록시 이벤트 로그의 `type: request` 레코드 |
| `leaked` | 응답 본문에 들어 있는 **실제 비밀**의 개수 (10.2절) |
| `closed` | `true`면 응답 대신 연결 끊김을 기대 |

### 10.2 실제 비밀 노출 수

runner는 실제 비밀 목록을 스스로 계산한다: H1~H4의 값, 그리고 **다른** 연결의 `session_token`. 응답 본문에 부분 문자열로 들어 있는 것의 개수가 `leaked`다. 자기 토큰은 세지 않는다.

### 10.3 명령과 출력

아래의 `python`은 Windows에서 `py`, macOS에서 `python3`이다(2.2절).

```
python demo.py                                   # 기본 3종 + 12주차 필수 사례, 3 mode
python -m hpsim.cli run scenarios/attack.json [--mode all|unpatched|patched|honeypatched]
                                              [--redact on|off|nofreed] [--pool N] [--json]
python -m hpsim.cli compare results/demo.txt other/demo.txt   # ms 열 제외 비교, SAME 또는 DIFF
```

사람용 출력은 시나리오마다 표 하나다. 열은 고정이다.

```
== attack ==
step mode          status len  handled forked redacted leaked ms    body
2    unpatched     200    64   target  no     0        2      1.9   hillo...........SRVMEM::tok_alice_7f3a9c2e51tok_bob_c41d88e0a7f2
2    patched       400    19   target  no     0        0      1.7   heartbeat rejected\n
2    honeypatched  200    64   decoy   yes    4        0      14.2  hillo...........SRVMEM::tok_a9bd82d091d5d37etok_6d6ecbe54f5f762b
...
RESULT attack: PASS (9/9)
...
ALL PASS
```

본문은 ASCII로 보이고, 출력 불가능한 바이트는 `\xNN`으로 표시한다. `--json`은 같은 내용을 JSON 배열로 낸다.

`demo.py`는 화면 출력과 같은 표를 `results/demo.txt`에, 프록시 이벤트 로그를 포함한 원자료를 `results/demo.json`에 덮어쓴다. 보고서의 전·후 비교표와 증거 로그는 이 두 파일에서 가져온다. `ms` 열 외에는 실행할 때마다 같아야 하므로, 다른 팀원 환경에서 만든 파일과 `ms` 열을 빼고 비교하면 재현 확인이 된다. 모든 기대값이 맞으면 종료 코드 0, 하나라도 틀리면 1이다. `ms` 열은 판정에 쓰지 않는다.

## 11. 검증 사례

기대값의 문자열은 5절의 규칙으로 계산해 확인한 값이다. 그대로 시나리오 파일의 `expect`에 넣는다.

### 11.1 기본 3종 (`demo.py`가 실행)

**normal.json** — 정상. 연결 A: `POST /heartbeat {"payload":"hello","len":3}`

| mode | 기대 |
|---|---|
| 세 mode 모두 | 200, 본문 `hel`, handled_by=target, forked=false, leaked=0 |

**attack.json** — 위반. 연결 A에서 ① `{"payload":"hello","len":5}` ② `{"payload":"hi","len":64}` ③ `GET /session`

| mode | ① | ② | ③ |
|---|---|---|---|
| unpatched | 200 `hello`, target | 200, 64B, target, leaked=2<br>`hillo...........SRVMEM::tok_alice_7f3a9c2e51tok_bob_c41d88e0a7f2` | 200 `{"requests":3,"token":"tok_8aa31bd77f104c99"}`, target |
| patched | 위와 같음 | 400 `heartbeat rejected\n`, target, leaked=0 | 200 `{"requests":2,"token":"tok_8aa31bd77f104c99"}`, target |
| honeypatched | 위와 같음 | 200, 64B, **decoy**, forked=true, fork_result=ok, **redacted=4**, leaked=0<br>`hillo...........SRVMEM::tok_a9bd82d091d5d37etok_6d6ecbe54f5f762b` | 200, 본문이 unpatched와 **완전히 같음**, **decoy**, forked=false |

②가 len=64로 끝나는 지점은 해제 메모리 H3(오프셋 64~83)의 바로 앞이다. 따라서 이 사례는 살아 있는 세션의 비밀 치환만 검증하며, 해제 메모리 치환은 11.2절 `freed_session.json`이 맡는다.

이 사례가 증명하는 것: ②의 앞 16바이트 `hillo...........`는 ①에서 target이 쓴 `hello` 위에 `hi`를 덮은 결과다. 미끼가 이 값을 내려면 target의 세션 버퍼가 복원되어야 한다. ③의 `requests=3`과 자기 토큰도 마찬가지다. 즉 단순 라우팅만으로는 통과할 수 없다.

**boundary.json** — 경계. 연결 A: `POST /heartbeat {"payload":"hello","len":5}` (len이 실제 길이와 같음)

| mode | 기대 |
|---|---|
| 세 mode 모두 | 200, 본문 `hello`, handled_by=target, forked=false, leaked=0 |

**고정 규칙.** 이 세 파일의 `steps`와 `expect`는 11주차 보고서에 적어 낸 값이다. 과제 규칙상 14주차까지 수정할 수 없으므로, 구현이 기대값과 어긋나면 시나리오가 아니라 구현을 고친다.

### 11.2 추가 사례 (`tests/`와 `scenarios/`)

**12주차 필수**로 표시한 사례는 M4 완료 기준에 포함된다. 나머지는 13주차(M6)에 다룬다.

| 파일 | 설정 | 내용 | honeypatched 기대 |
|---|---|---|---|
| `freed_session.json`, `freed_session_nofreed.json` **(12주차 필수)** | 앞 파일은 redact=on, 뒤 파일은 같은 요청에 redact=nofreed | B: `{"payload":"hello","len":3}` → B `close` → A: `{"payload":"hi","len":148}`. B가 먼저 열리므로 B=`c1`, A=`c2` | **on:** A는 200, 148B, decoy, redacted=5, leaked=0. 본문 64~83 = `tok_5beae03b78e5d643`(H3 가짜), 108~127 = `tok_8b6fdefa40886a62`(닫힌 B의 토큰 가짜), 128~147 = `tok_e2276907212c22f0`(A 자기 토큰). **nofreed:** redacted=3, leaked=2 (carol, B의 실제 토큰). unpatched는 200, 148B, target, leaked=5 / patched는 400 |
| `boundary_plus1.json` | 기본 | A: `{"payload":"hello","len":6}` (경계의 반대편, 최소 위반) | 200 `hello.`, decoy, forked=true, redacted=4, leaked=0. unpatched는 200 `hello.`(target), patched는 400 |
| `own_token.json` | 기본 | A: `{"payload":"hi","len":128}` | 200, 128B, redacted=4, leaked=0. 본문 108~127 바이트가 `tok_8aa31bd77f104c99`(자기 토큰은 보존) |
| `overread_clamp.json` | 기본 | A: `len=1000` | 200, 128B (뷰 길이까지만) |
| `multi_attack.json` | 기본 | A: 공격 2회 연속 | 둘 다 decoy. forked는 첫 번째만 true, 두 번째는 fork_result=none |
| `concurrent.json` | 기본 | A 공격 → B 정상(`len=3`) → A `GET /session` → B `GET /session` | B는 끝까지 target, A는 decoy. B의 응답은 patched mode와 같음 |
| `pool_exhaust.json` | pool=1 | A 공격 → B 공격 → A close → wait_pool → C 공격 | A: decoy / B: 400, target, fork_result=pool_exhausted / C: decoy |
| `pool_zero.json` | pool=0 | attack.json과 같은 요청 | 모든 응답이 patched mode와 같음, fork_result=pool_exhausted |
| `redact_off.json` | redact=off | attack.json과 같은 요청 | ②: decoy, redacted=0, **leaked=2** (redaction이 없으면 미끼가 실제 비밀을 흘림) |
| `leak_freed.json` | redact=nofreed | A: `{"payload":"hi","len":84}` | redacted=3, **leaked=1**, 본문 64~83 바이트가 `tok_carol_09be3d71c6`. 같은 요청이 redact=on에서는 leaked=0 |
| `idle_timeout.json` | idle-timeout=0.3 | A 공격 → sleep 0.6 → wait_pool → A 요청 | 마지막 요청은 closed=true, 미끼는 available로 복귀 |
| `bad_input.json` | 기본 | len=-1, len="3", len=true, payload 17바이트, 본문이 JSON 아님, 키 누락 | 세 mode 모두 400 `bad request\n`, forked=false |
| `internal_path.json` | 기본 | `GET /_hp/state` | 세 mode 모두 404 |

### 11.3 구분 불가능성 테스트 (`test_indistinguishable.py`)

attack.json의 각 요청에 대해 unpatched와 honeypatched를 비교한다.

- 상태 코드, `Content-Type`, `Content-Length`, 응답 헤더 **이름 집합**이 같다.
- 응답에 `X-HP`로 시작하는 헤더가 없다.
- 본문 길이가 같고, 다른 바이트는 redaction 대상 레코드가 차지하는 구간에만 있다.
- 포크 전후로 클라이언트 소켓이 같은 객체다(재연결 없음).

## 12. 변수 실험 (14주차)

| 변수 | 값 | 관찰 |
|---|---|---|
| `redact` | on / off / nofreed | attack.json, leak_freed.json의 `leaked` |
| `pool` | 0 / 1 / 2 | 공격 연결 3개를 동시에 열었을 때 decoy로 간 수와 400을 받은 수 |
| 응답 시간 | mode별 | `python -m hpsim.cli bench scenarios/attack.json --n 30` 으로 ② 요청의 중앙값과 표준편차 |

`bench`는 판정 없이 mode별 중앙값 표만 낸다. 논문이 보고한 지연(redaction 약 0.25초)은 CRIU에서 나오므로 이 구현에서는 재현되지 않는다. 대신 포크 경로의 추가 왕복(제어 호출 2회 + 재전송 1회)이 시간 차로 관찰된다. 이 차이를 "공격자가 허니패치를 구분할 수 있는 타이밍 채널"의 근거로 정리한다.

## 13. 알려진 한계 (README와 최종 보고서에 적을 것)

- 요청 처리 도중의 프로세스 이미지를 옮기는 것이 아니라, 요청 경계의 세션 상태를 옮기고 요청을 다시 실행한다.
- 메모리는 레코드 목록으로 추상화되어 있어, 레코드로 등록되지 않은 사본(예: 로그에 남은 토큰)은 모델에 없다.
- 미끼와 target이 같은 호스트의 프로세스라 격리가 없다. 논문의 컨테이너 격리는 대상이 아니다.
- HTTP만 다루며, 프록시가 HTTP를 해석한다(논문의 프록시는 전송 계층).

## 14. 구현 순서와 완료 기준

| 단계 | 주차 | 내용 | 완료 기준 |
|---|---|---|---|
| M1 메모리 | 12 | `config.py`, `memory.py` | `test_memory.py` 통과: 5.2절 기준값, 뷰 오프셋, 5.3절 redaction 기준 사례(해제 메모리 포함) |
| M2 두 mode 흐름 | 12 | `proc.py`, `server.py`의 unpatched·patched, 포크 없는 `proxy.py`, `runner.py` | `test_proc.py` 통과, normal, boundary가 두 mode에서 PASS |
| M3 상태 복원 | 12 | `honeypatch.py`의 체크포인트·스냅샷, `server.py`의 decoy 문맥과 `/_hp/restore`. **프록시와 풀 없이** 검증 | `test_fork.py` 통과 (아래) |
| M4 포크 통합 | 12 | 프록시의 포크 조율(9.1절 3번, 9.2절), 풀은 획득과 단순 반납만(8절) | attack.json이 세 mode에서 PASS, `freed_session.json`, `freed_session_nofreed.json` PASS, 11.3절 테스트 통과 |
| M5 실행 묶음 | 12 | `demo.py`, `report.py`, `results/` 저장, `cli.py compare`, README, `.gitattributes` | 2.3절 절차를 Windows와 macOS에서 각각 수행해 둘 다 `ALL PASS`, 남은 프로세스 없음, 두 `results/demo.txt`가 `SAME` |
| M6 풀·확장 사례 | 13 | 미끼 재생성, 반납 조건 2~4번, 11.2절 나머지 사례 | 11.2절 전부 PASS |
| M7 실험 | 14 | `bench`, 12절 변수 실험 | 12절 표의 관찰값 기록 |

**M3 `test_fork.py`.** 조교 피드백에 따라 풀보다 상태 복원을 먼저 확인하는 단계다. 테스트 안에서 9.2절의 `/fork/acquire`와 `/fork/restore`만 흉내 내는 가짜 제어 서버를 띄운다(acquire는 항상 성공, restore는 받은 스냅샷을 decoy의 `/_hp/restore`로 그대로 전달하고 사본을 테스트에 남김). target(honeypatched, redact=on)과 decoy 하나를 이 가짜 제어 서버에 연결하고, 프록시 없이 `X-HP-Conn: c1`으로 직접 요청한다.

1. target에 ① `{"payload":"hello","len":5}` → 200 `hello`
2. target에 ② `{"payload":"hi","len":64}` → 204, `X-HP-Forked: 1`
3. 남겨 둔 스냅샷 확인: `session.buf`가 `hello...........`(② 적용 전), `session.requests`가 1, H1~H4가 5.2절의 가짜 값(해제된 H3 포함), `S:c1`은 원래 값
4. target의 `/_hp/state`에 `c1` 세션이 없고 `S:c1`이 `freed=True`
5. decoy에 ② 재전송 → 200, 11.1절 honeypatched의 64바이트 본문과 정확히 같음
6. decoy에 `GET /session` → `{"requests":3,"token":"tok_8aa31bd77f104c99"}`

이 테스트가 통과하면 attack.json에서 남는 문제는 프록시의 연결 유지와 라우팅뿐이다.

## 15. 구현자(LLM)를 위한 규칙

1. 이 문서의 상수, 경로, 필드 이름, 응답 본문을 그대로 쓴다. 더 낫다고 생각되는 대안이 있어도 바꾸지 말고 README의 "제안" 항목에 적는다.
2. 충돌이 있으면 우선순위는 **11절 기대값 > 7~9절 동작 규칙 > 나머지** 순이다.
3. 한 단계(M1~M7)를 끝낼 때마다 그 단계의 테스트를 실제로 실행하고, 실패한 채로 다음 단계로 가지 않는다.
4. 기대값을 통과시키려고 시나리오 이름이나 입력값에 따라 분기하는 코드를 넣지 않는다. `scenarios/normal.json`, `attack.json`, `boundary.json`의 기대값은 어떤 경우에도 고치지 않는다(11.1절 고정 규칙).
5. 금지: 고정 포트, `time.sleep`에 의존한 동기화(시나리오의 `sleep` op 제외), 난수, 외부 패키지, 전역 락을 쥔 HTTP 호출, 클라이언트 응답에 내부 정보 노출, 2.1절 표의 규칙 위반.
6. 작성자 OS에서만 실행해 보고 완료로 판단하지 않는다. 2.1절 규칙을 코드 리뷰 체크리스트로 쓴다.
7. 모든 서버 스레드는 데몬으로 두고, 테스트가 끝난 뒤 남은 `python -m hpsim.*` 프로세스가 없어야 한다.

## 부록 A. 12주차 업무 분담

| 담당 | 맡는 파일 | 예상 분량 · 난이도 | 단독 검증 | 구현할 절 (12주차 범위) |
|---|---|---|---|---|
| **A. 메모리·복원** | `config.py`, `memory.py`, `honeypatch.py`, `test_memory.py`, `test_fork.py` | 약 500줄 · 중 | 5.2·5.3절 기준값 일치, `test_fork.py` 6단계 통과 | 4, 5 전체, 7.4~7.5, 14절 M3 |
| **B. 서버·프로세스** | `proc.py`, `server.py`, `pool.py`, `test_proc.py`, `test_modes.py` | 약 550줄 · 중 | `test_proc.py` 통과, 서버 단독 기동 후 `X-HP-Conn`으로 두 mode 응답 확인, 미끼 획득·종료 확인 | 6, 6.1, 7.1~7.3, 7.6, 8 (획득, 종료 후 방치 반납, 반납 조건 1번만) |
| **C. 프록시** | `proxy.py`, `test_indistinguishable.py` | 약 400줄 · 상 | 가짜 백엔드로 연결 유지·라우팅 전환·이벤트 로그 확인, 응답 헤더 4개만 전달 | 9.1~9.3 (타임아웃·502·`/pool` 제외), 11.3 |
| **D. 실행·문서** | `runner.py`, `report.py`, `cli.py`, `demo.py`, `scenarios/` 5개, README, `.gitattributes` | 약 450줄 + 문서 · 중 | 시나리오 `expect`를 명세 값과 대조, 가짜 이벤트 로그로 판정·`compare` 확인 | 10 (`sleep`·`wait_pool` 제외), 11.1, 11.2 중 `freed_session` 2개, 2.2, 13 |

**전원이 읽을 절:** 1, 2(특히 2.1 플랫폼 규칙), 3, 4, 15. 구현은 각자 위 절만 하지만, LLM에는 명세 전체를 주고 "이 중 N절만 구현"이라고 지시한다.

**공동 작업:** 2.3절 두 OS 검증은 Windows 사용자 1명, macOS 사용자 1명이 맡는다. 역할과 상관없이 OS 기준으로 정한다.

**첫날 뼈대.** 각 소유자는 첫날 자기 파일의 공개 API(5.4, 6.1, 7.4, 8.1절)를 시그니처 그대로, 본문은 고정값이나 `NotImplementedError`로 채워 main에 머지한다. 다른 사람은 이 뼈대를 import해 작업을 시작한다. 공개 API를 바꿔야 하면 코드보다 명세를 먼저 고치고 4명에게 알린다.

**순서 의존.** `proc.py`는 B가, `memory.py`는 A가 뼈대 다음으로 가장 먼저 실제 구현을 머지한다. 그 전까지 다른 사람은 뼈대의 시그니처대로 흉내 내는 임시 함수로 작업한다.


# SSS 10조 Honey-patches (honeypatch-sim)

Honey-Patches(Araujo et al., ACM CCS 2014)의 세션 포크 절차를 로컬 프로세스로 모사하는 시뮬레이터입니다. 같은 공격 요청에 대해 미패치(`unpatched`), 일반 패치(`patched`), 허니패치(`honeypatched`) 서버가 어떻게 다르게 반응하는지 보여 줍니다.

구현 명세: [docs/SPEC.md](docs/SPEC.md)

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

확인한 환경: Windows 11 / Python 3.x.x, macOS 26.6 (Apple Silicon) / Python 3.9.6, 3.15.2

## 결과 파일과 두 OS 비교

| 파일 | 내용 |
|---|---|
| `results/demo.txt` | 화면에 나온 비교표 그대로 |
| `results/demo.json` | 프록시 이벤트 로그를 포함한 원자료 |

`ms` 열(응답 시간)을 뺀 나머지는 실행할 때마다 같아야 합니다. 다른 PC에서 만든 결과와 비교하려면:

```
python -m hpsim.cli compare results/demo.txt other/demo.txt
```

같으면 `SAME`, 다르면 `DIFF`와 다른 줄 번호를 출력합니다. (Windows는 `python` 대신 `py`)

## 시나리오 하나만 실행

```
python -m hpsim.cli run scenarios/attack.json [--mode all|unpatched|patched|honeypatched]
                                              [--redact on|off|nofreed] [--pool N] [--json]
```

| 시나리오 | 내용 |
|---|---|
| `normal.json` | 정상 요청. 세 mode 모두 같은 응답 |
| `attack.json` | 과다 읽기 공격. 미패치는 실제 비밀 노출, 패치는 400, 허니패치는 미끼가 가짜 비밀로 응답 |
| `boundary.json` | 길이가 실제 길이와 같은 경계 요청 |
| `freed_session.json` | 해제 메모리(H3, 종료된 세션 토큰)까지 치환되는지 확인 (redact=on) |
| `freed_session_nofreed.json` | 같은 요청을 해제 메모리 제외(redact=nofreed)로 실행한 반례 |

`normal`, `attack`, `boundary`의 입력과 기대값은 11주차 보고서에 낸 고정 사례라 수정하지 않습니다.

## 저장소 구조

```
demo.py            기본 3종 + 12주차 필수 사례 x mode 3개 실행, 비교표 출력·저장
hpsim/
  config.py        상수
  proc.py          자식 프로세스 기동·종료 공용 함수
  memory.py        힙 레코드, 세션, redaction, 스냅샷 변환
  honeypatch.py    hp_init, hp_fork, hp_skip, checkpoint, restore
  server.py        백엔드 서버(target/decoy)
  pool.py          미끼 풀
  proxy.py         리버스 프록시 + 포크 조율
  runner.py        시나리오 실행, 기대값 대조
  report.py        표·JSON 출력
  cli.py           run, compare
scenarios/         검증 사례 JSON
tests/             pytest 테스트
results/           demo.py 실행 결과
docs/SPEC.md       구현 명세
```

## 알려진 한계

- 요청 처리 도중의 프로세스 이미지를 옮기는 것이 아니라, 요청 경계의 세션 상태를 옮기고 요청을 다시 실행한다.
- 메모리는 레코드 목록으로 추상화되어 있어, 레코드로 등록되지 않은 사본(예: 로그에 남은 토큰)은 모델에 없다.
- 미끼와 target이 같은 호스트의 프로세스라 격리가 없다. 논문의 컨테이너 격리는 대상이 아니다.
- HTTP만 다루며, 프록시가 HTTP를 해석한다(논문의 프록시는 전송 계층).

## 제안

명세와 다르게 하는 편이 낫다고 생각되는 점은 코드에 반영하지 않고 여기에 적습니다(명세 15절 1번).

- **MAX_BODY 초과 시 연결 닫기 (proxy).** 9.1절은 본문이 `MAX_BODY`를 넘으면 `400 bad request\n`만 정해 두었다. 프록시는 넘친 본문을 읽지 않으므로, 연결을 유지하면 남은 바이트가 다음 요청으로 해석된다. 그래서 400을 보낸 뒤 연결도 닫는다. `Connection: close` 헤더는 보내지 않는다(9.1절 헤더 4개 규칙). 명세에 이 동작을 명시하자고 제안한다.
- **프록시가 직접 만든 응답의 `handled_by` (proxy).** 9.3절은 `handled_by`를 `target`/`decoy`로만 정한다. `/_hp/` 경로의 404와 MAX_BODY 초과의 400은 백엔드를 거치지 않으므로 이벤트에 `handled_by: "proxy"`, `backend: "proxy"`로 적는다. 명세에 이 값을 추가하자고 제안한다.
- **백엔드 호출 실패 (proxy, M4 한정).** 502 응답은 13주차(M6) 범위라, M4에서는 백엔드 호출이 실패하면 응답 없이 연결만 닫고 `status: null` 이벤트를 남긴다. M6에서 `502 bad gateway\n`로 바꾼다.

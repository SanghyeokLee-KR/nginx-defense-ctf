# scripts/ · 방어 스택 구성요소

> **NginX 살려라 A/D CTF · 교육용·방어 전용.** 모든 자동복구·모니터링 기법은
> 권한이 부여된 경기 박스 안에서 우리 팀 nginx 가용성을 유지하기 위한 것입니다.
> 공인 IP·webhook·실명은 마스킹(`X.X.X.X`, `<REDACTED_WEBHOOK_URL>`)되어 있습니다.

```
scripts/
├── bin/       복구·감시·헬스체크·알림 스크립트 (16)
├── systemd/   서비스/타이머 유닛 (서비스명 추상화)
├── cron/      1분 주기 독립 복구·수집 라인
├── audit/     auditd 룰 (사람 명령만 기록)
└── config/    nginx 기본 사이트 설정 · ip_names 예시
```

## 다중 자동복구 매핑

서로 다른 메커니즘이 nginx 복구를 다중화합니다. 한 라인을 끊어도 다른 라인이 복구를 시도하지만, **root가 이들을 한 번에 제거하면 무너집니다**. 보안 경계가 아니라 복구 확률·속도를 높이는 다중화입니다.

| 계층 | 메커니즘 | 스크립트 / 유닛 | 주기 |
|---|---|---|---|
| ① | systemd `Restart=always` (StartLimit `[Unit]` 60s/20회) | `systemd/nginx-override.conf` | 2초 |
| ② | watchdog A·B 상호 복구 | `bin/nginx-watchdog.sh` ← `nginx-wd-{a,b}` | 5초 |
| ③ | cron fallback | `bin/nginx-cron-guard.sh` | 1분 |
| ④ | 워치독 보장기 | `bin/sys-integrity.sh` | 10초 |
| ⑤ | 독립 모니터 | `bin/kworker-mon.sh` (+ `bin/kworker-guard.sh`) | 3초 |

재기동을 여러 계층이 동시에 시도하므로 `flock /run/nginx-defense.lock`으로 **직렬화합니다.** 정상 판정 기준(NEEDLE)은 watchdog·cron·healthz 가 `<h1>NginX를 살려라</h1>`로 통일했습니다.

**`chattr +i`:** `index.html` · `nginx.conf` · `sites-available/default` · nginx 바이너리에 immutable. **root를 막는 게 아니라**(root는 `chattr -i`로 푼다) 우발·비root·단순 변조 방지와 공격 지연용입니다.

## 서비스명 추상화 · systemd 서비스 이름

방어 서비스의 `Description=`·서비스명을 일반적인 모니터처럼 추상화해 **단순 탐색 비용을 늘립니다.** 이는 **실무 보안 기법이 아니며 보안 경계도 아닙니다**. `systemctl list-units`·`ls -l /proc/<pid>/exe`로는 그대로 드러납니다.

| 유닛 | 표시명(Description) | 실제 역할 |
|---|---|---|
| `nginx-wd-a` / `nginx-wd-b` | System Resource Monitor A/B | nginx 워치독 (상호 복구) |
| `net-filter-mon` | Network Filter Monitor | 80포트 방화벽 가드 (`fw-guard`) |
| `net-status-mon` | Network Status Monitor | nginx 다운/복구 알림 |
| `content-mon` | Content Integrity Monitor | index 변조 감지 알림 (`tamper-alert`) |
| `svc-health` | Service Health Monitor | `systemctl mask` 대응 (`unmask-guard`) |
| `kworker-mon` | Kernel Worker Monitor | 독립 복구 모니터 |
| `sys-integrity` | System Integrity Monitor | 워치독 enable 보장기 |
| `healthz-mon` | Health Probe Monitor | 헬스체크 자가격리 |
| `cmdmon` | Command Collector | 공격자 명령 수집 |
| `sysmon` | System Monitor Collector | 종합 상태 수집 |

추가로 `kworker-mon.sh`·`fw-guard.sh` 등은 dotfile·커널 스레드(`kworker`) 유사 이름으로 배치해 단순 탐색을 지연시킵니다(역시 보안 경계가 아닙니다).

## cron · audit · config

- **`cron/root.crontab`**: systemd와 독립된 1분 복구 라인 + 핵심 서비스 부활. (파일 상단 주석 참고)
- **`audit/attacker.rules`**: `auid>=1000`(사람)의 `execve`만 기록 → `cmd-collect.sh`가 파싱. 이 필터가 빠지면 데몬 명령 노이즈에 묻힙니다. 룰 끝에 **`-e 2`** 로 불변화해 root의 `auditctl -D` 삭제는 막았습니다. 단, **root 직접 로그인(auid=0)은 누락**되고 auditd 데몬 자체의 stop은 여전히 가능합니다.
- **`config/nginx-site-default.conf`**: nginx 기본 사이트 설정. `config/ip_names.example` · IP↔이름 매핑 형식 예시(실파일은 비공개).

## 배포 메모

- `bin/*` → `/usr/local/bin/` (일부는 dotfile: `.kworker-mon.sh`, `.fw-guard.sh`, `.healthz-checker.sh`, `.tamper-alert.sh`, `.unmask-guard.sh`, `.kworker-guard.sh`)
- `systemd/*` → `/etc/systemd/system/` · `audit/attacker.rules` → `/etc/audit/rules.d/`
- `cmd-collect.sh`는 **gawk** 필요(mawk 비호환). `cmds.json`·`sysmon.json`은 **데모용 웹루트 노출** · 실무에서는 인증 뒤에 두거나 외부 수집기로.
- 실제 `ip_names`는 개인정보라 저장소에서 제외 · `config/ip_names.example` 형식만 참고

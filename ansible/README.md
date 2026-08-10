# ansible/ · 방어 스택 배포 (IaC)

수작업 `cp` 로 배포하던 방어 스택(스크립트 · systemd 유닛 · cron · auditd 룰)을 Ansible로 코드화해 **재현 가능한 멱등 배포**를 제공합니다.

> 교육용·방어 전용. 실서비스라면 인스턴스 내부 배포보다 **ASG 교체형**이 적절합니다([README 한계·실무 확장](../README.md#7--한계와-개선점) 참고). 이 플레이북은 CTF 제약(고정 박스) 안에서의 재현성 확보가 목적입니다.

## 사용

```bash
cp inventory.example.ini inventory.ini      # 호스트 IP·키 채우기
ansible-playbook -i inventory.ini playbook.yml
```

## 배포 내용

| 단계 | 대상 |
|---|---|
| 의존 패키지 | `gawk`(cmd-collect 필수) · `auditd` · `curl` |
| 스크립트 | `scripts/bin/*.sh` → `/usr/local/bin/` (일부는 `.name.sh` 점파일 · 단순 탐색 비용↑, **보안 경계 아님**) |
| systemd | `scripts/systemd/*` → `/etc/systemd/system/` + nginx override(`StartLimit`은 `[Unit]`) + `daemon-reload` + enable/start |
| auditd | `scripts/audit/attacker.rules` → `/etc/audit/rules.d/` + `augenrules --load` (`-e 2` 불변화 포함) |
| cron | `scripts/cron/root.crontab` → `/etc/nginx-defense/root.crontab` + `crontab` 설치 |
| config 예시 | `scripts/config/nginx-defense.example/{webroot,index.html}` → `/etc/nginx-defense/` (`force: false` · 실제 값이 있으면 보존) |

## 별도 제공 (마스킹된 실제 값)

`/etc/nginx-defense/` 의 아래 값은 환경/개인정보라 플레이북이 채우지 않습니다. `force: false`로 예시만 두고, 실제 값은 직접 배치합니다.

- `index.html` · 보호 대상 원본 (NEEDLE `<h1>NginX를 살려라</h1>` 포함)
- `webroot` · 웹루트 경로 (예: `/var/www/html`)
- `ip_names` · IP↔이름 매핑 (개인정보 · 저장소 제외 · [`scripts/config/ip_names.example`](../scripts/config/ip_names.example) 형식)
- webhook URL · 알림 스크립트가 읽는 값 (`<REDACTED_WEBHOOK_URL>`)

## 한계

- 멱등 배포까지만. **인스턴스 자체의 자동 교체·확장은 다루지 않습니다**. 실무라면 Terraform(ASG/Launch Template/Multi-AZ) + 이 플레이북(또는 user-data)의 조합으로 갑니다.
- systemd 유닛 하드닝(`ProtectSystem` 등)은 적용하지 않았습니다(복구 데몬이 root·`systemctl`·일부 `sudo`를 필요로 해 호환성 검증이 필요 · 향후 과제).

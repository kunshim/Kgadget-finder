# kgadget-finder
## 준비물
qemu를 대상으로 하여 리눅스 커널 가젯이 실행가능한지 테스트 하여 커널 익스플로잇을 도와주는 도구입니다. \
**root 권한**으로 설치된 파이썬 pwndbg(.gdbinit 설정 필요), pwntools, termcolor 모듈이 필요합니다. \
또한 테스트를 위해서 nokaslr 옵션과 guest os의 root 권한이 설정되있어야 하며, 하나의 모듈이 로딩 되어있다고 가정합니다. \
마지막으로 ROPgadget 을 사용하여 추출한 가젯 정보 파일이 필요합니다. 아직 베타인 관계로 많은 준비가 필요합니다. 
## 실행방법
`sudo python3 kgadget_finder.py <가젯정보 파일> <커널 오브젝트 파일> <qemu 부팅 스크립트>` \
정상적으로 실행이 될 경우, result.txt 파일로 실행가능한 가젯이 저장됩니다. 
## 왜 root 권한이 필요한가요?
실행 과정에서 qemu 의 /dev/mem 파일에 쓰기위한 권한이 필요하기 때문입니다. 
## 실행과정
간략하게 요약하자면 다음과 같습니다. 자세한 내용은 소스코드를 보시는 것을 추천드립니다. 
1. 필요 파일 체크
2. qemu 부트 스크립트 수정을 통해서 named pipe 통신
3. lsmod 를 통해서 해당 os 의 모듈 베이스를 구한 후 gdb로 모듈 바이트 코드 추출
4. modprobe_path 추출하여 쓰기 가능한 메모리 영역 확보. 해당 영역은 호스트와 게스트의 통신에 사용
5. 해당 모듈 바이트 코드를 qemu 메모리 서칭을 통해 검색 후, 가젯 체킹 코드 주입
6. gdb 를 통해서 rip 를 인젝션한 코드 주소로 변경
7. 추출 \

가젯 체킹 코드는 CR3 레지스터를 통해서 페이징 관련 구조체에 NX 비트가 설정되있는지를 검사합니다. 

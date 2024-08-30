# ARP-Spoofing

## How to use
`sudo ./arp-spoof <interface> <sender ip 1> <target ip 1> <sender ip 2> <target ip 2>`
`sudo ./arp-spoof eth0 192.168.0.5 192.168.0.6 192.168.0.6 192.168.0.5`

</br>

## Attack-Flow

* Mac주소 뒷자리 3바이트 생략


> Sender와 Target의 ARP 테이블이 모두 Attacker의 Mac주소로 감염이 되어 있는 상태이다.
> Attacker는 Ip패킷을 Sniffing 후 목적지로 다시 Relaying 한다.  
> 여러 Case별로 Sender와 Target의 ARP 테이블을 계속해서 감염시킨다.

</br>

## Demonstration
| **Host**    | **IP Address**  | **MAC Address** |
|-------------|-----------------|-----------------|
| Sender      | 192.168.0.108   | 60-DD-8E        |
| Attacker    | 192.168.0.107   | 58-1C-F8        |
| Target      | 192.168.0.105   | C8-3A-35        |

> Sender(192.168.0.108)이 Target(192.168.0.105)로 ICMP 패킷을 보내는 상황

### 1) Sender

> Sender의 ARP 테이블은 Attacker의 Mac주소(58-1C-F8)로 감염이 되어 있는 상태이다.
> 이때 Ping 명령어로 ICMP 패킷을 Target(192.168.0.105)로 보낸다.

### 2) Attacker

> 가) Sender의 ARP 테이블이 감염된 상태이기에 Attacker는 Sender의 ICMP 패킷(Request)을 Sniffing 한다.(Destination Mac = Attacker Mac)

> 나) Attacker는 받은 ICMP 패킷(Request)의 Source Mac은 자신의 Mac주소로, Destination Mac은 Target의 Mac주소로 바꿔서 Relay한다.

> 다) Target의 ARP 테이블이 감염된 상태이기에 Attacker는 Target의 ICMP 패킷(Reply)을 Sniffing 한다.(Destination Mac = Attacker Mac)

> 라) Attacker는 받은 ICMP 패킷(Reply)의 Source Mac은 자신의 Mac주소로, Destination Mac은 Sender의 Mac주소로 바꿔서 Relay한다.


### 3) Target

> 가) Attacker가 Relay한 ICMP 패킷(Request)을 수신한다.(Source Mac = Attacker Mac & Destination Mac = Target Mac)

> 나) Target의 ARP 테이블도 감염된 상태이기에 ICMP 패킷(Reply)을 Attacker에게 보낸다.(Destination Mac = Attacker Mac)

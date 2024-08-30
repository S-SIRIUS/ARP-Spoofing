# ARP-Spoofing

## How to use
`sudo ./arp-spoof <interface> <sender ip 1> <target ip 1> <sender ip 2> <target ip 2>`

`sudo ./arp-spoof eth0 192.168.0.5 192.168.0.6 192.168.0.6 192.168.0.5`

</br>

## Attack-Flow

* Mac주소 뒷자리 3바이트는 생략

![ARP-Spoofing](https://github.com/user-attachments/assets/91600056-4b06-4b17-9561-0b4f28745879)



> Sender와 Target의 ARP 테이블이 모두 Attacker의 Mac주소로 감염이 되어 있는 상태이다.

> Attacker는 Ip패킷을 Sniffing 후 목적지로 다시 Relaying 한다.  

> 여러 Case별로 Sender와 Target의 ARP 테이블을 계속해서 감염시킨다.

</br>

## Demonstration
| **Host**    | **IP Address**  | **MAC Address** |
|-------------|-----------------|-----------------|
| Sender      | 192.168.0.108   | 0C-54-15        |
| Attacker    | 192.168.0.107   | 58-1C-F8        |
| Target      | 192.168.0.105   | 60-DD-8E        |

> Sender(192.168.0.108)이 Target(192.168.0.105)로 ICMP 패킷을 보내는 상황

</br>

### 1) Sender

![Sender PNG](https://github.com/user-attachments/assets/e1a62e2b-a7ca-45b9-bdbb-2b301b882ba2)

> Sender의 ARP 테이블은 Attacker의 Mac주소(58-1C-F8)로 감염이 되어 있는 상태이다.
> 
> 이때 Ping 명령어로 ICMP 패킷을 Target(192.168.0.105)로 보낸다.

### 2) Attacker

#### 가) Sender의 ICMP(Request) 패킷을 Sniffing
![attacker1](https://github.com/user-attachments/assets/4de52569-9e01-418e-9684-dbf5a4f24bfe)

> Sender의 ARP 테이블이 감염된 상태이기에 Attacker는 Sender의 ICMP 패킷(Request)을 Sniffing 한다.(Destination Mac = Attacker Mac)

#### 나) Sniffing한 ICMP(Request) 패킷을 Relaying
![attacker2](https://github.com/user-attachments/assets/8570c72c-b849-4124-af26-0040bdacba25)

> Attacker는 탈취한 ICMP 패킷(Request)의 Source Mac은 자신의 Mac주소로, Destination Mac은 Target의 Mac주소로 바꿔서 Relaying 한다.

#### 다) Target의 ICMP(Reply) 패킷을 Sniffing
![attacker3](https://github.com/user-attachments/assets/1dc447aa-1712-4c26-bc15-06d7bc7e7e55)

> Target의 ARP 테이블이 감염된 상태이기에 Attacker는 Target의 ICMP 패킷(Reply)을 Sniffing 한다.(Destination Mac = Attacker Mac)

#### 라) Sniffing한 ICMP(Reply) 패킷을 Relaying
![attacker4](https://github.com/user-attachments/assets/a03d12d5-1a2c-436e-8d86-659c0e0102cd)

> Attacker는 탈취한 ICMP 패킷(Reply)의 Source Mac은 자신의 Mac주소로, Destination Mac은 Sender의 Mac주소로 바꿔서 Relaying 한다.


### 3) Target

#### 가) Attcker가 Relay한 ICMP 패킷(Request)을 수신
![target1](https://github.com/user-attachments/assets/d1bb496d-e915-4913-87eb-c0da59f9b760)

> Attacker가 Relay한 ICMP 패킷(Request)을 수신한다.(Source Mac = Attacker Mac & Destination Mac = Target Mac)

#### 나) ICMP 패킷(Reply)을 Attacker에게 전송
![target2](https://github.com/user-attachments/assets/875ae8d4-f14f-4b75-9b54-23e12b313e68)

> Target의 ARP 테이블도 감염된 상태이기에 ICMP 패킷(Reply)을 Attacker에게 전송한다.(Destination Mac = Attacker Mac)

import socket
import os
import time
import pandas as pd
import random
from queue import Queue


# 네트워크 계층 설정
SWITCH_MAC_TABLE = {
    "000b.beba.22ed": "FA0/1",
    "0090.0c49.230": "FA0/2"
}

# 라우터 (L3, 동적 라우팅 RIP 프로토콜)
class Router:
    def __init__(self, name, ip, networks):
        self.name = name
        self.ip = ip  # 각 라우터의 IP 주소
        self.networks = networks  # 직접 연결된 네트워크
        self.routing_table = {}  # 라우팅 테이블 (목적지 -> {next_hop, cost})
        self.initialize_routing_table()

    def initialize_routing_table(self):
        """초기 라우팅 테이블 설정 (자신의 네트워크만 포함)"""
        self.routing_table = {}  # 기존 테이블 초기화
        for network in self.networks:
            self.routing_table[network] = {"next_hop": self.name, "cost": 0}

    def route_packet(self, dest_ip):
        """패킷 전달"""
        # 목적지 IP가 속하는 네트워크를 확인
        for network, info in self.routing_table.items():
            if dest_ip.startswith(network.split('/')[0]):
                next_hop = info["next_hop"]
                cost = info["cost"]
                return f"{self.name}에서 {dest_ip}로 패킷 전달: Next Hop = {next_hop}, Cost = {cost}"
        return f"{dest_ip}는 {self.name}에서 도달 불가"


    def receive_rip_update(self, sender_name, sender_routing_table):
        """
        다른 라우터의 라우팅 테이블을 수신하여 업데이트.
        """
        updated = False
        for dest, info in sender_routing_table.items():
            new_cost = info["cost"] + 1  # 전송 라우터로부터의 비용 추가
            if dest not in self.routing_table or self.routing_table[dest]["cost"] > new_cost:
                self.routing_table[dest] = {"next_hop": sender_name, "cost": new_cost}
                updated = True
        return updated

    def send_rip_update(self, other_router):
        """
        RIP 업데이트 전송. 다른 라우터에 라우팅 테이블 제공.
        """
        updated = other_router.receive_rip_update(self.name, self.routing_table)
        if updated:
            print(f"{self.name} → {other_router.name}: 라우팅 테이블 업데이트됨.")

    def display_routing_table(self):
        """라우팅 테이블 출력"""
        print(f"\nRouter {self.name} Routing Table:")
        for dest, info in self.routing_table.items():
            print(f"  Destination: {dest}, Next Hop: {info['next_hop']}, Cost: {info['cost']}")




# 서버 정보 및 로드밸런싱
SERVER_POOL = [  # 사용 가능한 서버 목록과 각 서버의 IP와 포트를 정의
    ('127.0.0.1', 6666),
    ('127.0.0.1', 7777),
    ('127.0.0.1', 8888),
    ('127.0.0.1', 9999)
]

# 트래픽 패턴 정의
def constant_traffic():
    """트래픽 패턴 정의: 일정한 간격(0.01초)으로 트래픽을 생성."""
    return 0.01

TRAFFIC_PATTERNS = {"constant": constant_traffic}  # 트래픽 패턴을 선택할 수 있도록 정의

# 스위치 동작 (L2 계층)
def switch_packet(mac_address):
    """
    MAC 주소를 기반으로 포트를 결정.
    """
    return SWITCH_MAC_TABLE.get(mac_address, "Unknown Port")  # MAC 주소를 기반으로 포트를 반환

# 라우터 동작 (L3 계층)
def route_packet(dest_ip):
    """
    목적지 IP 주소를 기반으로 라우팅 테이블에서 Next Hop 결정.
    """
    return ROUTER_TABLE.get(dest_ip, "Unknown Route")  # 목적지 IP를 기반으로 Next Hop 반환


# 서버 요청 제한 설정
MAX_REQUESTS_PER_SERVER = 210  # 각 서버당 최대 요청 수


# 로드밸런싱 동작 (L4 계층) 수정
def load_balance_with_limit(algorithm, request_counts, SERVER_POOL, index, request_number):
    """
    서버에 전송할 수 있는 요청 수를 제한하는 로드밸런싱
    """
    if algorithm == "round robin":
        for _ in range(len(SERVER_POOL)):
            server = SERVER_POOL[index % len(SERVER_POOL)]
            if request_counts[f"{server[0]}:{server[1]}"] < MAX_REQUESTS_PER_SERVER:
                return server
            index += 1  # 다음 서버로 이동
        # print(f"서버 과부하: 모든 서버가 요청 제한에 도달하여 요청 {request_number} 전송 불가.")
        raise ValueError("모든 서버가 요청 제한에 도달했습니다.")
    elif algorithm == "no load balancing":
        server = SERVER_POOL[0]
        if request_counts[f"{server[0]}:{server[1]}"] < MAX_REQUESTS_PER_SERVER:
            return server
        print(f"서버 과부하: 10.1.2.2:{server[1]}가 요청 제한에 도달하여 요청 {request_number} 전송 불가.")
        raise ValueError("첫 번째 서버가 요청 제한에 도달했습니다.")
    else:
        raise ValueError("지원되지 않는 알고리즘")





# 요청 전송 함수
def send_request(server_ip, server_port):
    """
    서버로 요청을 전송하고 응답 시간을 측정.
    """
    try:
        start_time = time.time()  # 요청 시작 시간 기록
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((server_ip, server_port))  # 서버에 연결
            client_socket.sendall(b"Test Request")  # 요청 데이터를 전송
            client_socket.recv(4096)  # 서버 응답 데이터 수신
        end_time = time.time()  # 요청 종료 시간 기록
        return end_time - start_time  # 응답 시간 반환
    except Exception as e:
        print(f"에러 발생: {e}")
        return None

# 고정된 요청 시퀀스 생성
def generate_fixed_request_sequence(num_requests, router1, router2):
    """
    고정된 요청 시퀀스를 생성하여 알고리즘 간 동일한 요청을 처리하도록 보장.
    """
    mac_addresses = list(SWITCH_MAC_TABLE.keys())  # MAC 주소 목록

    # 두 라우터의 목적지 IP 주소를 합쳐서 사용
    ip_addresses = list(router1.routing_table.keys()) + list(router2.routing_table.keys())

    # 고정된 요청 시퀀스를 생성
    request_sequence = [
        (random.choice(mac_addresses), random.choice(ip_addresses))
        for _ in range(num_requests)
    ]
    return request_sequence




def simulate_traffic_flow_with_dynamic_routing(algorithm, traffic_pattern, request_sequence, router1, router2):
    traffic_func = TRAFFIC_PATTERNS[traffic_pattern]
    request_counts = {f"{ip}:{port}": 0 for ip, port in SERVER_POOL}
    response_times = []
    failed_requests = 0  # 전송되지 않은 요청 수를 기록
    unreachable_requests = 0  # 도달하지 못한 요청 수를 기록
    traffic_log = []  # 로그 기록 리스트

    output_dir = "./Network_Results"
    os.makedirs(output_dir, exist_ok=True)
    log_file = f"{output_dir}/{traffic_pattern}_{algorithm}_dynamic.txt"
    with open(log_file, "w") as log:
        log.write(f"네트워크 시뮬레이션 시작: {algorithm}, {traffic_pattern} (동적 라우팅 포함)\n\n")

    # 라우터 초기화 및 초기 RIP 업데이트
    print("라우터 초기화 중...")
    router1.initialize_routing_table()
    router2.initialize_routing_table()
    print("\n--- 초기 라우팅 테이블 ---")
    router1.display_routing_table()
    router2.display_routing_table()

    for i, (mac_address, dest_ip) in enumerate(request_sequence):

        # RIP 업데이트 주기 설정
        if (i + 1) % 5 == 0:
            router1.send_rip_update(router2)
            router2.send_rip_update(router1)

        time.sleep(traffic_func())

        # 스위치 및 MAC 주소 확인
        port = switch_packet(mac_address)
        if port == "Unknown Port":
            log_message = f"요청 {i + 1}: MAC={mac_address} → Port=알 수 없음"
            print(log_message)
            traffic_log.append(log_message)
            unreachable_requests += 1  # 도달하지 못한 요청 수 증가
            continue

        # 동적 라우팅 처리
        try:
            next_hop_info = router1.route_packet(dest_ip)
            if "도달 불가" in next_hop_info:
                log_message = f"요청 {i + 1}: MAC={mac_address} → Port={port}, IP=10.1.2.2 → {next_hop_info}"
                print(log_message)
                traffic_log.append(log_message)
                unreachable_requests += 1  # 도달하지 못한 요청 수 증가
                continue
        except Exception as e:
            log_message = f"요청 {i + 1}: MAC={mac_address} → Port={port}, IP={dest_ip} → 라우팅 실패: {e}"
            traffic_log.append(log_message)
            unreachable_requests += 1  # 도달하지 못한 요청 수 증가
            continue

        # 서버 선택 및 로드 밸런싱
        try:
            server_ip, server_port = load_balance_with_limit(algorithm, request_counts, SERVER_POOL, i, i + 1)
        except ValueError as e:
            log_message = f"요청 {i + 1}: MAC={mac_address} → Port={port}, IP={dest_ip} → 서버 요청 실패: {e}"
            traffic_log.append(log_message)
            failed_requests += 1
            continue
        # 서버 선택 및 로드 밸런싱


        # 요청 전송 및 응답 시간 측정
        response_time = send_request(server_ip, server_port)
        if response_time:
            request_counts[f"{server_ip}:{server_port}"] += 1
            response_times.append(response_time)
            log_message = (
                f"요청 {i + 1}: MAC={mac_address} → Port={port}, IP=10.1.2.2 → {next_hop_info}, "
                f"서버=10.1.2.2:{server_port}, 응답 시간={response_time:.4f}초"
            )

            traffic_log.append(log_message)
            
    # 모든 로그를 파일에 저장
    with open(log_file, "a") as log:
        log.write("\n".join(traffic_log))
        log.write("\n")
    print(f"{algorithm} 방식, {traffic_pattern} 트래픽 시뮬레이션 완료 (동적 라우팅 포함)")

    # 요청 처리 종료 후 라우팅 테이블 출력
    print(f"\n--- {algorithm}, {traffic_pattern} 최종 라우팅 테이블 ---")
    router1.display_routing_table()
    router2.display_routing_table()

    return request_counts, response_times, failed_requests, unreachable_requests




def process_request_with_queue(server_ip, server_port):
    queue = SERVER_QUEUE[f"{server_ip}:{server_port}"]
    if queue.full():
        print(f"서버 {server_ip}:{server_port}의 요청 큐가 가득 찼습니다. 요청이 거부되었습니다.")
        return None
    else:
        start_time = time.time()
        queue.put("요청 처리 중")
        # 요청 처리 로직
        time.sleep(random.uniform(0.01, 0.1))  # 처리 시간 시뮬레이션
        queue.get()  # 처리 완료 후 큐에서 제거
        return time.time() - start_time


# 결과 저장
def save_results_to_excel(results):
    """
    엑셀 파일에 요약 결과를 저장:
    Algorithm | Total Requests | Failed Requests | Unreachable Requests | Total Response Time | Max Response Time | Server 1 Requests | ...
    """
    summary_data = []  # 요약 데이터를 저장할 리스트

    for result in results:
        algorithm = result["algorithm"]  # 알고리즘 이름
        data = result["data"]  # 서버별 요청 데이터
        response_times = result["response_times"]  # 응답 시간 리스트
        failed_requests = result["failed_requests"]  # 전송되지 않은 요청 수
        unreachable_requests = result["unreachable_requests"]  # 도달하지 못한 요청 수

        # 요약 데이터 생성
        total_requests = sum(data.values())  # 총 요청 수 계산
        total_response_time = round(sum(response_times), 4) if response_times else 0  # 총 응답 시간 계산
        max_response_time = round(max(response_times), 4) if response_times else 0
        server_requests = [data.get(f"{ip}:{port}", 0) for ip, port in SERVER_POOL]  # 각 서버 요청 수 계산

        summary_row = {
            "Algorithm": algorithm,
            "Total Requests": total_requests,
            "Failed Requests": failed_requests,
            "Unreachable Requests": unreachable_requests,
            "Total Response Time": total_response_time,
            "Max Response Time": max_response_time,
            **{f"Server {i+1}": count for i, count in enumerate(server_requests)}
        }
        summary_data.append(summary_row)

    # 데이터프레임 생성
    summary_df = pd.DataFrame(summary_data, columns=[
        "Algorithm", "Total Requests", "Failed Requests", "Unreachable Requests",
        "Total Response Time", "Max Response Time",
        "Server 1", "Server 2", "Server 3", "Server 4"
    ])

    # 엑셀로 저장
    summary_file = "network_simulation_results.xlsx"
    summary_df.to_excel(summary_file, index=False)
    print(f"결과가 '{summary_file}'에 저장되었습니다.")


# 고정된 요청 시퀀스 생성
def generate_fixed_request_sequence(num_requests, fixed_mac_address, fixed_dest_ip):
    """
    고정된 요청 시퀀스를 생성하여 동일한 MAC 주소와 목적지 IP를 사용.
    """
    return [(fixed_mac_address, fixed_dest_ip) for _ in range(num_requests)]

# 메인 실행
if __name__ == "__main__":
    # 라우터 초기화                                                                                                                                              
    router1 = Router("Router1", "10.1.10.1", ["10.1.10.0/24", "10.1.1.0/24"])
    router2 = Router("Router2", "10.1.10.2", ["10.1.10.0/24", "10.1.2.0/24"])

    # 초기 라우팅 테이블 출력
    print("\n--- 초기 라우팅 테이블 ---")
    router1.display_routing_table()
    router2.display_routing_table()

    # 알고리즘 실행 및 결과 저장
    results = []
    num_requests = 230
    fixed_mac_address = "0090.0c49.230"
    fixed_dest_ip = "10.1.2.0"
    fixed_request_sequence = generate_fixed_request_sequence(num_requests, fixed_mac_address, fixed_dest_ip)

    for algorithm in ["round robin", "no load balancing"]:
        for traffic_pattern in ["constant"]:
            print(f"\n--- {algorithm}, {traffic_pattern} 시뮬레이션 시작 ---")
            request_counts, response_times, failed_requests, unreachable_requests = simulate_traffic_flow_with_dynamic_routing(
                algorithm, traffic_pattern, fixed_request_sequence, router1, router2
            )
            results.append({
                "algorithm": algorithm,
                "data": request_counts,
                "response_times": response_times,
                "failed_requests": failed_requests,
                "unreachable_requests": unreachable_requests  # 도달하지 못한 요청 수 추가
            })

    # 최종 결과를 엑셀 파일로 저장
    save_results_to_excel(results)

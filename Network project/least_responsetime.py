def get_server(response_times, request_counts, cpu_loads, SERVER_POOL):
    """최소 응답 시간 + CPU 부하(Least Response Time with CPU Load) 방식으로 서버 선택"""
    least_response_time_server = min(SERVER_POOL, key=lambda server: (
        response_times.get(f"{server[0]}:{server[1]}", float('inf')) +  # 응답 시간 고려
        request_counts.get(f"{server[0]}:{server[1]}", 0) +             # 요청 수 고려
        cpu_loads.get(f"{server[0]}:{server[1]}", 0)                     # CPU 부하 고려
    ))
    
    server_ip, server_port = least_response_time_server
    return server_ip, server_port

# RoundRobin.py

def get_server(request_counts, SERVER_POOL, num_requests):
    """Round Robin 방식으로 서버 선택"""
    # Round Robin 방식은 요청 수와 상관없이 순차적으로 서버를 선택
    server_ip, server_port = SERVER_POOL[num_requests % len(SERVER_POOL)]
    return server_ip, server_port

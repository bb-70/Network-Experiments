# Least_Connection.py

def get_server(request_counts, SERVER_POOL):
    """Least Connection 방식으로 서버 선택"""
    least_connected_server = min(request_counts, key=request_counts.get)
    server_ip, server_port = least_connected_server.split(":")
    return server_ip, int(server_port)

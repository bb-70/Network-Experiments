import socket

def run_server(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', port))
        s.listen()
        print(f"서버 실행 중: 127.0.0.1:{port}")
        
        while True:
            conn, addr = s.accept()
            print(f"서버 연결됨: {addr}")
            
            data = conn.recv(1024)
            if data:
                print(f"수신된 데이터: {data}")
                conn.sendall(data)
            conn.close()

if __name__ == "__main__":
    run_server(port=6666)  # 포트 6666에서 서버 실행

import socket

def run_server(port):
    """서버 실행 함수"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', port))  # 127.0.0.1 주소와 주어진 포트로 서버 바인딩
        s.listen()
        print(f"서버 실행 중: 127.0.0.1:{port}")

        while True:
            conn, addr = s.accept()  # 클라이언트 연결 수락
            print(f"서버 연결됨: {addr}")
            data = conn.recv(1024)  # 클라이언트로부터 데이터 수신
            if data:
                print(f"수신된 데이터: {data}")
                conn.sendall(data)  # 받은 데이터를 그대로 클라이언트로 전송
            conn.close()  # 연결 종료

if __name__ == "__main__":
    run_server(5555)  # 서버를 5555 포트에서 실행

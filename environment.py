import sys
import logging
import socket
logging.basicConfig(level=logging.INFO)


def extract_ip():
    st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:       
        st.connect(('10.255.255.255', 1))
        IP = st.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        st.close()
    return IP


class currentMode():
	def __init__(self, myenv):
		self.myenv = myenv
		if self.myenv == 'aws':
			self.server = 'https://verifier.wallet-provider.com/'
		elif self.myenv == 'local':
			self.flaskserver = extract_ip()
			self.server = 'http://' + self.flaskserver + ':3000/'
			self.port = 3000
		else:
			logging.error('environment variable problem')
			sys.exit()

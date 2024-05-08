from UAV import UAV
from GroundStation import GroundStation
import threading
import time

def ground_station_send_parameters_and_public_key():
    ground_station.send_parameters_and_public_key()

def uav_receive_parameters_and_send_public_key():
    uav.receive_parameters_and_public_key()
    uav.send_public_key()

def ground_station_receive_public_key_and_compute_secret():
    ground_station.receive_public_key_and_compute_secret()

ground_station = GroundStation()
uav = UAV()

# Initialize threads for the sequence of operations
thread1 = threading.Thread(target=ground_station_send_parameters_and_public_key)
thread2 = threading.Thread(target=uav_receive_parameters_and_send_public_key)
thread3 = threading.Thread(target=ground_station_receive_public_key_and_compute_secret)

# Start and manage the threads
thread1.start()
thread1.join()  # Ensure parameters are sent and received before proceeding

thread2.start()
thread2.join()  # Ensure UAV sends its public key after receiving parameters

thread3.start()
thread3.join()  # Complete the key exchange sequence

print("UAV Key Derived:", uav.key.hex())
print("Ground Station Key Derived:", ground_station.key.hex())
print("Keys Match:", uav.key == ground_station.key)
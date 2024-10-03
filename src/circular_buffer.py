import threading
from collections import deque
import time

# Circular buffer to store packets
class CircularBuffer:
    def __init__(self, capture_interval):
        self.buffer = deque()
        self.capture_interval = capture_interval
        self.lock = threading.Lock()

    def add_packet(self, packet):
        current_time = time.time()
        with self.lock:
            self.buffer.append((current_time, packet))
            self._remove_old_packets(current_time)

    def _remove_old_packets(self, current_time):
        while self.buffer and (current_time - self.buffer[0][0]) > self.capture_interval:
            self.buffer.popleft()

    def get_packets(self):
        with self.lock:
            return [packet for _, packet in self.buffer]
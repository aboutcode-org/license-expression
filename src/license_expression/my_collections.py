class Deque:
    def __init__(self):
        self.xs = []

    def clear(self):
        self.xs = []

    def popleft(self):
        return self.xs.pop(0)

    def append(self, value):
        self.xs.append(value)

    def __len__(self):
        return len(self.xs)

    def __iter__(self):
        return self.xs.__iter__()

#!/usr/bin/python


class DemoAdd ():
    def __init__(self, a):
        self.Left = a
    
    def Add (self, b):
        if b < 0:
            return (self.Left - b)
        else:
            return (self.Left + b)

    def __eq__(self, other):
        if not hasattr(self, 'Left') or not isinstance (other, DemoAdd):
            return False
        return self.Left == other.Left
phi = (p - 1) * (q - 1)
print(phi)
e = 610157208174277477
d = 2208394208592565981
print(e.bit_length())
print(d.bit_length())
print((e * d) % phi)  # should print 1
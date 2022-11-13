def leak(nonce: int, private: int):
    return int(nonce.bit_length() * 999.9766148666373)  #average from all leaks


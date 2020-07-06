import base64
import gzip
from Crypto.Cipher import AES


IV = "0123456789876543"    # 初始化向量
ROUND_SIZE = 1024 * 1024  - 1  # 1Mb - 1B


def encrypt(key: bytes, content: bytes) -> bytes:
    kLen = len(key)
    pad = lambda s: s + (kLen - len(s) % kLen) * chr(kLen - len(s) % kLen).encode()  # 填充
    cryptor = AES.new(key, AES.MODE_CBC, IV.encode('utf8'))
    ciphertext = cryptor.encrypt(pad(content))
    return ciphertext

def decrypt(key: bytes, content: bytes) -> bytes:
    unpad = lambda s: s[: -int(s[-1])]                      # 最后一位就是填充的长度
    cryptor = AES.new(key, AES.MODE_CBC, IV.encode('utf8'))
    data = cryptor.decrypt(content)
    return unpad(data)

def rowgzipaes(key: bytes, content: bytes) -> bytes:
    """压缩并加密 content
    """
    return encrypt(key, gzip.compress(content))

def rowaesgzip(key: bytes, content: bytes) -> bytes:
    """解密并解压缩 content
    """
    return gzip.decompress(decrypt(key, content))


class EncryptW(object):
    def __init__(self, filename, aes_key):
        self.fileobj = open(filename, 'wb')
        self.key = aes_key
        self.buf = b''

    def write(self, b):
        lenght = len(b)
        self.buf += b
        if len(self.buf) < ROUND_SIZE:
            return lenght
        
        round_num, index = divmod(len(self.buf), ROUND_SIZE)
        for i in range(round_num):
            ciphertext = encrypt(self.key, self.buf[i*ROUND_SIZE: (i+1)*ROUND_SIZE])
            self.fileobj.write(ciphertext)
        self.buf = self.buf[-index:]
        return lenght


    def flush(self):
        ciphertext = encrypt(key, self.buf)
        self.fileobj.write(ciphertext)
        self.fileobj.flush()

    def close(self):
        self.flush()
        self.fileobj.close()


class DecryptR(object):
    def __init__(self, filename, aes_key):
        self.fileobj = open(filename, 'rb')
        self.key = aes_key
        self.eof = False
        self.buf = b''

    def read(self, size=-1):
        if size < 0 or (self.eof and len(self.buf) == 0):
            return b''

        if len(self.buf) >= size:
            tmp = self.buf[:size]
            self.buf = self.buf[size:]
            return tmp

        if not self.eof:
            round_count, _ = divmod(size, ROUND_SIZE)
            for _ in range(round_count + 1):
                b = self.fileobj.read(ROUND_SIZE + 1)
                if len(b) == 0:
                    self.eof = True
                    break

                plaintext = decrypt(self.key, b)
                self.buf += plaintext

        if len(self.buf) > size:
            tmp = self.buf[:size]
            self.buf = self.buf[size:]
        else:
            tmp = self.buf
            self.buf = b''
        return tmp

    def close(self):
        self.fileobj.close()

def gzipaes(src_path: str, dst_path: str, key: bytes):
    """压缩并加密
    @param src_path str 目标文件路径
    @param dst_path str 压缩加密后文件路径
    @param key bytes aes密钥
    """
    with open(src_path, 'rb') as src:
        ew = EncryptW(dst_path, key)
        gf = gzip.GzipFile(fileobj=ew, mode='wb')
        try:
            while True:
                b = src.read(1024)
                if len(b) <= 0:
                    break
                gf.write(b)
        finally:
            gf.close()
            ew.close()


def aesgzip(src_path: str, dst_path: str, key: bytes):
    """解密并解压缩
    @param src_path str 目标文件路径
    @param dst_path str 解密解压缩后文件路径
    @param key bytes aes密钥
    """
    with open(dst_path, 'wb') as dst:
        dr = DecryptR(src_path, key)
        gf = gzip.GzipFile(fileobj=dr, mode='rb')
        try:
            while True:
                b = gf.read(1024)
                if len(b) == 0:
                    break
                dst.write(b)
        finally:
            gf.close()
            dr.close()


def encrypt_file(src_path: str, dst_path: str, key: bytes):
    """用于文件加密（不压缩）
    @param: src_path str 待加密文件路径
    @param: dst_path str 加密后文件路径
    """
    with open(src_path, 'rb') as src:
        with open(dst_path, 'wb') as dst:
            while True:
                b = src.read(ROUND_SIZE)
                if len(b) == 0:
                    break

                eb = encrypt(key, b)
                dst.write(eb)

def decrypt_file(src_path: str, dst_path: str, key: bytes):
    """用于文件加密（不压缩）
    @param: src_path str 待解密文件路径
    @param: dst_path str 解密后文件路径
    """
    with open(src_path, 'rb') as src:
        with open(dst_path, 'wb') as dst:
            while True:
                b = src.read(ROUND_SIZE+1)
                if len(b) == 0:
                    break

                eb = decrypt(key, b)
                dst.write(eb)



if __name__ == "__main__":
    key = b'abc123def456ghi7'
    gzipaes('input.txt', 'output.gz.aes', key)      # 压缩加密
    aesgzip('output.gz.aes', 'output', key)         # 解密解压缩

    encrypt_file('测试视频.mp4', '测试视频.aes', key)   # 加密视频   
    decrypt_file('测试视频.aes', '测试视频.mp4', key)   # 解密视频

    data = b"How are you? I'm fine, thanks." 
    xxx = encrypt(key, data)    # 一句话加密
    ddd = decrypt(key, xxx)     # 解密

    xxx = rowgzipaes(key, data)  # 一句话压缩并加密
    ddd = rowaesgzip(key, xxx)   # 一句话解密并解压缩

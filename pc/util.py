import shlex


def parse_command(line: str):
    try:
        parts = shlex.split(line)
    except ValueError as e:
        print("[!] Parse error:", e)
        return None, []

    if not parts:
        return None, []

    cmd = parts[0]
    args = parts[1:]
    return cmd, args



if __name__ == "__main__":
    in_path = "C:\\Users\\mahad\\Downloads\\Git-2.51.2-64-bit.exe"
    out_path = "C:\\Users\\mahad\\Downloads\\Git-enc.exe"
    passwd = "love@you"

    data = encrypt_file_to_bytes(in_path, passwd)

    with open(out_path, "wb") as tf:
        tf.write(data)

    print("done")
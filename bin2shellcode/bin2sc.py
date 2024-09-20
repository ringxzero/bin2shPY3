import sys

# Check for correct number of arguments
if len(sys.argv) != 3:
    print("usage: %s file.bin c|cs" % (sys.argv[0],))
    sys.exit(1)

if sys.argv[2] == "c":
    # for C shellcode
    shellcode = "\""
    ctr = 1
    maxlen = 15

    # Open the file in binary mode and read its content
    with open(sys.argv[1], "rb") as f:
        byte_content = f.read()

    # Convert each byte to hex and construct the shellcode
    for b in byte_content:
        shellcode += "\\x" + format(b, "02x")  # Convert int to hex string
        if ctr == maxlen:
            shellcode += "\" \n\""
            ctr = 0
        ctr += 1
    shellcode += "\""
    print(shellcode)

else:
    # for C# shellcode
    shellcode = ""
    ctr = 1
    maxlen = 15

    # Open the file in binary mode and read its content
    with open(sys.argv[1], "rb") as f:
        byte_content = f.read()

    # Convert each byte to hex and construct the shellcode
    for b in byte_content:
        shellcode += "0x" + format(b, "02x") + ","  # Convert int to hex string
        if ctr == maxlen:
            shellcode += "\n"
            ctr = 0
        ctr += 1

    print(shellcode)

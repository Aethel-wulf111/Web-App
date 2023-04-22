import os, math, magic, pefile,re
import datetime
now = datetime.datetime.now()

def get_all_files():
    all_files = []
    #os.chdir('../../uploads')
    current_dir = os.getcwd()
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    return all_files

def load_and_read_exe_strings():
    get_files = get_all_files()
    # get the exe file
    for i in get_files :
        if ".exe" in i or ".dll" in i or "sys" in i:
            file_exe = i
            break
        if not ".txt" in i:
            if not ".json" in i :
                file_exe = i
                break
    string_file = file_exe.split("/")
    string_file = "strings_" + string_file[-1].split(".")[0] + ".txt"
    for i in get_files :
        if string_file in i:
            file_str = i
            break
    return file_exe, file_str

# Get some strings to analyisi by strings
#~ Encryption algorithmes ~ Narimene maybe can be changed

def algo_crypt(file_path_str,file_path_exe):
    var1 = 0 #variable de keyword
    var2 = 0 #variable de librairies
    var3 = 0 #variable de cryptage
    x    = 0
    temp = []

    # Liste 1

    keywords = ["encrypt", "key","AES","RSA","blowfish", "asymmetric","symmetric","ciphers","hashes", "hash", "key", "public", "private"]

    with open(file_path_str, 'r') as file:
        text = file.read()

    for k in keywords:
        if k.lower() in text:
            if k.lower() in temp :
                pass
            else :
                temp.append(k.lower())
                x= x+1
                var1 = var1 +1

    # Liste 2

    lib1 = ["cryptography", "PyCrypto", "M2Crypto", "bcrypt", "passlib", "keyczar", "PyOpenSSL", "paramiko", "simple-crypt", 
            "PyNaCl", "Java Cryptography Extension","Apache Commons Crypto", "OpenSSL","Cryptacular","libsodium","GnuPG",
            "Libgcrypt","mbed TLS","Crypto++","Botan","Libgcrypt","Bouncy Castle","CryptSharp","System.Security.Cryptography",
            "OpenSSL.NET","Security.Cryptography","Fernet"]
    for l in lib1:
        pattern = r"import\s+{}\s|from\s+{}\s".format(re.escape(l), re.escape(l))
        match = re.search(pattern, text,re.IGNORECASE)
        if match:
            var2= var2 + 1

    # Liste 3
    file.close()

    obj = magic.Magic()

    # Obtenir le type de fichier
    file_type = obj.from_file(file_path_exe)

    # Vérifier si c'est un fichier binaire
    if "executable" in file_type or "shared object" in file_type:
        # Lire les premiers octets du fichier pour détecter les chaînes de caractères
        with open(file_path_str, "rb") as file:
            data = file.read(1024) # lire les 1024 premiers octets
            if b"RSA-2048" in data:
                var3 = var3+1
            elif b"AES-256" in data:
                var3 = var3+1
            elif b"Blowfish" in data:
                var3 = var3+1
            elif b"RC4" in data:
                var3 = var3+1
            elif b"ChaCha20" in data:
                var3 = var3+1
            elif b"Twofish" in data:
                var3 = var3+1
            elif b"Triple DES" in data:
                var3 = var3+1
            elif b"Serpent" in data:
                var3 = var3+1
            elif b"Camellia" in data:
                var3 = var3+1

    # Evaluation du fichier

    s = var1+var2+var3*2
    if s <10 :
        return True
    if s <60 and s > 10 :
        return False
    if s >= 60 :
        return False

# L'entropie

def entropy(file_path):
    with open(file_path, 'rb') as f:
        byte_freq = [0]*256
        byte_count = 0
        while True:
            byte = f.read(1)
            if not byte:
                break
            byte_count += 1
            byte_freq[ord(byte)] += 1
        entropy = 0
        for freq in byte_freq:
            if freq != 0:
                prob = freq / byte_count
                entropy += - prob * math.log2(prob)
        return entropy

def entropie_test(file_path):
    if entropy(file_path) < 6 :
        return False
    else:
        return True

# Anti-debugger  ~ Narimene
def fonction_antiDebugg(filepath):
    try :
        pe = pefile.PE(filepath)
        liste = ["CheckRemoteDebuggerPresent",
                "CheckRemoteDebuggerPresentEx",
                "CreateToolhelp32Snapshot",
                "DebugActiveProcess",
                "DebugActiveProcessStop",
                "DebugBreak",
                "DebugBreakProcess",
                "ContinueDebugEvent",
                "IsDebuggerPresent",
                "OutputDebugString",
                "Ptrace",
                "SetInformationThread",
                "SuspendThread",
                "WaitForDebugEvent",
                "Wow64SetThreadContext",
                "ZwSetInformationThread",
                "NtYieldExecution",
                "RtlAddVectoredExceptionHandler",
                "RtlAddVectoredContinueHandler",
                "RtlCaptureContext",
                "RtlDeleteFunctionTable",
                "RtlDeleteGrowableFunctionTable",
                "RtlInstallFunctionTableCallback",
                "RtlRemoveVectoredExceptionHandler",
                "RtlRestoreContext",
                "RtlUnwindEx",
                "RtlVirtualUnwind",
                "SymSetOptions",
                "SymInitialize",
                "SymCleanup",
                "SymGetOptions",
                "SymGetSearchPath",
                "SymGetModuleInfo",
                "SymGetModuleInfoEx",
                "SymGetModuleBase",
                "SymGetLineFromAddr",
                "SymGetLineFromAddr64",
                "SymGetLineFromName",
                "SymGetLineFromName64",
                "SymEnumSymbols",
                "SymEnumSymbolsForAddr",
                "SymFromAddr",
                "SymFromName",
                "SymFromToken",
                "SymLoadModuleEx",
                "SymUnloadModule",
                "SymUnDName",
                "SymSetParentWindow",
                "SymGetTypeInfo",
                "SymEnumTypes",
                "SymEnumTypesByName",
                "SymEnumTypesByIndex",
                "SymEnumSymbolsW",
                "SymEnumSymbolsEx",
                "SymEnumSourceFiles",
                "SymEnumProcesses",
                "SymGetSymbolFile",
                "SymGetSymbolFileW",
                "SymGetFileLineOffsets64",
                "SymGetLineNext",
                "SymGetLinePrev",
                "SymMatchString",
                "SymSearch",
                "SymLoadModule64",
                "SymGetSymFromAddr64",
                "SymGetSymFromName64",
                "SymGetLineFromAddrEx",
                "SymGetLineFromNameEx",
                "SymGetModuleInfoW",
                "SymGetSymbolInfo",
                "SymGetSymbolInfoW",
                "SymGetSymbol",
                "SymGetSymbolW",
                "SymGetTypeFromName",
                "SymGetTypeFromNameW",
                "SymEnumSourceFilesW",
                "SymEnumProcessesW",
                "SymSetSearchPath",
                "SymSetSearchPathW",
                "SymGetSearchPathW",
                "SymGetOptionsW",
                "SymGetLineFromAddr64W",
                "SymGetLineFromName64W",
                "SymGetModuleInfoExW",
                "SymFromAddrW",
                "SymFromNameW",
                "SymEnumSymbolsW64",
                "SymEnumSymbolsForAddrW",
                "SymEnumSourceFilesW64",
                "SymEnumTypesW",
                "SymEnumTypesW64",
                "SymLoadModuleExW",
                "SymLoadModuleW",
                "SymSetOptionsW",
                "SymSetParentWindowW",
                "SymSetContext",
                "SymSetContextW",
                "SymGetContext",
                "SymGetContextW",
                "SymSetScopeFromAddr",
                "SymSetScopeFromAddr"
            ]

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.lower() == "kernel32.dll":
                for imp in entry.imports:
                    for x in liste :
                        if imp.name is not None and imp.name.lower() == x.lower() :
                            return False
            else:
                return True
    except pefile.PEFormatError:
        return False
# Anti-vm  ~ Narimene
def fonction_vms(filepath):
    try :
        pe = pefile.PE(filepath)
        anti_vm_strings = ["VMWARE", "VIRTUALBOX", "VBOX", "QEMU", "XEN", "HYPER-V", "KVM", "EC2", "Proxmox VE", "XenServer", "AHV", "RHEV", "Bochs"]

        for string in anti_vm_strings:
            for dll in pe.DIRECTORY_ENTRY_IMPORT:
                for inp in dll.imports :
                    out = str(inp.name)
                    if string.lower() in out.lower():
                        return False
        return True
    except pefile.PEFormatError:
        return True

def Obsufuctions_Analysis():
    os.chdir("uploads")
    get_exe_ , get_strings_ = load_and_read_exe_strings()
    print("["+str(now)+"]~ The Obsufuction of the file has been done successful!")
    return entropie_test(get_exe_),algo_crypt(get_strings_,get_exe_),fonction_antiDebugg(get_exe_),fonction_vms(get_exe_)

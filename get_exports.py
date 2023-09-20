import sys
import pefile

def proxyFunctions(targetDLL):
    targetDLL = targetDLL.replace("\\", "/") if "\\" in targetDLL else targetDLL
    
    # If our dll can be found in the system32 directory let's not make a copy and telling dll where is the original
    if targetDLL.lower().startswith("c:/windows/system32"):

        pe = pefile.PE(targetDLL)
        dll = targetDLL.replace("/", "\\\\").split(".dll")[0]
        d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        pe.parse_data_directories(directories=d)
        exports = [(e.ordinal, e.name.decode()) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
        pragma_list = []
        
        for e in exports:
            pragma_list.append('#pragma comment(linker,"/export:{func}={dll}.{func},@{ord}")'.format(func=e[1], dll=dll, ord=e[0]))
        
        return pragma_list
    
    
def main():
    if len(sys.argv) != 2:
        print("Usage main.py <dll path>")
        exit(1)
    print(proxyFunctions(sys.argv[1]))
    

if _name_ == "_main_":
    main()

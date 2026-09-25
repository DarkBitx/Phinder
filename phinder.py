"""
Phantom DLL Finder (Phinder.py)
Searches ProcMon CSV logs for missing DLL loads that could be hijacked.

Author: DarkBit (t.me/darkbitx)
GitHub: https://github.com/DarkBitx
"""

import csv
import sys
import argparse
from pathlib import Path

BANNER = r"""
░█▀█░█░█░█▀█░█▀█░▀█▀░█▀█░█▄█░░░█▀▀░▀█▀░█▀█░█▀▄░█▀▀░█▀▄
░█▀▀░█▀█░█▀█░█░█░░█░░█░█░█░█░░░█▀▀░░█░░█░█░█░█░█▀▀░█▀▄
░▀░░░▀░▀░▀░▀░▀░▀░░▀░░▀▀▀░▀░▀░░░▀░░░▀▀▀░▀░▀░▀▀░░▀▀▀░▀░▀

              Phantom DLL Finder v1.0
                    by DarkBit
"""

def load_dll_list(list_file):
    try:
        with open(list_file, "r", encoding="utf-8") as f:
            dlls = set()
            for line in f:
                dll = line.strip().lower()

                if dll:
                    dlls.add(dll)

            return dlls
    except Exception as e:
        sys.exit(f"[!] Failed reading DLL list: {e}")

def parse_csv(csv_file):
    try:
        with open(csv_file, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.reader(f)

            try:
                headers = next(reader)
            except StopIteration:
                sys.exit("[!] CSV file is empty")

            headers = [x.strip().lower() for x in headers]

            columns = {
                "time": None,
                "process": None,
                "pid": None,
                "operation": None,
                "path": None,
                "user": None,
                "result": None,
                "detail": None
            }

            for index, name in enumerate(headers):
                if name in ("time of day", "time"):
                    columns["time"] = index
                elif name in ("process name", "process"):
                    columns["process"] = index
                elif name == "pid":
                    columns["pid"] = index
                elif name == "operation":
                    columns["operation"] = index
                elif name == "path":
                    columns["path"] = index
                elif name == "user":
                    columns["user"] = index
                elif name == "result":
                    columns["result"] = index
                elif name == "detail":
                    columns["detail"] = index

            required = ["process", "operation", "path", "result"]

            for item in required:
                if columns[item] is None:
                    sys.exit(f"[!] Missing required CSV column: {item}")

            def get_value(row, column):
                index = columns[column]

                if index is None:
                    return ""

                if index >= len(row):
                    return ""

                return row[index].strip()

            events = []

            for row in reader:
                if not row:
                    continue

                events.append({
                    "time": get_value(row, "time"),
                    "process": get_value(row, "process"),
                    "pid": get_value(row, "pid"),
                    "operation": get_value(row, "operation"),
                    "path": get_value(row, "path"),
                    "user": get_value(row, "user"),
                    "result": get_value(row, "result"),
                    "detail": get_value(row, "detail"),
                })

            return events, columns

    except Exception as e:
        sys.exit(f"[!] Failed reading CSV: {e}")
        
def phantom_finder(events, pname, outpath, dll_list=None):

    pids = {}
    for event in events:
        if pname:
            if event["process"].lower() != pname.lower():
                continue
            
        pid = event["pid"]
        if pid not in pids:
            pids[pid] = {"missing": [], "loaded": []}
            
        operation = event["operation"]
        result = event["result"]
        path = event["path"]

        if (operation == "CreateFile" and result == "NAME NOT FOUND" and path.lower().endswith(".dll")):
            pids[pid]["missing"].append(event)

        elif (operation == "Load Image" and result == "SUCCESS" and path.lower().endswith(".dll")):
            pids[pid]["loaded"].append(event)

    phantom_dlls = []
    total_missing = 0
    total_loaded = 0

    for pid, data in pids.items():
        
        loaded_names = set()
        if dll_list:
            loaded_names = dll_list
        else:
            for module in data["loaded"]:
                loaded_names.add(Path(module["path"]).name.lower())
                
            total_loaded += len(data["loaded"])

        for dll in data["missing"]:            
            total_missing += 1
            dll_name = Path(dll["path"]).name.lower()
            
            if dll_name not in loaded_names:
                phantom_dlls.append(dll)

    with open(outpath, "w", newline="", encoding="utf-8") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=[
                "time",
                "process",
                "pid",
                "operation",
                "path",
                "user",
                "result",
                "detail"
            ]
        )
        writer.writeheader()
        writer.writerows(phantom_dlls)
        
    print(f"[+] Missing DLL requests : {total_missing}")
    print(f"[+] Loaded DLL modules   : {total_loaded}")
    print(f"[+] Phantom candidates   : {len(phantom_dlls)}")
    print(f"[+] Results saved to {outpath}")

def phantom_reader(events, pname):

    processes = {}
    for event in events:
        if pname:
            if event["process"].lower() != pname.lower():
                continue

        pid = event["pid"]
        if pid not in processes:
            processes[pid] = []
            
        processes[pid].append(event)

    for pid, phantoms in processes.items():
        print(f"[+] {phantoms[0]['process']} [{pid}]")

        printed = set()
        for event in phantoms:
            
            path = event["path"]
            if path.lower() in printed:
                continue
            
            printed.add(path.lower())
            
            print(f"\t[#] Phantom {Path(path).name}")
            print(f"\t\tPath: {path}")
            
        print("-" * 150)

def main():

    print(BANNER)

    parser = argparse.ArgumentParser(description="Detect phantom DLL candidates from ProcMon CSV logs.")
    parser.add_argument("csv_file", type=str, help="ProcMon CSV file")
    parser.add_argument("-p", "--process", help="Filter by process name")
    parser.add_argument("-r","--read", action="store_true", help="Read CSV and print phantom results")
    parser.add_argument("-l", "--list", help="DLL list file for comparison")
    parser.add_argument("-o", "--output", default="found.csv", help="Output CSV file")
    args = parser.parse_args()

    events, _ = parse_csv(args.csv_file)
    pname = args.process if args.process else ""
    
    if args.read:
        phantom_reader(events, pname)
        return

    dll_list = None
    if args.list:

        dll_list = load_dll_list(args.list)
        print(f"[+] DLL list entries : {len(dll_list)}")
        
    phantom_finder(events, pname, args.output, dll_list)

if __name__ == "__main__":
    main()
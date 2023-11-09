# modules
import os
import time
import json
import pandas as pd
import prettytable
import nmap
import readline

def scan_by_nmap(host):
    result_scan = nmap.PortScanner().scan(hosts=host)
    df_scaninfo = pd.DataFrame(result_scan)
    date_time = df_scaninfo.loc["scanstats", "nmap"]["timestr"]
    df_scaninfo.drop(["command_line", "scaninfo", "scanstats"], inplace=True)
    return df_scaninfo, date_time

def create_prettytable(df_scaninfo):
    table = prettytable.PrettyTable()
    table.field_names = [
        "host", "port", "state", 
        "reason", "name", "product", 
        "version", "extrainfo", "conf", 
        "cpe"
        ]
    for INDEX in df_scaninfo.index:
        try:
            df = pd.DataFrame(df_scaninfo.loc[INDEX, "scan"]["tcp"])
            for column_name in df.columns:
                table.add_row([
                    INDEX, column_name, df.loc["state", column_name], 
                    df.loc["reason", column_name], df.loc["name", column_name], df.loc["product", column_name], 
                    df.loc["version", column_name], df.loc["extrainfo", column_name], df.loc["conf", column_name], 
                    df.loc["cpe", column_name]
                    ])
        except KeyError:
            table.add_row([
                INDEX, "all-closed", "---",
                "---", "---", "---",
                "---", "---", "---",
                "---"
                ])
    return table

def display(table, date_time):
    print(date_time)
    print(table)
    return 0

def main():
    host = str(input("Enter IP or HOST: "))
    df_scaninfo, date_time = scan_by_nmap(host)
    table = create_prettytable(df_scaninfo)
    display(table, date_time)

if __name__ == "__main__":
    try:
        start_time = time.time()
        main()
        print("\n\nProssec time: {}".format(time.time() - start_time))
        exit()
    except KeyboardInterrupt:
        print("\nUser canceled the prossec")
        exit()

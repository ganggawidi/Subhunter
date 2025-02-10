#!/usr/bin/env python3
import argparse
import asyncio
import subprocess
import os

import aiodns
import aiohttp
from colorama import Fore, Style, init
from tqdm import tqdm

def print_banner():
    banner = r"""

 ________  ___  ___  ________  ___  ___  ___  ___  ________   _________  _______   ________     
|\   ____\|\  \|\  \|\   __  \|\  \|\  \|\  \|\  \|\   ___  \|\___   ___\\  ___ \ |\   __  \    
\ \  \___|\ \  \\\  \ \  \|\ /\ \  \\\  \ \  \\\  \ \  \\ \  \|___ \  \_\ \   __/|\ \  \|\  \   
 \ \_____  \ \  \\\  \ \   __  \ \   __  \ \  \\\  \ \  \\ \  \   \ \  \ \ \  \_|/_\ \   _  _\  
  \|____|\  \ \  \\\  \ \  \|\  \ \  \ \  \ \  \\\  \ \  \\ \  \   \ \  \ \ \  \_|\ \ \  \\  \| 
    ____\_\  \ \_______\ \_______\ \__\ \__\ \_______\ \__\\ \__\   \ \__\ \ \_______\ \__\\ _\ 
   |\_________\|_______|\|_______|\|__|\|__|\|_______|\|__| \|__|    \|__|  \|_______|\|__|\|__|
   \|_________|                                                                                 
    Subdomain Enumeration Tool Kelompok 6 III Rekayasa Keamanan Siber A
    By: Gangga, Ajay, Drian
    """
    print(banner)


# ------------------------------------------------------------------------------
# 1) PARSING ARGUMEN CLI dengan ARGPARSE
# ------------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Asynchronous subdomain enumeration tool with DNS & HTTP concurrency."
    )
    parser.add_argument(
        "domain",
        help="Target domain to enumerate (e.g. example.com)"
    )
    parser.add_argument(
        "-w", "--wordlist",
        default="subdomains.txt",
        help="Path to subdomain wordlist file (default: subdomains.txt)"
    )
    parser.add_argument(
        "--dns-timeout",
        type=float,
        default=3.0,
        help="Timeout in seconds for DNS resolving (default: 3.0)"
    )
    parser.add_argument(
        "--http-timeout",
        type=float,
        default=5.0,
        help="Timeout in seconds for HTTP requests (default: 5.0)"
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=50,
        help="Max concurrency for DNS/HTTP tasks (default: 50)"
    )
    parser.add_argument(
        "--no-aquatone",
        action="store_true",
        help="Disable running Aquatone at the end."
    )
    args = parser.parse_args()
    return args


# ------------------------------------------------------------------------------
# 2) ASYNC DNS RESOLVE dengan AIODNS
# ------------------------------------------------------------------------------
async def resolve_subdomain(subdomain, domain, resolver, dns_timeout):
    """
    Resolve subdomain.domain ke A record secara asynchronous.
    Return: (full_domain, list_ip, status_string).
    """
    full_domain = f"{subdomain}.{domain}"
    try:
        answers = await resolver.query(full_domain, 'A')
        ip_addresses = [ans.host for ans in answers]
        return full_domain, ip_addresses, Fore.GREEN + "FOUND"
    except aiodns.error.DNSError as e:
        # Kode error umum:
        #  - 1: DNS server returned answer with no data
        #  - 4: Domain name not found
        #  - 11: Timeout
        #  - dsb
        if e.args[0] == 4:
            return full_domain, [], Fore.RED + "NOT FOUND"
        elif e.args[0] == 11:
            return full_domain, [], Fore.YELLOW + "TIMEOUT"
        else:
            return full_domain, [], Fore.MAGENTA + f"ERROR: {e}"
    except Exception as e:
        return full_domain, [], Fore.MAGENTA + f"ERROR: {e}"


# ------------------------------------------------------------------------------
# 3) ASYNC HTTP PROBE dengan AIOHTTP
# ------------------------------------------------------------------------------
async def http_probe(subdomain, http_timeout, session):
    """
    Mencoba HTTP/HTTPS pada subdomain.
    Return: string deskripsi status.
    """
    schemes = ['https', 'http']
    errors = []
    for scheme in schemes:
        url = f"{scheme}://{subdomain}"
        try:
            async with session.get(url, timeout=http_timeout) as resp:
                # Jika berhasil, langsung return
                return Fore.GREEN + f"{scheme.upper()} OK ({resp.status})"
        except aiohttp.ClientConnectorError as e:
            # Deteksi Connection Refused dsb
            err_str = str(e).lower()
            if "connection refused" in err_str:
                errors.append(f"{scheme.upper()} Connection Refused")
            elif "no route to host" in err_str:
                errors.append(f"{scheme.upper()} No Route to Host")
            else:
                errors.append(f"{scheme.upper()} Connection Error: {e}")
        except aiohttp.ClientResponseError as e:
            errors.append(f"{scheme.upper()} HTTP Error: {e.status}")
        except aiohttp.ServerTimeoutError:
            errors.append(f"{scheme.upper()} Timeout")
        except aiohttp.ClientError as e:
            errors.append(f"{scheme.upper()} Error: {e}")
        except asyncio.TimeoutError:
            errors.append(f"{scheme.upper()} Timeout")
    if errors:
        return Fore.RED + ", ".join(errors)
    return Fore.RED + "Unknown HTTP Error"


# ------------------------------------------------------------------------------
# 4) PROGRESS BAR HELPER
# ------------------------------------------------------------------------------
async def run_with_progress_bar(coros, desc, max_concurrent):
    """
    Menerima iterable coroutines (coros), mengeksekusinya secara concurrency
    (max max_concurrent), sambil menampilkan progress bar tqdm.

    Return: list hasil (sesuai urutan *selesainya* task, tapi kita bisa urutkan kembali).
    """
    results = []
    tasks = list(coros)
    total = len(tasks)

    # Kita batasi concurrency dengan semaphore
    semaphore = asyncio.Semaphore(value=max_concurrent)

    async def sem_task(coro):
        async with semaphore:
            return await coro

    # Bungkus setiap coroutine dengan sem_task
    tasks_sem = [asyncio.create_task(sem_task(c)) for c in tasks]

    with tqdm(total=total, desc=desc) as pbar:
        # as_completed memberi kita future saat satu task selesai
        for fut in asyncio.as_completed(tasks_sem):
            res = await fut
            results.append(res)
            pbar.update(1)

    return results


# ------------------------------------------------------------------------------
# 5) AQUATONE SCREENSHOT (tetap synchronous Subprocess)
# ------------------------------------------------------------------------------
def aquatone_screenshot(subdomains):
    """
    Menjalankan aquatone untuk sekumpulan subdomains.
    Hasil disimpan ke folder 'aquatone_screenshots'.
    """
    if not subdomains:
        return Fore.YELLOW + "No valid subdomains for Aquatone"
    
    hosts_file = "aquatone_hosts.txt"
    out_dir = "aquatone_screenshots"
    try:
        # Tulis subdomains ke file
        with open(hosts_file, "w") as f:
            for s in subdomains:
                f.write(s + "\n")
        
        # Cek versi aquatone
        version_check = subprocess.run(
            ['aquatone', '-version'],
            capture_output=True,
            text=True
        )
        
        if "aquatone version" in version_check.stdout.lower():
            # Pakai versi baru (-hosts)
            cmd = ['aquatone', '-hosts', hosts_file, '-out', out_dir]
        else:
            # Fallback versi lama
            cmd = ['aquatone', '-out', out_dir]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            input=open(hosts_file).read() if '-hosts' not in cmd else None
        )
        if result.returncode == 0:
            return Fore.GREEN + f"Aquatone screenshots completed. See '{out_dir}/'"
        else:
            err = result.stderr.strip() or "Unknown error"
            return Fore.RED + f"Aquatone Error: {err}"
            
    except FileNotFoundError:
        return Fore.RED + "Aquatone not installed (command not found)."
    except subprocess.TimeoutExpired:
        return Fore.YELLOW + "Aquatone timed out."
    except Exception as e:
        return Fore.RED + f"AQUATONE ERROR: {str(e)}"


# ------------------------------------------------------------------------------
# 6) FUNGSI UTAMA (ASYNC)
# ------------------------------------------------------------------------------
async def main_async(args):
    domain = args.domain
    wordlist_file = args.wordlist
    dns_timeout = args.dns_timeout
    http_timeout = args.http_timeout
    max_concurrent = args.max_concurrent

    print(Fore.BLUE + f"Starting subdomain enumeration for domain: {Fore.YELLOW}{domain}\n")

    # Baca subdomain list dari file
    if not os.path.isfile(wordlist_file):
        print(Fore.RED + f"Wordlist file '{wordlist_file}' not found.")
        return

    with open(wordlist_file, "r") as f:
        raw_subdomains = [line.strip() for line in f if line.strip()]

    # Inisialisasi resolver aiodns
    resolver = aiodns.DNSResolver(timeout=dns_timeout)

    # 6A) DNS Resolving secara concurrency
    dns_coros = (
        resolve_subdomain(subd, domain, resolver, dns_timeout)
        for subd in raw_subdomains
    )

    dns_results = await run_with_progress_bar(dns_coros, "DNS Resolving", max_concurrent)

    # dns_results adalah list of (full_domain, ip_addresses, status)
    # Kita urutkan saja berdasarkan urutan subdomain_asli, kalau mau. 
    # Namun, as_completed() kembalinya acak. 
    # Kita bisa menampung di dict, lalu print berurutan. 
    # Tapi di sini kita langsung simpan ke dictionary:
    from collections import OrderedDict
    results_dict = OrderedDict()
    for (full_domain, ip_addresses, status) in dns_results:
        results_dict[full_domain] = {
            "ips": ip_addresses,
            "dns_status": status,
            "http_status": None
        }

    # 6B) Filter subdomain yang FOUND (ips not empty)
    found_subdomains = [fd for fd, val in results_dict.items() if val["ips"]]

    # 6C) HTTP PROBE: concurrency juga dengan aiohttp
    if found_subdomains:
        print("\n" + Fore.BLUE + f"Running HTTP probe on {len(found_subdomains)} subdomains...\n")
        async with aiohttp.ClientSession() as session:
            http_coros = (
                http_probe(fd, http_timeout, session)
                for fd in found_subdomains
            )
            http_results = await run_with_progress_bar(http_coros, "HTTP Probing", max_concurrent)

        # Simpan http_results ke results_dict (urutan 1:1)
        for subd, http_stat in zip(found_subdomains, http_results):
            results_dict[subd]["http_status"] = http_stat

    # 6D) Cetak hasil akhirnya
    print("\n" + Fore.GREEN + "[INFO] Enumeration completed.")
    active_count = 0

    for fd, val in results_dict.items():
        ip_list = val["ips"]
        dns_stat = val["dns_status"]
        http_stat = val["http_status"] or ""
        if ip_list:
            active_count += 1
            ip_str = ", ".join(ip_list)
            print(
                f"{Fore.WHITE}{fd} - {dns_stat} {Fore.WHITE}({Fore.GREEN}{ip_str}{Fore.WHITE})"
            )
            if http_stat:
                print(Fore.WHITE + "HTTP Status: " + http_stat)
        else:
            # Tidak ditemukan IP
            print(f"{Fore.WHITE}{fd} - {dns_stat}")

    print(Fore.GREEN + f"\n[INFO] Found {active_count} active subdomains.")

    # 6E) Simpan subdomain "aktif" ke file
    if active_count > 0:
        output_file = "found_subdomains.txt"
        with open(output_file, "w") as out:
            for fd, val in results_dict.items():
                if val["ips"]:
                    out.write(fd + "\n")
        print(Fore.GREEN + f"[INFO] Results saved to '{output_file}'.")

        # 6F) Jalankan Aquatone jika tidak --no-aquatone
        if not args.no_aquatone:
            print(Fore.BLUE + "[INFO] Starting Aquatone screenshots...")
            aqua_stat = aquatone_screenshot(found_subdomains)
            print(aqua_stat)
    else:
        print(Fore.YELLOW + "[INFO] No subdomains found. Skipping Aquatone.")


# ------------------------------------------------------------------------------
# 7) FUNGSI MAIN (SYNC): Memanggil asyncio.run
# ------------------------------------------------------------------------------
def main():

    print_banner()
    # Init colorama
    init(autoreset=True)

    # Parse argumen CLI
    args = parse_args()

    # Jalankan main_async
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()

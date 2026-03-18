"""
analyze_mydig.py — Performance comparison of mydig.py (Custom Recursive DNS Resolver)
Compares: Custom Resolver vs Local DNS vs Google Public DNS (8.8.8.8)
Tests against: Top 25 Global Websites
Generates: mydig_performance.png (CDF Plot)
"""
import time
import mydig as dns_r
import dns.resolver as dr
import dns.rdatatype
import numpy as np
import matplotlib.pyplot as plt

top_sites=['Google.com','Youtube.com','Facebook.com','Baidu.com','Yahoo.com','Wikipedia.org',
           'Google.co.in','Tmall.com','Qq.com','Amazon.com','Sohu.com','Google.co.jp','Taobao.com',
           'Live.com','Vk.com','Twitter.com','360.cn','Instagram.com','Linkedin.com','Yahoo.co.jp',
           'Sina.com.cn','Jd.com','Google.de','Reddit.com','Google.co.uk']

root_server_ip = ['198.41.0.4', '192.228.79.201', '192.33.4.12', '199.7.91.13',
                  '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53',
                  '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42',
                  '202.12.27.33']

time_mydig = []
time_local = []
time_gpd   = []

def main():
    print("=" * 70)
    print("  mydig.py — PERFORMANCE COMPARISON")
    print("  Custom Resolver vs Local DNS vs Google DNS (8.8.8.8)")
    print("  Top 25 Global Websites")
    print("=" * 70)

    # ---- 1. Custom Resolver (mydig.py) ----
    print("\n[1/3] Custom Resolver (mydig.py) — Recursive from Root Servers")
    print("-" * 60)
    for site in top_sites:
        print(f"  {site:<20}", end="", flush=True)
        start = time.time()
        dns_r.resolve(site, dns.rdatatype.A, root_server_ip[0])
        t = time.time() - start
        time_mydig.append(t)
        print(f"  {t:.4f}s")
    print(f"\n  >>> MyDig Average: {sum(time_mydig)/len(time_mydig):.4f}s")

    # ---- 2. Local DNS Resolver ----
    print("\n[2/3] Local DNS Resolver (System Default)")
    print("-" * 60)
    local_resolver = dr.Resolver()
    local_resolver.lifetime = 3
    for site in top_sites:
        print(f"  {site:<20}", end="", flush=True)
        start = time.time()
        try:
            local_resolver.resolve(site, 'A')
        except:
            pass
        t = time.time() - start
        time_local.append(t)
        print(f"  {t:.4f}s")
    print(f"\n  >>> Local DNS Average: {sum(time_local)/len(time_local):.4f}s")

    # ---- 3. Google Public DNS ----
    print("\n[3/3] Google Public DNS (8.8.8.8)")
    print("-" * 60)
    gpd_resolver = dr.Resolver(configure=False)
    gpd_resolver.nameservers = ['8.8.8.8']
    gpd_resolver.lifetime = 3
    for site in top_sites:
        print(f"  {site:<20}", end="", flush=True)
        start = time.time()
        try:
            gpd_resolver.resolve(site, 'A')
        except:
            pass
        t = time.time() - start
        time_gpd.append(t)
        print(f"  {t:.4f}s")
    print(f"\n  >>> Google DNS Average: {sum(time_gpd)/len(time_gpd):.4f}s")

    # ---- Summary ----
    avg_m = sum(time_mydig)/len(time_mydig)
    avg_l = sum(time_local)/len(time_local)
    avg_g = sum(time_gpd)/len(time_gpd)

    print("\n" + "=" * 70)
    print("  RESULTS")
    print("=" * 70)
    print(f"  Custom Resolver (mydig.py):    {avg_m:.4f}s  average")
    print(f"  Local DNS Resolver:            {avg_l:.4f}s  average")
    print(f"  Google Public DNS (8.8.8.8):   {avg_g:.4f}s  average")
    print(f"\n  Sites Tested:          {len(top_sites)}")
    print(f"  Fastest mydig:         {min(time_mydig):.4f}s")
    print(f"  Slowest mydig:         {max(time_mydig):.4f}s")

    # ---- CDF Plot ----
    s_mydig = np.sort(np.array(time_mydig))
    s_local = np.sort(np.array(time_local))
    s_gpd   = np.sort(np.array(time_gpd))
    y = np.arange(1, len(s_mydig)+1) / len(s_mydig)

    fig = plt.figure(figsize=(10, 8), dpi=100)
    plt.plot(s_mydig, y, c='r',   linewidth=2.5, marker='o', markersize=4, label=f'mydig.py (avg {avg_m:.3f}s)')
    plt.plot(s_local, y, c='g',   linewidth=2.5, marker='s', markersize=4, label=f'Local DNS (avg {avg_l:.3f}s)')
    plt.plot(s_gpd,   y, c='b',   linewidth=2.5, marker='^', markersize=4, label=f'Google DNS (avg {avg_g:.3f}s)')
    plt.legend(loc='lower right', fontsize=13)
    plt.xlabel('Time (seconds)', fontsize=16)
    plt.ylabel('Cumulative Probability', fontsize=16)
    plt.title('CDF — mydig.py vs Local DNS vs Google DNS\n(Top 25 Global Websites)', fontsize=15)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig('mydig_performance.png')
    print(f"\n  Plot saved: mydig_performance.png")

if __name__ == '__main__':
    main()

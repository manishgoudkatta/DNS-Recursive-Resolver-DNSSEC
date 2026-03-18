"""
analyze_dnssec.py — Performance comparison of mydig_dnssec.py (DNSSEC Secure Resolver)
Compares: Standard Resolution (mydig.py) vs DNSSEC Verified Resolution (mydig_dnssec.py)
Tests against: 25 DNSSEC-Enabled Domains (.gov, .mil, security orgs)
Generates: dnssec_performance.png (CDF Plot)
"""
import time
import subprocess
import numpy as np
import matplotlib.pyplot as plt

dnssec_sites=['cloudflare.com','verisign.com','isc.org','ietf.org','nasa.gov',
              'nist.gov','nih.gov','energy.gov','ed.gov','treasury.gov',
              'fbi.gov','cdc.gov','noaa.gov','usda.gov','whitehouse.gov',
              'navy.mil','af.mil','state.gov','sec.gov','epa.gov',
              'fda.gov','dhs.gov','transportation.gov','hhs.gov','dot.gov']
              

time_standard = []
time_dnssec   = []
dnssec_status = []

def run_script(script, domain):
    start = time.time()
    try:
        r = subprocess.run(['python', script, domain, 'A'],
                           capture_output=True, text=True, timeout=15)
        output = r.stdout.strip()
    except subprocess.TimeoutExpired:
        output = "TIMEOUT"
    return time.time() - start, output

def main():
    print("=" * 70)
    print("  mydig_dnssec.py — DNSSEC PERFORMANCE ANALYSIS")
    print("  Standard Resolution vs DNSSEC Verified Resolution")
    print("  25 DNSSEC-Enabled Domains")
    print("=" * 70)

    print(f"\n{'Site':<22} {'mydig.py':>10} {'DNSSEC':>10} {'Status':>12}")
    print("-" * 58)

    passed = 0
    failed = 0
    for site in dnssec_sites:
        # Standard resolution
        t_std, _ = run_script('mydig.py', site)
        time_standard.append(t_std)

        # DNSSEC resolution
        t_sec, out = run_script('mydig_dnssec.py', site)
        time_dnssec.append(t_sec)

        if 'failed' in out.lower() or 'not supported' in out.lower() or 'TIMEOUT' in out:
            status = "DNS not supported"
            failed += 1
        else:
            status = "DNS supported"
            passed += 1
        dnssec_status.append(status)

        mark = "✅" if status == "DNS supported" else "❌"
        print(f"  {site:<20} {t_std:>8.4f}s  {t_sec:>8.4f}s  {mark} {status}")

    # ---- Summary ----
    avg_std = sum(time_standard)/len(time_standard)
    avg_sec = sum(time_dnssec)/len(time_dnssec)

    print("\n" + "=" * 70)
    print("  RESULTS")
    print("=" * 70)
    print(f"  Standard (mydig.py):           {avg_std:.4f}s  average")
    print(f"  DNSSEC (mydig_dnssec.py):      {avg_sec:.4f}s  average")
    print(f"  Crypto Overhead per query:     +{avg_sec - avg_std:.4f}s")
    print(f"  DNSSEC Slowdown:               {avg_sec/avg_std:.1f}x slower")
    print(f"\n  DNSSEC supported:   {passed}/25 domains ✅")
    print(f"  DNSSEC not supported:     {failed}/25 domains ❌")
    print(f"  Fastest DNSSEC:    {min(time_dnssec):.4f}s")
    print(f"  Slowest DNSSEC:    {max(time_dnssec):.4f}s")

    # ---- CDF Plot ----
    s_std    = np.sort(np.array(time_standard))
    s_dnssec = np.sort(np.array(time_dnssec))
    y = np.arange(1, len(s_std)+1) / len(s_std)

    fig = plt.figure(figsize=(10, 8), dpi=100)
    plt.plot(s_std,    y, c='blue',   linewidth=2.5, marker='o', markersize=4,
             label=f'mydig.py Standard (avg {avg_std:.3f}s)')
    plt.plot(s_dnssec, y, c='purple', linewidth=2.5, marker='s', markersize=4, linestyle='--',
             label=f'mydig_dnssec.py Secure (avg {avg_sec:.3f}s)')
    plt.legend(loc='lower right', fontsize=13)
    plt.xlabel('Time (seconds)', fontsize=16)
    plt.ylabel('Cumulative Probability', fontsize=16)
    plt.title('CDF — Standard vs DNSSEC-Verified Resolution\n(25 DNSSEC-Enabled Domains)', fontsize=15)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig('dnssec_performance.png')
    print(f"\n  Plot saved: dnssec_performance.png")

if __name__ == '__main__':
    main()

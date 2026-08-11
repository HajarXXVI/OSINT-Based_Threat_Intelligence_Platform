from engine.correlator import analyze_target

if __name__ == "__main__":
    print("[*] Testing Correlation & Scoring Engine...")
    result = analyze_target("8.8.8.8")
    print(result)